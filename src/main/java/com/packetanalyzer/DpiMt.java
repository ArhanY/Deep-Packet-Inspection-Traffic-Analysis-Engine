package com.packetanalyzer;

import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapGlobalHeader;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;
import com.packetanalyzer.dpi.AppType;
import com.packetanalyzer.dpi.DpiTypes;
import com.packetanalyzer.dpi.FiveTuple;
import com.packetanalyzer.dpi.HTTPHostExtractor;
import com.packetanalyzer.dpi.SNIExtractor;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

// "Multi-threaded DPI Engine - Fixed Version"
// Architecture: Reader -> LB threads -> FP threads -> Output
public class DpiMt {

    // =========================================================================
    // Thread-safe queue
    // =========================================================================
    static class TSQueue<T> {
        private final ArrayDeque<T> queue = new ArrayDeque<>();
        private final ReentrantLock mutex = new ReentrantLock();
        private final Condition notEmpty = mutex.newCondition();
        private final Condition notFull = mutex.newCondition();
        private final int maxSize;
        private volatile boolean shutdown = false;

        TSQueue() {
            this(10000);
        }

        TSQueue(int maxSize) {
            this.maxSize = maxSize;
        }

        void push(T item) {
            mutex.lock();
            try {
                while (queue.size() >= maxSize && !shutdown) {
                    notFull.awaitUninterruptibly();
                }
                if (shutdown) return;
                queue.addLast(item);
                notEmpty.signal();
            } finally {
                mutex.unlock();
            }
        }

        Optional<T> pop(int timeoutMs) {
            mutex.lock();
            try {
                long nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs);
                while (queue.isEmpty() && !shutdown) {
                    if (nanos <= 0) return Optional.empty();
                    try {
                        nanos = notEmpty.awaitNanos(nanos);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return Optional.empty();
                    }
                }
                if (queue.isEmpty()) return Optional.empty();
                T item = queue.pollFirst();
                notFull.signal();
                return Optional.of(item);
            } finally {
                mutex.unlock();
            }
        }

        Optional<T> pop() {
            return pop(100);
        }

        void shutdown() {
            mutex.lock();
            try {
                shutdown = true;
                notEmpty.signalAll();
                notFull.signalAll();
            } finally {
                mutex.unlock();
            }
        }

        int size() {
            mutex.lock();
            try {
                return queue.size();
            } finally {
                mutex.unlock();
            }
        }

        boolean isShutdown() {
            return shutdown;
        }
    }

    // =========================================================================
    // Packet Job - Contains all packet data (self-contained, no pointers)
    // =========================================================================
    static class Packet {
        long id;
        long ts_sec;
        long ts_usec;
        FiveTuple tuple = new FiveTuple();
        byte[] data;
        int tcp_flags;
        int payload_offset;
        int payload_length;
    }

    // =========================================================================
    // Flow Entry
    // =========================================================================
    static class FlowEntry {
        FiveTuple tuple;
        AppType app_type = AppType.UNKNOWN;
        String sni = "";
        long packets = 0;
        long bytes = 0;
        boolean blocked = false;
        boolean classified = false;
    }

    // =========================================================================
    // Blocking Rules
    // =========================================================================
    static class Rules {
        private final ReentrantLock mutex = new ReentrantLock();
        private final Set<Long> blocked_ips = new HashSet<>();
        private final Set<AppType> blocked_apps = new HashSet<>();
        private final List<String> blocked_domains = new ArrayList<>();

        void blockIP(String ip) {
            mutex.lock();
            try {
                blocked_ips.add(parseIP(ip));
                System.out.println("[Rules] Blocked IP: " + ip);
            } finally {
                mutex.unlock();
            }
        }

        void blockApp(String app) {
            mutex.lock();
            try {
                for (int i = 0; i < AppType.APP_COUNT.ordinal(); i++) {
                    AppType type = AppType.values()[i];
                    if (DpiTypes.appTypeToString(type).equals(app)) {
                        blocked_apps.add(type);
                        System.out.println("[Rules] Blocked app: " + app);
                        return;
                    }
                }
                System.err.println("[Rules] Unknown app: " + app);
            } finally {
                mutex.unlock();
            }
        }

        void blockDomain(String domain) {
            mutex.lock();
            try {
                blocked_domains.add(domain);
                System.out.println("[Rules] Blocked domain: " + domain);
            } finally {
                mutex.unlock();
            }
        }

        boolean isBlocked(long src_ip, AppType app, String sni) {
            mutex.lock();
            try {
                if (blocked_ips.contains(src_ip)) return true;
                if (blocked_apps.contains(app)) return true;
                for (String dom : blocked_domains) {
                    if (sni.contains(dom)) return true;
                }
                return false;
            } finally {
                mutex.unlock();
            }
        }

        static long parseIP(String ip) {
            long result = 0;
            int octet = 0, shift = 0;
            for (int i = 0; i < ip.length(); i++) {
                char c = ip.charAt(i);
                if (c == '.') {
                    result |= ((long) octet << shift);
                    shift += 8;
                    octet = 0;
                } else if (c >= '0' && c <= '9') {
                    octet = octet * 10 + (c - '0');
                }
            }
            result |= ((long) octet << shift);
            return result & 0xFFFFFFFFL;
        }
    }

    // =========================================================================
    // Statistics (thread-safe)
    // =========================================================================
    static class Stats {
        final AtomicLong total_packets = new AtomicLong(0);
        final AtomicLong total_bytes = new AtomicLong(0);
        final AtomicLong forwarded = new AtomicLong(0);
        final AtomicLong dropped = new AtomicLong(0);
        final AtomicLong tcp_packets = new AtomicLong(0);
        final AtomicLong udp_packets = new AtomicLong(0);

        // Per-app stats (protected by mutex)
        private final ReentrantLock app_mutex = new ReentrantLock();
        final Map<AppType, Long> app_counts = new HashMap<>();
        final Map<String, AppType> detected_snis = new HashMap<>();

        void recordApp(AppType app, String sni) {
            app_mutex.lock();
            try {
                app_counts.merge(app, 1L, Long::sum);
                if (sni != null && !sni.isEmpty()) {
                    detected_snis.put(sni, app);
                }
            } finally {
                app_mutex.unlock();
            }
        }

        void withAppMutex(Runnable r) {
            app_mutex.lock();
            try {
                r.run();
            } finally {
                app_mutex.unlock();
            }
        }
    }

    // =========================================================================
    // Fast Path Processor (one per FP thread)
    // =========================================================================
    static class FastPath {
        private final int id;
        private final Rules rules;
        private final Stats stats;
        private final TSQueue<Packet> output_queue;
        private final TSQueue<Packet> input_queue = new TSQueue<>();
        private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();

        private final AtomicBoolean running = new AtomicBoolean(false);
        private Thread thread;
        private final AtomicLong processed = new AtomicLong(0);

        FastPath(int id, Rules rules, Stats stats, TSQueue<Packet> output_queue) {
            this.id = id;
            this.rules = rules;
            this.stats = stats;
            this.output_queue = output_queue;
        }

        void start() {
            running.set(true);
            thread = new Thread(this::run, "FastPath-" + id);
            thread.start();
        }

        void stop() {
            running.set(false);
            input_queue.shutdown();
            if (thread != null) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        TSQueue<Packet> queue() {
            return input_queue;
        }

        long processedCount() {
            return processed.get();
        }

        private void run() {
            while (running.get()) {
                Optional<Packet> pktOpt = input_queue.pop(100);
                if (!pktOpt.isPresent()) continue;

                processed.incrementAndGet();
                Packet pkt = pktOpt.get();

                // Get or create flow
                FlowEntry flow = flows.computeIfAbsent(pkt.tuple, t -> new FlowEntry());
                if (flow.packets == 0) {
                    flow.tuple = pkt.tuple;
                }
                flow.packets++;
                flow.bytes += pkt.data.length;

                // Try to classify if not done yet
                if (!flow.classified) {
                    classifyFlow(pkt, flow);
                }

                // Check blocking
                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
                }

                // Record stats
                stats.recordApp(flow.app_type, flow.sni);

                // Forward or drop
                if (flow.blocked) {
                    stats.dropped.incrementAndGet();
                } else {
                    stats.forwarded.incrementAndGet();
                    output_queue.push(pkt);
                }
            }
        }

        private void classifyFlow(Packet pkt, FlowEntry flow) {
            // Try SNI extraction for HTTPS
            if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
                byte[] payload = slicePayload(pkt);
                Optional<String> sni = SNIExtractor.extract(payload, pkt.payload_length);
                if (sni.isPresent()) {
                    flow.sni = sni.get();
                    flow.app_type = DpiTypes.sniToAppType(sni.get());
                    flow.classified = true;
                    return;
                }
            }

            // Try HTTP Host extraction
            if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
                byte[] payload = slicePayload(pkt);
                Optional<String> host = HTTPHostExtractor.extract(payload, pkt.payload_length);
                if (host.isPresent()) {
                    flow.sni = host.get();
                    flow.app_type = DpiTypes.sniToAppType(host.get());
                    flow.classified = true;
                    return;
                }
            }

            // DNS
            if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
                flow.app_type = AppType.DNS;
                flow.classified = true;
                return;
            }

            // Port-based fallback (but don't mark as classified - might get SNI later)
            if (pkt.tuple.dst_port == 443) {
                flow.app_type = AppType.HTTPS;
            } else if (pkt.tuple.dst_port == 80) {
                flow.app_type = AppType.HTTP;
            }
        }

        private byte[] slicePayload(Packet pkt) {
            int len = Math.min(pkt.payload_length, pkt.data.length - pkt.payload_offset);
            byte[] out = new byte[len];
            System.arraycopy(pkt.data, pkt.payload_offset, out, 0, len);
            return out;
        }
    }

    // =========================================================================
    // Load Balancer (one per LB thread)
    // =========================================================================
    static class LoadBalancer {
        private final int id;
        private final List<FastPath> fps;
        private final int num_fps;
        private final TSQueue<Packet> input_queue = new TSQueue<>();

        private final AtomicBoolean running = new AtomicBoolean(false);
        private Thread thread;
        private final AtomicLong dispatched = new AtomicLong(0);

        LoadBalancer(int id, List<FastPath> fps) {
            this.id = id;
            this.fps = fps;
            this.num_fps = fps.size();
        }

        void start() {
            running.set(true);
            thread = new Thread(this::run, "LoadBalancer-" + id);
            thread.start();
        }

        void stop() {
            running.set(false);
            input_queue.shutdown();
            if (thread != null) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        TSQueue<Packet> queue() {
            return input_queue;
        }

        long dispatchedCount() {
            return dispatched.get();
        }

        private void run() {
            while (running.get()) {
                Optional<Packet> pktOpt = input_queue.pop(100);
                if (!pktOpt.isPresent()) continue;

                // Hash to select FP
                int hash = pktOpt.get().tuple.hashCode();
                int mixed = Integer.rotateLeft(hash, 15) ^ (hash >>> 3);
                int fpIdx = Math.floorMod(mixed, num_fps);

                fps.get(fpIdx).queue().push(pktOpt.get());
                dispatched.incrementAndGet();
            }
        }
    }

    // =========================================================================
    // DPI Engine
    // =========================================================================
    static class Engine {

        static class Config {
            int num_lbs = 2;
            int fps_per_lb = 2;
        }

        private final Config config;
        private final Rules rules = new Rules();
        private final Stats stats = new Stats();
        private final TSQueue<Packet> output_queue = new TSQueue<>();
        private final List<FastPath> fps = new ArrayList<>();
        private final List<LoadBalancer> lbs = new ArrayList<>();

        Engine(Config cfg) {
            this.config = cfg;
            int totalFps = cfg.num_lbs * cfg.fps_per_lb;

            System.out.println();
            System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
            System.out.println("\u2551              DPI ENGINE v2.0 (Multi-threaded)                 \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551 Load Balancers: " + String.format("%2d", cfg.num_lbs) +
                    "    FPs per LB: " + String.format("%2d", cfg.fps_per_lb) +
                    "    Total FPs: " + String.format("%2d", totalFps) + "     \u2551");
            System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");

            // Create FP threads
            for (int i = 0; i < totalFps; i++) {
                fps.add(new FastPath(i, rules, stats, output_queue));
            }

            // Create LB threads, each managing a subset of FPs
            for (int lb = 0; lb < cfg.num_lbs; lb++) {
                List<FastPath> lbFps = new ArrayList<>();
                int start = lb * cfg.fps_per_lb;
                for (int i = 0; i < cfg.fps_per_lb; i++) {
                    lbFps.add(fps.get(start + i));
                }
                lbs.add(new LoadBalancer(lb, lbFps));
            }
        }

        void blockIP(String ip) { rules.blockIP(ip); }
        void blockApp(String app) { rules.blockApp(app); }
        void blockDomain(String dom) { rules.blockDomain(dom); }

        boolean process(String inputFile, String outputFile) throws IOException, InterruptedException {
            // Open input
            PcapReader reader = new PcapReader();
            if (!reader.open(inputFile)) return false;

            // Open output
            FileOutputStream output;
            try {
                output = new FileOutputStream(outputFile);
            } catch (IOException e) {
                System.err.println("Cannot open output file");
                return false;
            }

            // Write PCAP header
            PcapGlobalHeader hdr = reader.getGlobalHeader();
            writeGlobalHeader(output, hdr);

            // Start all threads
            for (FastPath fp : fps) fp.start();
            for (LoadBalancer lb : lbs) lb.start();

            // Start output writer thread
            AtomicBoolean outputRunning = new AtomicBoolean(true);
            Thread outputThread = new Thread(() -> {
                while (outputRunning.get() || output_queue.size() > 0) {
                    Optional<Packet> pktOpt = output_queue.pop(50);
                    if (!pktOpt.isPresent()) continue;

                    try {
                        writePacket(output, pktOpt.get());
                    } catch (IOException ignored) {
                    }
                }
            }, "DpiMt-Output");
            outputThread.start();

            // Read and dispatch packets
            System.out.println("[Reader] Processing packets...");
            RawPacket raw = new RawPacket();
            ParsedPacket parsed = new ParsedPacket();
            long pktId = 0;

            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) continue;
                if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

                // Create packet
                Packet pkt = new Packet();
                pkt.id = pktId++;
                pkt.ts_sec = raw.header.ts_sec;
                pkt.ts_usec = raw.header.ts_usec;
                pkt.tcp_flags = parsed.tcp_flags;
                pkt.data = raw.data;

                // Parse 5-tuple
                pkt.tuple.src_ip = parseIP(parsed.src_ip);
                pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
                pkt.tuple.src_port = parsed.src_port;
                pkt.tuple.dst_port = parsed.dest_port;
                pkt.tuple.protocol = parsed.protocol;

                // Calculate payload offset
                pkt.payload_offset = 14; // Ethernet
                if (pkt.data.length > 14) {
                    int ipIhl = pkt.data[14] & 0x0F;
                    pkt.payload_offset += ipIhl * 4;

                    if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.length) {
                        int tcpOff = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                        pkt.payload_offset += tcpOff * 4;
                    } else if (parsed.has_udp) {
                        pkt.payload_offset += 8;
                    }

                    if (pkt.payload_offset < pkt.data.length) {
                        pkt.payload_length = pkt.data.length - pkt.payload_offset;
                    } else {
                        pkt.payload_length = 0;
                    }
                }

                // Update stats
                stats.total_packets.incrementAndGet();
                stats.total_bytes.addAndGet(pkt.data.length);
                if (parsed.has_tcp) stats.tcp_packets.incrementAndGet();
                else if (parsed.has_udp) stats.udp_packets.incrementAndGet();

                // Dispatch to LB (hash-based)
                int lbIdx = Math.floorMod(pkt.tuple.hashCode(), lbs.size());
                lbs.get(lbIdx).queue().push(pkt);
            }

            System.out.println("[Reader] Done reading " + pktId + " packets");
            reader.close();

            // Wait for queues to drain
            Thread.sleep(500);

            // Stop all threads
            for (LoadBalancer lb : lbs) lb.stop();
            for (FastPath fp : fps) fp.stop();

            outputRunning.set(false);
            output_queue.shutdown();
            outputThread.join();

            output.close();

            // Print report
            printReport();

            return true;
        }

        private void printReport() {
            System.out.println();
            System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
            System.out.println("\u2551                      PROCESSING REPORT                        \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551 Total Packets:      " + String.format("%12d", stats.total_packets.get()) + "                           \u2551");
            System.out.println("\u2551 Total Bytes:        " + String.format("%12d", stats.total_bytes.get()) + "                           \u2551");
            System.out.println("\u2551 TCP Packets:        " + String.format("%12d", stats.tcp_packets.get()) + "                           \u2551");
            System.out.println("\u2551 UDP Packets:        " + String.format("%12d", stats.udp_packets.get()) + "                           \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551 Forwarded:          " + String.format("%12d", stats.forwarded.get()) + "                           \u2551");
            System.out.println("\u2551 Dropped:            " + String.format("%12d", stats.dropped.get()) + "                           \u2551");

            // Thread stats
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551 THREAD STATISTICS                                             \u2551");
            for (int i = 0; i < lbs.size(); i++) {
                System.out.println("\u2551   LB" + i + " dispatched:   " + String.format("%12d", lbs.get(i).dispatchedCount()) + "                           \u2551");
            }
            for (int i = 0; i < fps.size(); i++) {
                System.out.println("\u2551   FP" + i + " processed:    " + String.format("%12d", fps.get(i).processedCount()) + "                           \u2551");
            }

            // App distribution
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551                   APPLICATION BREAKDOWN                       \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");

            long total = stats.total_packets.get();

            stats.withAppMutex(() -> {
                List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.app_counts.entrySet());
                sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

                for (Map.Entry<AppType, Long> entry : sortedApps) {
                    double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
                    int bar = (int) (pct / 5);
                    StringBuilder barStr = new StringBuilder();
                    for (int i = 0; i < bar; i++) barStr.append('#');

                    System.out.println("\u2551 " +
                            String.format("%-15s", DpiTypes.appTypeToString(entry.getKey())) +
                            String.format("%8d", entry.getValue()) +
                            " " + String.format("%5.1f", pct) + "% " +
                            String.format("%-20s", barStr.toString()) + "  \u2551");
                }
            });

            System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");

            // Detected SNIs
            if (!stats.detected_snis.isEmpty()) {
                System.out.println("\n[Detected Domains/SNIs]");
                for (Map.Entry<String, AppType> entry : stats.detected_snis.entrySet()) {
                    System.out.println("  - " + entry.getKey() + " -> " + DpiTypes.appTypeToString(entry.getValue()));
                }
            }
        }

        private static void writeGlobalHeader(FileOutputStream out, PcapGlobalHeader header) throws IOException {
            byte[] buf = new byte[24];
            writeU32LE(buf, 0, header.magic_number);
            writeU16LE(buf, 4, header.version_major);
            writeU16LE(buf, 6, header.version_minor);
            writeU32LE(buf, 8, header.thiszone);
            writeU32LE(buf, 12, header.sigfigs);
            writeU32LE(buf, 16, header.snaplen);
            writeU32LE(buf, 20, header.network);
            out.write(buf);
        }

        private static void writePacket(FileOutputStream out, Packet pkt) throws IOException {
            byte[] header = new byte[16];
            writeU32LE(header, 0, pkt.ts_sec);
            writeU32LE(header, 4, pkt.ts_usec);
            writeU32LE(header, 8, pkt.data.length);
            writeU32LE(header, 12, pkt.data.length);
            out.write(header);
            out.write(pkt.data);
        }

        private static void writeU32LE(byte[] buf, int offset, long value) {
            buf[offset] = (byte) (value & 0xFF);
            buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
            buf[offset + 2] = (byte) ((value >> 16) & 0xFF);
            buf[offset + 3] = (byte) ((value >> 24) & 0xFF);
        }

        private static void writeU16LE(byte[] buf, int offset, int value) {
            buf[offset] = (byte) (value & 0xFF);
            buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
        }

        // Mirrors the local parseIP lambda used inside DPIEngine::process
        private static long parseIP(String ip) {
            long result = 0;
            int octet = 0, shift = 0;
            for (int i = 0; i < ip.length(); i++) {
                char c = ip.charAt(i);
                if (c == '.') {
                    result |= ((long) octet << shift);
                    shift += 8;
                    octet = 0;
                } else if (c >= '0' && c <= '9') {
                    octet = octet * 10 + (c - '0');
                }
            }
            result |= ((long) octet << shift);
            return result & 0xFFFFFFFFL;
        }
    }

    // =========================================================================
    // Main
    // =========================================================================
    static void printUsage(String prog) {
        System.out.println("\nDPI Engine v2.0 - Multi-threaded Deep Packet Inspection\n" +
                "========================================================\n\n" +
                "Usage: " + prog + " <input.pcap> <output.pcap> [options]\n\n" +
                "Options:\n" +
                "  --block-ip <ip>        Block source IP\n" +
                "  --block-app <app>      Block application (YouTube, Facebook, etc.)\n" +
                "  --block-domain <dom>   Block domain (substring match)\n" +
                "  --lbs <n>              Number of load balancer threads (default: 2)\n" +
                "  --fps <n>              FP threads per LB (default: 2)\n\n" +
                "Example:\n" +
                "  " + prog + " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50\n");
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length < 2) {
            printUsage("DpiMt");
            System.exit(1);
            return;
        }

        String input = args[0];
        String output = args[1];

        Engine.Config cfg = new Engine.Config();
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) blockIps.add(args[++i]);
            else if (arg.equals("--block-app") && i + 1 < args.length) blockApps.add(args[++i]);
            else if (arg.equals("--block-domain") && i + 1 < args.length) blockDomains.add(args[++i]);
            else if (arg.equals("--lbs") && i + 1 < args.length) cfg.num_lbs = Integer.parseInt(args[++i]);
            else if (arg.equals("--fps") && i + 1 < args.length) cfg.fps_per_lb = Integer.parseInt(args[++i]);
        }

        Engine engine = new Engine(cfg);

        for (String ip : blockIps) engine.blockIP(ip);
        for (String app : blockApps) engine.blockApp(app);
        for (String dom : blockDomains) engine.blockDomain(dom);

        if (!engine.process(input, output)) {
            System.exit(1);
            return;
        }

        System.out.println("\nOutput written to: " + output);
    }
}
