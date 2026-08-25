package com.packetanalyzer.dpi;

import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapGlobalHeader;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class DPIEngine {

    public static class Config {
        public int num_load_balancers = 2;
        public int fps_per_lb = 2;
        public int queue_size = 10000;
        public String rules_file = "";
        public boolean verbose = false;
    }

    private final Config config;

    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;

    private FPManager fpManager;
    private LBManager lbManager;

    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10000);
    private Thread outputThread;
    private FileOutputStream outputFile;
    private final Object outputMutex = new Object();

    private final DPIStats stats = new DPIStats();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);

    private Thread readerThread;

    public DPIEngine(Config config) {
        this.config = config;

        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0                            \u2551");
        System.out.println("\u2551               Deep Packet Inspection System                   \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551 Configuration:                                                \u2551");
        System.out.println("\u2551   Load Balancers:    " + String.format("%3d", config.num_load_balancers) + "                                       \u2551");
        System.out.println("\u2551   FPs per LB:        " + String.format("%3d", config.fps_per_lb) + "                                       \u2551");
        System.out.println("\u2551   Total FP threads:  " + String.format("%3d", config.num_load_balancers * config.fps_per_lb) + "                                       \u2551");
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
    }

    public boolean initialize() {
        // Create rule manager
        ruleManager = new RuleManager();

        // Load rules if specified
        if (config.rules_file != null && !config.rules_file.isEmpty()) {
            ruleManager.loadRules(config.rules_file);
        }

        // Create output callback
        PacketOutputCallback outputCb = this::handleOutput;

        // Create FP manager (creates FP threads and their queues)
        int totalFps = config.num_load_balancers * config.fps_per_lb;
        fpManager = new FPManager(totalFps, ruleManager, outputCb);

        // Create LB manager (creates LB threads, connects to FP queues)
        lbManager = new LBManager(
                config.num_load_balancers,
                config.fps_per_lb,
                fpManager.getQueuePtrs()
        );

        // Create global connection table
        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        processingComplete.set(false);

        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "DPIEngine-Output");
        outputThread.start();

        // Start FP threads
        fpManager.startAll();

        // Start LB threads
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);

        // Stop LB threads first (they feed FPs)
        if (lbManager != null) {
            lbManager.stopAll();
        }

        // Stop FP threads
        if (fpManager != null) {
            fpManager.stopAll();
        }

        // Stop output thread
        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        // Wait for reader to finish
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Wait a bit for queues to drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Signal completion
        processingComplete.set(true);
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        // Initialize if not already done
        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        // Open output file
        try {
            outputFile_open(outputFile);
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        // Start processing threads
        start();

        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "DPIEngine-Reader");
        readerThread.start();

        // Wait for completion
        waitForCompletion();

        // Give some time for final packets to process
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Stop all threads
        stop();

        // Close output file
        outputFile_close();

        // Print final report
        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());

        return true;
    }

    private void outputFile_open(String path) throws IOException {
        synchronized (outputMutex) {
            outputFile = new FileOutputStream(path);
        }
    }

    private void outputFile_close() {
        synchronized (outputMutex) {
            if (outputFile != null) {
                try {
                    outputFile.close();
                } catch (IOException ignored) {
                }
                outputFile = null;
            }
        }
    }

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader();

        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        // Write PCAP header to output
        writeOutputHeader(reader.getGlobalHeader());

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        AtomicInteger packetId = new AtomicInteger(0);

        System.out.println("[Reader] Starting packet processing...");

        while (reader.readNextPacket(raw)) {
            // Parse the packet
            if (!PacketParser.parse(raw, parsed)) {
                continue; // Skip unparseable packets
            }

            // Only process IP packets with TCP/UDP
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
                continue;
            }

            int id = packetId.getAndIncrement();

            // Create packet job
            PacketJob job = createPacketJob(raw, parsed, id);

            // Update global stats
            stats.total_packets.incrementAndGet();
            stats.total_bytes.addAndGet(raw.data.length);

            if (parsed.has_tcp) {
                stats.tcp_packets.incrementAndGet();
            } else if (parsed.has_udp) {
                stats.udp_packets.incrementAndGet();
            }

            // Send to appropriate LB based on hash
            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            lb.getInputQueue().push(job);
        }

        System.out.println("[Reader] Finished reading " + packetId.get() + " packets");
        reader.close();
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packet_id = packetId;
        job.ts_sec = raw.header.ts_sec;
        job.ts_usec = raw.header.ts_usec;

        // Set five-tuple - parse IP addresses from string back to a packed value
        job.tuple.src_ip = parseIP(parsed.src_ip);
        job.tuple.dst_ip = parseIP(parsed.dest_ip);
        job.tuple.src_port = parsed.src_port;
        job.tuple.dst_port = parsed.dest_port;
        job.tuple.protocol = parsed.protocol;

        // TCP flags
        job.tcp_flags = parsed.tcp_flags;

        // Copy packet data
        job.data = raw.data;

        // Calculate offsets
        job.eth_offset = 0;
        job.ip_offset = 14; // Ethernet header is 14 bytes

        // IP header length
        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transport_offset = 14 + ipHeaderLen;

            // Transport header length
            if (parsed.has_tcp && job.data.length > job.transport_offset) {
                int tcpDataOffset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payload_offset = job.transport_offset + tcpHeaderLen;
            } else if (parsed.has_udp) {
                job.payload_offset = job.transport_offset + 8; // UDP header is 8 bytes
            }

            if (job.payload_offset < job.data.length) {
                job.payload_length = job.data.length - job.payload_offset;
            }
        }

        return job;
    }

    // Mirrors the local parseIP lambda in DPIEngine::createPacketJob
    private static long parseIP(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 0;
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

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            Optional<PacketJob> jobOpt = outputQueue.popWithTimeout(100);

            jobOpt.ifPresent(this::writeOutputPacket);
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.dropped_packets.incrementAndGet();
            return;
        }

        stats.forwarded_packets.incrementAndGet();
        outputQueue.push(job);
    }

    private boolean writeOutputHeader(PcapGlobalHeader header) {
        synchronized (outputMutex) {
            if (outputFile == null) return false;

            try {
                byte[] buf = new byte[24];
                writeU32LE(buf, 0, header.magic_number);
                writeU16LE(buf, 4, header.version_major);
                writeU16LE(buf, 6, header.version_minor);
                writeU32LE(buf, 8, header.thiszone);
                writeU32LE(buf, 12, header.sigfigs);
                writeU32LE(buf, 16, header.snaplen);
                writeU32LE(buf, 20, header.network);
                outputFile.write(buf);
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputMutex) {
            if (outputFile == null) return;

            try {
                byte[] header = new byte[16];
                writeU32LE(header, 0, job.ts_sec);
                writeU32LE(header, 4, job.ts_usec);
                writeU32LE(header, 8, job.data.length);
                writeU32LE(header, 12, job.data.length);

                outputFile.write(header);
                outputFile.write(job.data);
            } catch (IOException ignored) {
            }
        }
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

    // ========== Rule Management API ==========

    public void blockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.blockIP(ip);
        }
    }

    public void unblockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.unblockIP(ip);
        }
    }

    public void blockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.blockApp(app);
        }
    }

    public void blockApp(String appName) {
        for (AppType app : AppType.values()) {
            if (app == AppType.APP_COUNT) break;
            if (DpiTypes.appTypeToString(app).equals(appName)) {
                blockApp(app);
                return;
            }
        }
        System.err.println("[DPIEngine] Unknown app: " + appName);
    }

    public void unblockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.unblockApp(app);
        }
    }

    public void unblockApp(String appName) {
        for (AppType app : AppType.values()) {
            if (app == AppType.APP_COUNT) break;
            if (DpiTypes.appTypeToString(app).equals(appName)) {
                unblockApp(app);
                return;
            }
        }
    }

    public void blockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.blockDomain(domain);
        }
    }

    public void unblockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.unblockDomain(domain);
        }
    }

    public boolean loadRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.loadRules(filename);
        }
        return false;
    }

    public boolean saveRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.saveRules(filename);
        }
        return false;
    }

    // ========== Reporting ==========

    public String generateReport() {
        StringBuilder ss = new StringBuilder();

        ss.append("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n");
        ss.append("\u2551                    DPI ENGINE STATISTICS                      \u2551\n");
        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

        ss.append("\u2551 PACKET STATISTICS                                             \u2551\n");
        ss.append("\u2551   Total Packets:      ").append(String.format("%12d", stats.total_packets.get())).append("                        \u2551\n");
        ss.append("\u2551   Total Bytes:        ").append(String.format("%12d", stats.total_bytes.get())).append("                        \u2551\n");
        ss.append("\u2551   TCP Packets:        ").append(String.format("%12d", stats.tcp_packets.get())).append("                        \u2551\n");
        ss.append("\u2551   UDP Packets:        ").append(String.format("%12d", stats.udp_packets.get())).append("                        \u2551\n");

        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        ss.append("\u2551 FILTERING STATISTICS                                          \u2551\n");
        ss.append("\u2551   Forwarded:          ").append(String.format("%12d", stats.forwarded_packets.get())).append("                        \u2551\n");
        ss.append("\u2551   Dropped/Blocked:    ").append(String.format("%12d", stats.dropped_packets.get())).append("                        \u2551\n");

        if (stats.total_packets.get() > 0) {
            double dropRate = 100.0 * stats.dropped_packets.get() / stats.total_packets.get();
            ss.append("\u2551   Drop Rate:          ").append(String.format("%11.2f", dropRate)).append("%                        \u2551\n");
        }

        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            ss.append("\u2551 LOAD BALANCER STATISTICS                                      \u2551\n");
            ss.append("\u2551   LB Received:        ").append(String.format("%12d", lbStats.total_received)).append("                        \u2551\n");
            ss.append("\u2551   LB Dispatched:      ").append(String.format("%12d", lbStats.total_dispatched)).append("                        \u2551\n");
        }

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            ss.append("\u2551 FAST PATH STATISTICS                                          \u2551\n");
            ss.append("\u2551   FP Processed:       ").append(String.format("%12d", fpStats.total_processed)).append("                        \u2551\n");
            ss.append("\u2551   FP Forwarded:       ").append(String.format("%12d", fpStats.total_forwarded)).append("                        \u2551\n");
            ss.append("\u2551   FP Dropped:         ").append(String.format("%12d", fpStats.total_dropped)).append("                        \u2551\n");
            ss.append("\u2551   Active Connections: ").append(String.format("%12d", fpStats.total_connections)).append("                        \u2551\n");
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            ss.append("\u2551 BLOCKING RULES                                                \u2551\n");
            ss.append("\u2551   Blocked IPs:        ").append(String.format("%12d", ruleStats.blocked_ips)).append("                        \u2551\n");
            ss.append("\u2551   Blocked Apps:       ").append(String.format("%12d", ruleStats.blocked_apps)).append("                        \u2551\n");
            ss.append("\u2551   Blocked Domains:    ").append(String.format("%12d", ruleStats.blocked_domains)).append("                        \u2551\n");
            ss.append("\u2551   Blocked Ports:      ").append(String.format("%12d", ruleStats.blocked_ports)).append("                        \u2551\n");
        }

        ss.append("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");

        return ss.toString();
    }

    public String generateClassificationReport() {
        if (fpManager != null) {
            return fpManager.generateClassificationReport();
        }
        return "";
    }

    public DPIStats getStats() {
        return stats;
    }

    public void printStatus() {
        System.out.println("\n--- Live Status ---");
        System.out.println("Packets: " + stats.total_packets.get()
                + " | Forwarded: " + stats.forwarded_packets.get()
                + " | Dropped: " + stats.dropped_packets.get());

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            System.out.println("Connections: " + fpStats.total_connections);
        }
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public Config getConfig() {
        return config;
    }

    public boolean isRunning() {
        return running.get();
    }
}