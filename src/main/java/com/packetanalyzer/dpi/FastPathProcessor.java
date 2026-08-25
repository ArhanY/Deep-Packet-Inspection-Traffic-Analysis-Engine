package com.packetanalyzer.dpi;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor {

    public static class FPStats {
        public long packets_processed;
        public long packets_forwarded;
        public long packets_dropped;
        public long connections_tracked;
        public long sni_extractions;
        public long classification_hits;
    }

    private static final int SYN = 0x02;
    private static final int ACK = 0x10;
    private static final int FIN = 0x01;
    private static final int RST = 0x04;

    private final int fpId;

    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10000);
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        thread = new Thread(this::run, "FP-" + fpId);
        thread.start();

        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);
        inputQueue.shutdown();

        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    private void run() {
        while (running.get()) {
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (!jobOpt.isPresent()) {
                // Periodically cleanup stale connections
                connTracker.cleanupStale(300);
                continue;
            }

            packetsProcessed.incrementAndGet();

            PacketJob job = jobOpt.get();

            // Process the packet
            PacketAction action = processPacket(job);

            // Call output callback
            if (outputCallback != null) {
                outputCallback.accept(job, action);
            }

            // Update stats
            if (action == PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        // Get or create connection
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            // Should not happen, but handle gracefully
            return PacketAction.FORWARD;
        }

        // Update connection stats
        boolean isOutbound = true; // In this model, all packets from user are outbound
        connTracker.updateConnection(conn, job.data.length, isOutbound);

        // Update TCP state if applicable
        if (job.tuple.protocol == 6) { // TCP
            updateTCPState(conn, job.tcp_flags);
        }

        // If connection is already blocked, drop immediately
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // If connection not yet classified, try to inspect payload
        if (conn.state != ConnectionState.CLASSIFIED && job.payload_length > 0) {
            inspectPayload(job, conn);
        }

        // Check rules (even for classified connections, as rules might change)
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payload_length == 0 || job.payload_offset >= job.data.length) {
            return;
        }

        byte[] payload = slicePayload(job);

        // Try TLS SNI extraction first (most common for HTTPS)
        if (tryExtractSNI(job, conn)) {
            return;
        }

        // Try HTTP Host header extraction
        if (tryExtractHTTPHost(job, conn)) {
            return;
        }

        // Check for DNS (port 53)
        if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
            Optional<String> domain = DNSExtractor.extractQuery(payload, job.payload_length);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Basic port-based classification as fallback
        if (job.tuple.dst_port == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dst_port == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        // Only for port 443 (HTTPS) or if it looks like TLS
        if (job.tuple.dst_port != 443 && job.payload_length < 50) {
            return false;
        }

        if (job.payload_offset >= job.data.length || job.payload_length == 0) {
            return false;
        }

        byte[] payload = slicePayload(job);
        Optional<String> sni = SNIExtractor.extract(payload, job.payload_length);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();

            // Map SNI to app type
            AppType app = DpiTypes.sniToAppType(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }

            return true;
        }

        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        // Only for port 80 (HTTP)
        if (job.tuple.dst_port != 80) {
            return false;
        }

        if (job.payload_offset >= job.data.length || job.payload_length == 0) {
            return false;
        }

        byte[] payload = slicePayload(job);
        Optional<String> host = HTTPHostExtractor.extract(payload, job.payload_length);
        if (host.isPresent()) {
            AppType app = DpiTypes.sniToAppType(host.get());
            connTracker.classifyConnection(conn, app, host.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }

            return true;
        }

        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        // Parse source IP from tuple
        long srcIp = job.tuple.src_ip;

        // Check blocking rules
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
                srcIp,
                job.tuple.dst_port,
                conn.app_type,
                conn.sni
        );

        if (blockReason.isPresent()) {
            RuleManager.BlockReason reason = blockReason.get();

            // Log the block
            StringBuilder ss = new StringBuilder();
            ss.append("[FP").append(fpId).append("] BLOCKED packet: ");

            switch (reason.type) {
                case IP:
                    ss.append("IP ").append(reason.detail);
                    break;
                case APP:
                    ss.append("App ").append(reason.detail);
                    break;
                case DOMAIN:
                    ss.append("Domain ").append(reason.detail);
                    break;
                case PORT:
                    ss.append("Port ").append(reason.detail);
                    break;
            }

            System.out.println(ss.toString());

            // Mark connection as blocked
            connTracker.blockConnection(conn);

            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) {
                conn.syn_ack_seen = true;
            } else {
                conn.syn_seen = true;
            }
        }

        if (conn.syn_seen && conn.syn_ack_seen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((tcpFlags & FIN) != 0) {
            conn.fin_seen = true;
        }

        if ((tcpFlags & RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.fin_seen && (tcpFlags & ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    private byte[] slicePayload(PacketJob job) {
        int len = Math.min(job.payload_length, job.data.length - job.payload_offset);
        byte[] out = new byte[len];
        System.arraycopy(job.data, job.payload_offset, out, 0, len);
        return out;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packets_processed = packetsProcessed.get();
        stats.packets_forwarded = packetsForwarded.get();
        stats.packets_dropped = packetsDropped.get();
        stats.connections_tracked = connTracker.getActiveCount();
        stats.sni_extractions = sniExtractions.get();
        stats.classification_hits = classificationHits.get();
        return stats;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running.get();
    }
}