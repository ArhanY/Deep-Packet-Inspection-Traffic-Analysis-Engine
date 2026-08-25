package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FPManager {

    public static class AggregatedStats {
        public long total_processed;
        public long total_forwarded;
        public long total_dropped;
        public long total_connections;
    }

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        // Create FP processors (each has its own input queue)
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }

        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    public void stopAll() {
        // Stop all FPs (they'll shutdown their own queues)
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public ThreadSafeQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> ptrs = new ArrayList<>();
        for (FastPathProcessor fp : fps) {
            ptrs.add(fp.getInputQueue());
        }
        return ptrs;
    }

    public int getNumFPs() {
        return fps.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();

        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats fpStats = fp.getStats();
            stats.total_processed += fpStats.packets_processed;
            stats.total_forwarded += fpStats.packets_forwarded;
            stats.total_dropped += fpStats.packets_dropped;
            stats.total_connections += fpStats.connections_tracked;
        }

        return stats;
    }

    public String generateClassificationReport() {
        // Aggregate app distribution across all FPs
        Map<AppType, Long> appCounts = new HashMap<>();
        Map<String, Long> domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            for (Connection conn : fp.getConnectionTracker().getAllConnections()) {
                appCounts.merge(conn.app_type, 1L, Long::sum);

                if (conn.app_type == AppType.UNKNOWN) {
                    totalUnknown++;
                } else {
                    totalClassified++;
                }

                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1L, Long::sum);
                }
            }
        }

        StringBuilder ss = new StringBuilder();
        ss.append("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n");
        ss.append("\u2551                 APPLICATION CLASSIFICATION REPORT             \u2551\n");
        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

        ss.append("\u2551 Total Connections:    ").append(String.format("%10d", total)).append("                           \u2551\n");
        ss.append("\u2551 Classified:           ").append(String.format("%10d", totalClassified))
          .append(" (").append(String.format("%.1f", classifiedPct)).append("%)                  \u2551\n");
        ss.append("\u2551 Unidentified:         ").append(String.format("%10d", totalUnknown))
          .append(" (").append(String.format("%.1f", unknownPct)).append("%)                  \u2551\n");

        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        ss.append("\u2551                    APPLICATION DISTRIBUTION                   \u2551\n");
        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;

            // Create a simple bar graph
            int barLen = (int) (pct / 5); // 20 chars max
            StringBuilder bar = new StringBuilder();
            for (int i = 0; i < barLen; i++) bar.append('#');

            ss.append("\u2551 ")
              .append(String.format("%-15s", DpiTypes.appTypeToString(entry.getKey())))
              .append(String.format("%8d", entry.getValue()))
              .append(" ").append(String.format("%5.1f", pct)).append("% ")
              .append(String.format("%-20s", bar.toString())).append("   \u2551\n");
        }

        ss.append("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");

        return ss.toString();
    }
}