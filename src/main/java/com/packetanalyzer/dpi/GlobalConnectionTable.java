package com.packetanalyzer.dpi;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;


public class GlobalConnectionTable {

    public static class GlobalStats {
        public long total_active_connections;
        public long total_connections_seen;
        public Map<AppType, Long> app_distribution = new HashMap<>();
        public List<Map.Entry<String, Long>> top_domains = new ArrayList<>();
    }

    private final List<ConnectionTracker> trackers;
    private final ReadWriteLock mutex = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        trackers = new ArrayList<>(numFps);
        for (int i = 0; i < numFps; i++) {
            trackers.add(null);
        }
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        mutex.writeLock().lock();
        try {
            if (fpId < trackers.size()) {
                trackers.set(fpId, tracker);
            }
        } finally {
            mutex.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        mutex.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            stats.total_active_connections = 0;
            stats.total_connections_seen = 0;

            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats trackerStats = tracker.getStats();
                stats.total_active_connections += trackerStats.active_connections;
                stats.total_connections_seen += trackerStats.total_connections_seen;

                tracker.forEach(conn -> {
                    stats.app_distribution.merge(conn.app_type, 1L, Long::sum);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            // Get top domains
            List<Map.Entry<String, Long>> domainVec = new ArrayList<>(domainCounts.entrySet());
            domainVec.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            int count = Math.min(domainVec.size(), 20);
            for (int i = 0; i < count; i++) {
                Map.Entry<String, Long> e = domainVec.get(i);
                stats.top_domains.add(new AbstractMap.SimpleEntry<>(e.getKey(), e.getValue()));
            }

            return stats;
        } finally {
            mutex.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();

        StringBuilder ss = new StringBuilder();
        ss.append("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n");
        ss.append("\u2551               CONNECTION STATISTICS REPORT                    \u2551\n");
        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

        ss.append("\u2551 Active Connections:     ").append(String.format("%10d", stats.total_active_connections)).append("                          \u2551\n");
        ss.append("\u2551 Total Connections Seen: ").append(String.format("%10d", stats.total_connections_seen)).append("                          \u2551\n");

        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        ss.append("\u2551                    APPLICATION BREAKDOWN                      \u2551\n");
        ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

        long total = 0;
        for (long v : stats.app_distribution.values()) {
            total += v;
        }

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.app_distribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            ss.append("\u2551 ")
              .append(String.format("%-20s", DpiTypes.appTypeToString(entry.getKey())))
              .append(String.format("%10d", entry.getValue()))
              .append(" (").append(String.format("%5.1f", pct)).append("%)           \u2551\n");
        }

        if (!stats.top_domains.isEmpty()) {
            ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            ss.append("\u2551                      TOP DOMAINS                             \u2551\n");
            ss.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");

            for (Map.Entry<String, Long> entry : stats.top_domains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                ss.append("\u2551 ")
                  .append(String.format("%-40s", domain))
                  .append(String.format("%10d", entry.getValue()))
                  .append("           \u2551\n");
            }
        }

        ss.append("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");

        return ss.toString();
    }
}