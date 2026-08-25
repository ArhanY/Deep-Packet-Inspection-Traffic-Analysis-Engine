package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class ConnectionTracker {

    public static class TrackerStats {
        public long active_connections;
        public long total_connections_seen;
        public long classified_connections;
        public long blocked_connections;
    }

    private final int fpId;
    private final long maxConnections;

    // Connection table (FiveTuple hash ensures consistent mapping)
    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    public ConnectionTracker(int fpId, long maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    // Get or create connection entry
    public synchronized Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = connections.get(tuple);
        if (existing != null) {
            return existing;
        }

        // Check if we need to evict old connections
        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        // Create new connection
        Connection conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.first_seen = System.nanoTime();
        conn.last_seen = conn.first_seen;

        connections.put(tuple, conn);
        totalSeen++;

        return conn;
    }

    // Get existing connection (returns null if not found)
    public synchronized Connection getConnection(FiveTuple tuple) {
        Connection direct = connections.get(tuple);
        if (direct != null) {
            return direct;
        }

        // Try reverse tuple (for bidirectional matching)
        Connection reverse = connections.get(tuple.reverse());
        if (reverse != null) {
            return reverse;
        }

        return null;
    }

    // Update connection with new packet
    public synchronized void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;

        conn.last_seen = System.nanoTime();

        if (isOutbound) {
            conn.packets_out++;
            conn.bytes_out += packetSize;
        } else {
            conn.packets_in++;
            conn.bytes_in += packetSize;
        }
    }

    // Mark connection as classified
    public synchronized void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;

        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.app_type = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    // Mark connection as blocked
    public synchronized void blockConnection(Connection conn) {
        if (conn == null) return;

        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    // Mark connection as closed
    public synchronized void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    // Remove timed-out connections. timeoutSeconds defaults to 300 in the original.
    public synchronized long cleanupStale(long timeoutSeconds) {
        long now = System.nanoTime();
        long timeoutNanos = timeoutSeconds * 1_000_000_000L;
        long removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            long age = now - entry.getValue().last_seen;

            if (age > timeoutNanos || entry.getValue().state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }

        return removed;
    }

    public synchronized long cleanupStale() {
        return cleanupStale(300);
    }

    // Get all connections (for reporting)
    public synchronized List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    // Get active connection count
    public synchronized long getActiveCount() {
        return connections.size();
    }

    public synchronized TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.active_connections = connections.size();
        stats.total_connections_seen = totalSeen;
        stats.classified_connections = classifiedCount;
        stats.blocked_connections = blockedCount;
        return stats;
    }

    // Clear all connections
    public synchronized void clear() {
        connections.clear();
    }

    // Iteration callback for all connections
    public synchronized void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;

        Map.Entry<FiveTuple, Connection> oldest = null;
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (oldest == null || entry.getValue().last_seen < oldest.getValue().last_seen) {
                oldest = entry;
            }
        }

        if (oldest != null) {
            connections.remove(oldest.getKey());
        }
    }
}