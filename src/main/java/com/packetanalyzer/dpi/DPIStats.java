package com.packetanalyzer.dpi;

import java.util.concurrent.atomic.AtomicLong;

// Thread-safe counters for engine statistics
public class DPIStats {
    public final AtomicLong total_packets = new AtomicLong(0);
    public final AtomicLong total_bytes = new AtomicLong(0);
    public final AtomicLong forwarded_packets = new AtomicLong(0);
    public final AtomicLong dropped_packets = new AtomicLong(0);
    public final AtomicLong tcp_packets = new AtomicLong(0);
    public final AtomicLong udp_packets = new AtomicLong(0);
    public final AtomicLong other_packets = new AtomicLong(0);
    public final AtomicLong active_connections = new AtomicLong(0);

    public DPIStats() {}
}
