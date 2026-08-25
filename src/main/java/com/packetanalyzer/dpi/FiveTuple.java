package com.packetanalyzer.dpi;

import java.util.Objects;

public class FiveTuple {
    public long src_ip;   // stored as unsigned 32-bit in a long
    public long dst_ip;
    public int src_port;  // stored as unsigned 16-bit in an int
    public int dst_port;
    public int protocol;  // TCP=6, UDP=17 (stored as unsigned 8-bit in an int)

    public FiveTuple() {}

    public FiveTuple(long src_ip, long dst_ip, int src_port, int dst_port, int protocol) {
        this.src_ip = src_ip;
        this.dst_ip = dst_ip;
        this.src_port = src_port;
        this.dst_port = dst_port;
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple other = (FiveTuple) o;
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    // Create reverse tuple (for matching bidirectional flows)
    public FiveTuple reverse() {
        return new FiveTuple(dst_ip, src_ip, dst_port, src_port, protocol);
    }

    public String toString() {
        return FiveTupleUtil.toString(this);
    }

    @Override
    public int hashCode() {
        long h = 0;
        h ^= Objects.hashCode(src_ip) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Objects.hashCode(dst_ip) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Objects.hashCode(src_port) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Objects.hashCode(dst_port) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Objects.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int) h;
    }
}