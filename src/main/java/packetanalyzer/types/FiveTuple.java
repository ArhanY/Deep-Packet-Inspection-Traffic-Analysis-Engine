package packetanalyzer.types;

public class FiveTuple {
    public int srcIp;
    public int dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;

    public FiveTuple() {}

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple other = (FiveTuple) o;
        return srcIp == other.srcIp &&
               dstIp == other.dstIp &&
               srcPort == other.srcPort &&
               dstPort == other.dstPort &&
               protocol == other.protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public String toString() {
        java.util.function.IntFunction<String> formatIP = ip -> 
            ((ip >> 0) & 0xFF) + "." +
            ((ip >> 8) & 0xFF) + "." +
            ((ip >> 16) & 0xFF) + "." +
            ((ip >> 24) & 0xFF);
        
        return formatIP.apply(srcIp) + ":" + srcPort +
               " -> " +
               formatIP.apply(dstIp) + ":" + dstPort +
               " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    @Override
    public int hashCode() {
        long hash = getHash();
        return (int) (hash ^ (hash >>> 32));
    }

    // Expose the 64-bit unsigned hash value to match size_t hashing in C++
    public long getHash() {
        long h = 0;
        h = stepHash(h, srcIp & 0xFFFFFFFFL);
        h = stepHash(h, dstIp & 0xFFFFFFFFL);
        h = stepHash(h, srcPort & 0xFFFFL);
        h = stepHash(h, dstPort & 0xFFFFL);
        h = stepHash(h, protocol & 0xFFL);
        return h;
    }

    private static long stepHash(long h, long val) {
        return h ^ (val + 0x9e3779b9L + (h << 6) + (h >>> 2));
    }
}
