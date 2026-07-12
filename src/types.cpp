package packetanalyzer;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

public final class Types {

    private Types() {
    }

    // =========================================================================
    // FiveTuple
    // =========================================================================

    public static class FiveTuple {

        public int src_ip;
        public int dst_ip;
        public short src_port;
        public short dst_port;
        public byte protocol;

        public FiveTuple() {
        }

        public FiveTuple(int src_ip,
                         int dst_ip,
                         short src_port,
                         short dst_port,
                         byte protocol) {

            this.src_ip = src_ip;
            this.dst_ip = dst_ip;
            this.src_port = src_port;
            this.dst_port = dst_port;
            this.protocol = protocol;
        }

        public FiveTuple reverse() {
            return new FiveTuple(
                    dst_ip,
                    src_ip,
                    dst_port,
                    src_port,
                    protocol
            );
        }

        @Override
        public boolean equals(Object obj) {

            if (this == obj)
                return true;

            if (!(obj instanceof FiveTuple))
                return false;

            FiveTuple other = (FiveTuple) obj;

            return src_ip == other.src_ip &&
                    dst_ip == other.dst_ip &&
                    src_port == other.src_port &&
                    dst_port == other.dst_port &&
                    protocol == other.protocol;
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol
            );
        }

        @Override
        public String toString() {

            return formatIP(src_ip)
                    + ":"
                    + Short.toUnsignedInt(src_port)
                    + " -> "
                    + formatIP(dst_ip)
                    + ":"
                    + Short.toUnsignedInt(dst_port)
                    + " ("
                    + (protocol == 6 ? "TCP"
                    : protocol == 17 ? "UDP"
                    : "?")
                    + ")";
        }

        private static String formatIP(int ip) {

            return (ip & 0xFF)
                    + "."
                    + ((ip >> 8) & 0xFF)
                    + "."
                    + ((ip >> 16) & 0xFF)
                    + "."
                    + ((ip >> 24) & 0xFF);
        }
    }

    // =========================================================================
    // FiveTupleHash
    // =========================================================================

    public static class FiveTupleHash {

        public int hash(FiveTuple tuple) {

            int h = 0;

            h ^= Integer.hashCode(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Integer.hashCode(tuple.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Short.hashCode(tuple.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Short.hashCode(tuple.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Byte.hashCode(tuple.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);

            return h;
        }
    }

    // =========================================================================
    // Application Classification
    // =========================================================================

    public enum AppType {
        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,

        GOOGLE,
        FACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE,

        APP_COUNT
    }

    // =========================================================================

    public enum ConnectionState {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    // =========================================================================

    public enum PacketAction {
        FORWARD,
        DROP,
        INSPECT,
        LOG_ONLY
    }

    // =========================================================================
    // Connection
    // =========================================================================

    public static class Connection {

        public FiveTuple tuple;

        public ConnectionState state = ConnectionState.NEW;

        public AppType app_type = AppType.UNKNOWN;

        public String sni = "";

        public long packets_in = 0;
        public long packets_out = 0;

        public long bytes_in = 0;
        public long bytes_out = 0;

        public Instant first_seen;
        public Instant last_seen;

        public PacketAction action = PacketAction.FORWARD;

        public boolean syn_seen = false;
        public boolean syn_ack_seen = false;
        public boolean fin_seen = false;
    }

    // =========================================================================
    // PacketJob
    // =========================================================================

    public static class PacketJob {

        public int packet_id;

        public FiveTuple tuple;

        public byte[] data;

        public long eth_offset = 0;
        public long ip_offset = 0;
        public long transport_offset = 0;
        public long payload_offset = 0;
        public long payload_length = 0;

        public byte tcp_flags = 0;

        /*
         * C++:
         * const uint8_t* payload_data
         *
         * Java equivalent:
         * index inside data[]
         */
        public int payload_data = -1;

        public int ts_sec;
        public int ts_usec;
    }

    // =========================================================================
    // DPIStats
    // =========================================================================

    public static class DPIStats {

        public final AtomicLong total_packets = new AtomicLong(0);
        public final AtomicLong total_bytes = new AtomicLong(0);
        public final AtomicLong forwarded_packets = new AtomicLong(0);
        public final AtomicLong dropped_packets = new AtomicLong(0);
        public final AtomicLong tcp_packets = new AtomicLong(0);
        public final AtomicLong udp_packets = new AtomicLong(0);
        public final AtomicLong other_packets = new AtomicLong(0);
        public final AtomicLong active_connections = new AtomicLong(0);

        public DPIStats() {
        }
    }

    // =========================================================================
    // Function declarations (implemented in Part 2)
    // =========================================================================

    public static String appTypeToString(AppType type);

    public static AppType sniToAppType(String sni);
}