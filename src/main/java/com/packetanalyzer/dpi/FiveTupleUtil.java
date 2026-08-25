package com.packetanalyzer.dpi;

public final class FiveTupleUtil {

    private FiveTupleUtil() {}

    public static String toString(FiveTuple t) {
        StringBuilder ss = new StringBuilder();

        ss.append(formatIP(t.src_ip)).append(":").append(t.src_port)
          .append(" -> ")
          .append(formatIP(t.dst_ip)).append(":").append(t.dst_port)
          .append(" (").append(t.protocol == 6 ? "TCP" : t.protocol == 17 ? "UDP" : "?").append(")");

        return ss.toString();
    }

    private static String formatIP(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }
}