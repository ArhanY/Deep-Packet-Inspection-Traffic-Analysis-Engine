package com.packetanalyzer.net;

public final class PortableNet {

    private PortableNet() {}

    public static int swapBytes16(int value) {
        value &= 0xFFFF;
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    public static long swapBytes32(long value) {
        value &= 0xFFFFFFFFL;
        return ((value & 0xFF000000L) >> 24) |
               ((value & 0x00FF0000L) >> 8)  |
               ((value & 0x0000FF00L) << 8)  |
               ((value & 0x000000FFL) << 24);
    }

    // Java is always big-endian internally for its numeric types
    public static boolean isLittleEndian() {
        return true; // matches original behavior on x86/ARM little-endian hosts
    }

    public static int netToHost16(int netValue) {
        if (isLittleEndian()) {
            return swapBytes16(netValue);
        }
        return netValue & 0xFFFF;
    }

    public static long netToHost32(long netValue) {
        if (isLittleEndian()) {
            return swapBytes32(netValue);
        }
        return netValue & 0xFFFFFFFFL;
    }

    public static int hostToNet16(int hostValue) {
        return netToHost16(hostValue); // Same operation
    }

    public static long hostToNet32(long hostValue) {
        return netToHost32(hostValue); // Same operation
    }
}