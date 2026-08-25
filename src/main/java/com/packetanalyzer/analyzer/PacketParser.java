package com.packetanalyzer.analyzer;

import com.packetanalyzer.net.PortableNet;

public final class PacketParser {

    private PacketParser() {}

    private static class Offset {
        int value;
        Offset(int v) { value = v; }
    }

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        // reset every field to its default before reparsing, since the
        // caller reuses the same ParsedPacket instance across packets.
        parsed.src_mac = null;
        parsed.dest_mac = null;
        parsed.ether_type = 0;
        parsed.has_ip = false;
        parsed.ip_version = 0;
        parsed.src_ip = null;
        parsed.dest_ip = null;
        parsed.protocol = 0;
        parsed.ttl = 0;
        parsed.has_tcp = false;
        parsed.has_udp = false;
        parsed.src_port = 0;
        parsed.dest_port = 0;
        parsed.tcp_flags = 0;
        parsed.seq_number = 0;
        parsed.ack_number = 0;
        parsed.payload_length = 0;
        parsed.payload_data = null;
        parsed.payload_offset = 0;

        parsed.timestamp_sec = raw.header.ts_sec;
        parsed.timestamp_usec = raw.header.ts_usec;

        byte[] data = raw.data;
        int len = data.length;
        Offset offset = new Offset(0);

        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }

        if (parsed.ether_type == EtherType.IPv4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }

            if (parsed.protocol == Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }

        if (offset.value < len) {
            parsed.payload_length = len - offset.value;
            parsed.payload_data = data;
            parsed.payload_offset = offset.value;
        } else {
            parsed.payload_length = 0;
            parsed.payload_data = null;
            parsed.payload_offset = 0;
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, Offset offset) {
        final int ETH_HEADER_LEN = 14;

        if (len < ETH_HEADER_LEN) {
            return false; // Packet too short
        }

        parsed.dest_mac = macToString(data, 0);
        parsed.src_mac = macToString(data, 6);
        // NOTE: readU16BE already yields the correct big-endian value here -
        // no additional PortableNet swap is needed (that would double-swap it).
        parsed.ether_type = readU16BE(data, 12);

        offset.value = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, Offset offset) {
        final int MIN_IP_HEADER_LEN = 20;

        if (len < offset.value + MIN_IP_HEADER_LEN) {
            return false; // Packet too short
        }

        int ipStart = offset.value;

        int version_ihl = data[ipStart] & 0xFF;
        parsed.ip_version = (version_ihl >> 4) & 0x0F;
        int ihl = version_ihl & 0x0F;

        if (parsed.ip_version != 4) {
            return false; // Not IPv4
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset.value + ipHeaderLen) {
            return false;
        }

        parsed.ttl = data[ipStart + 8] & 0xFF;
        parsed.protocol = data[ipStart + 9] & 0xFF;

        long srcIp = readU32RawOrder(data, ipStart + 12);
        parsed.src_ip = ipToString(srcIp);

        long destIp = readU32RawOrder(data, ipStart + 16);
        parsed.dest_ip = ipToString(destIp);

        parsed.has_ip = true;
        offset.value += ipHeaderLen;

        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, Offset offset) {
        final int MIN_TCP_HEADER_LEN = 20;

        if (len < offset.value + MIN_TCP_HEADER_LEN) {
            return false;
        }

        int tcpStart = offset.value;

        // NOTE: readU16BE/readU32BE already yield the correct values directly -
        // no additional PortableNet swap needed.
        parsed.src_port = readU16BE(data, tcpStart);
        parsed.dest_port = readU16BE(data, tcpStart + 2);
        parsed.seq_number = readU32BE(data, tcpStart + 4) & 0xFFFFFFFFL;
        parsed.ack_number = readU32BE(data, tcpStart + 8) & 0xFFFFFFFFL;

        int data_offset = (data[tcpStart + 12] >> 4) & 0x0F;
        int tcpHeaderLen = data_offset * 4;

        parsed.tcp_flags = data[tcpStart + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset.value + tcpHeaderLen) {
            return false;
        }

        parsed.has_tcp = true;
        offset.value += tcpHeaderLen;

        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, Offset offset) {
        final int UDP_HEADER_LEN = 8;

        if (len < offset.value + UDP_HEADER_LEN) {
            return false;
        }

        int udpStart = offset.value;

        parsed.src_port = readU16BE(data, udpStart);
        parsed.dest_port = readU16BE(data, udpStart + 2);

        parsed.has_udp = true;
        offset.value += UDP_HEADER_LEN;

        return true;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder ss = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) ss.append(":");
            ss.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return ss.toString();
    }

    public static String ipToString(long ip) {
        // byte 0 of the packet ends up as bits 0-7 of the value.
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Protocol.ICMP: return "ICMP";
            case Protocol.TCP:  return "TCP";
            case Protocol.UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) result.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) result.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) result.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) result.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) result.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) result.append("URG ");
        if (result.length() > 0) result.setLength(result.length() - 1); // remove trailing space
        return result.length() == 0 ? "none" : result.toString();
    }

    // --- Byte helpers for raw packet data ---

    private static int readU16BE(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    private static long readU32BE(byte[] b, int offset) {
        return ((long) (b[offset] & 0xFF) << 24) |
               ((b[offset + 1] & 0xFF) << 16) |
               ((b[offset + 2] & 0xFF) << 8) |
               (b[offset + 3] & 0xFF);
    }

    // Reads four bytes in little-endian order.
    private static long readU32RawOrder(byte[] b, int offset) {
        return (b[offset] & 0xFFL) |
               ((b[offset + 1] & 0xFFL) << 8) |
               ((b[offset + 2] & 0xFFL) << 16) |
               ((b[offset + 3] & 0xFFL) << 24);
    }
}
