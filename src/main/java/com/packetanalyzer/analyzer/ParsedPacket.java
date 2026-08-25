package com.packetanalyzer.analyzer;

public class ParsedPacket {
    // Timestamps
    public long timestamp_sec;
    public long timestamp_usec;

    // Ethernet layer
    public String src_mac;
    public String dest_mac;
    public int ether_type;

    // IP layer (if present)
    public boolean has_ip = false;
    public int ip_version;
    public String src_ip;
    public String dest_ip;
    public int protocol;   // TCP=6, UDP=17, ICMP=1
    public int ttl;

    // Transport layer (if present)
    public boolean has_tcp = false;
    public boolean has_udp = false;
    public int src_port;
    public int dest_port;

    // TCP-specific
    public int tcp_flags;
    public long seq_number;
    public long ack_number;

    // Payload
    public int payload_length;
    public byte[] payload_data = null; // logically "points into" original packet
    public int payload_offset = 0;     // offset into the original packet's data array
}