package com.packetanalyzer.dpi;

public class PacketJob {
    public long packet_id;
    public FiveTuple tuple = new FiveTuple();
    public byte[] data;
    public int eth_offset = 0;
    public int ip_offset = 0;
    public int transport_offset = 0;
    public int payload_offset = 0;
    public int payload_length = 0;
    public int tcp_flags = 0;
    public byte[] payload_data = null; // logically "points into" data

    // Timestamps
    public long ts_sec;
    public long ts_usec;
}