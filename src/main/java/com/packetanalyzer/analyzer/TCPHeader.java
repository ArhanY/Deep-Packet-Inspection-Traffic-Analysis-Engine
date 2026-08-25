package com.packetanalyzer.analyzer;

public class TCPHeader {
    public int src_port;
    public int dest_port;
    public long seq_number;
    public long ack_number;
    public int data_offset;
    public int flags;
    public int window;
    public int checksum;
    public int urgent_pointer;
}
