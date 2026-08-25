package com.packetanalyzer.analyzer;

public class IPv4Header {
    public int version_ihl;
    public int tos;
    public int total_length;
    public int identification;
    public int flags_fragment;
    public int ttl;
    public int protocol;
    public int checksum;
    public long src_ip;
    public long dest_ip;
}
