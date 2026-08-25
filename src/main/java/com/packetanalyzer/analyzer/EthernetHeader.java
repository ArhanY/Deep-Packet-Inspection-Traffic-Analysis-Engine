package com.packetanalyzer.analyzer;

public class EthernetHeader {
    public byte[] dest_mac = new byte[6];
    public byte[] src_mac = new byte[6];
    public int ether_type;
}
