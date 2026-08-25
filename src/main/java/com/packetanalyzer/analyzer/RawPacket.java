package com.packetanalyzer.analyzer;

public class RawPacket {
    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[] data; // The actual packet bytes
}