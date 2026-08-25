package com.packetanalyzer.dpi;

@FunctionalInterface
public interface PacketOutputCallback {
    void accept(PacketJob job, PacketAction action);
}