package com.packetanalyzer.dpi;

public class Connection {
    public FiveTuple tuple = new FiveTuple();
    public ConnectionState state = ConnectionState.NEW;
    public AppType app_type = AppType.UNKNOWN;
    public String sni = ""; // Server Name Indication (if detected)

    public long packets_in = 0;
    public long packets_out = 0;
    public long bytes_in = 0;
    public long bytes_out = 0;

    // Monotonic timestamp for connection tracking
    public long first_seen; // nanoTime()
    public long last_seen;  // nanoTime()

    public PacketAction action = PacketAction.FORWARD;

    // For TCP state tracking
    public boolean syn_seen = false;
    public boolean syn_ack_seen = false;
    public boolean fin_seen = false;
}
