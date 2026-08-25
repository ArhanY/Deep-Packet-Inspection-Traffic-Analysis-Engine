package com.packetanalyzer;

import com.packetanalyzer.analyzer.EtherType;
import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class Main {

    static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        // Format timestamp
        Instant instant = Instant.ofEpochSecond(pkt.timestamp_sec);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());

        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.println("Time: " + fmt.format(instant) + "." + String.format("%06d", pkt.timestamp_usec));

        // Ethernet layer
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.src_mac);
        System.out.println("  Destination MAC: " + pkt.dest_mac);

        StringBuilder etherLine = new StringBuilder();
        etherLine.append("  EtherType:       0x").append(String.format("%04x", pkt.ether_type));

        if (pkt.ether_type == EtherType.IPv4) {
            etherLine.append(" (IPv4)");
        } else if (pkt.ether_type == EtherType.IPv6) {
            etherLine.append(" (IPv6)");
        } else if (pkt.ether_type == EtherType.ARP) {
            etherLine.append(" (ARP)");
        }
        System.out.println(etherLine.toString());

        // IP layer
        if (pkt.has_ip) {
            System.out.println("\n[IPv" + pkt.ip_version + "]");
            System.out.println("  Source IP:      " + pkt.src_ip);
            System.out.println("  Destination IP: " + pkt.dest_ip);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP layer
        if (pkt.has_tcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.src_port);
            System.out.println("  Destination Port: " + pkt.dest_port);
            System.out.println("  Sequence Number:  " + pkt.seq_number);
            System.out.println("  Ack Number:       " + pkt.ack_number);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcp_flags));
        }

        // UDP layer
        if (pkt.has_udp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.src_port);
            System.out.println("  Destination Port: " + pkt.dest_port);
        }

        // Payload info
        if (pkt.payload_length > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payload_length + " bytes");

            // Print first 32 bytes of payload as hex (if present)
            StringBuilder preview = new StringBuilder("  Preview: ");
            int previewLen = Math.min(pkt.payload_length, 32);
            for (int i = 0; i < previewLen; i++) {
                preview.append(String.format("%02x", pkt.payload_data[pkt.payload_offset + i] & 0xFF)).append(" ");
            }
            if (pkt.payload_length > 32) {
                preview.append("...");
            }
            System.out.println(preview.toString());
        }
    }

    static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  " + programName + " capture.pcap");
        System.out.println("  " + programName + " capture.pcap 10");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================\n");

        // Check command line arguments
        if (args.length < 1) {
            printUsage("Main");
            System.exit(1);
            return;
        }

        String filename = args[0];
        int maxPackets = -1; // -1 means no limit

        if (args.length >= 2) {
            maxPackets = Integer.parseInt(args[1]);
        }

        // Open the PCAP file
        PcapReader reader = new PcapReader();
        if (!reader.open(filename)) {
            System.exit(1);
            return;
        }

        System.out.println("\n--- Reading packets ---");

        // Read and parse packets
        RawPacket rawPacket = new RawPacket();
        ParsedPacket parsedPacket = new ParsedPacket();
        int packetCount = 0;
        int parseErrors = 0;

        while (reader.readNextPacket(rawPacket)) {
            packetCount++;

            if (PacketParser.parse(rawPacket, parsedPacket)) {
                printPacketSummary(parsedPacket, packetCount);
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }

            // Check if we've reached the limit
            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println("\n(Stopped after " + maxPackets + " packets)");
                break;
            }
        }

        // Summary
        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");

        reader.close();
    }
}