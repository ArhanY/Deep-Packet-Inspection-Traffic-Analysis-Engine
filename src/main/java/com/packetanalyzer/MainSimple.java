package com.packetanalyzer;

import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;
import com.packetanalyzer.dpi.SNIExtractor;

import java.util.Optional;

public class MainSimple {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: MainSimple <pcap_file>");
            System.exit(1);
            return;
        }

        PcapReader reader = new PcapReader();
        if (!reader.open(args[0])) {
            System.exit(1);
            return;
        }

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int count = 0;
        int tlsCount = 0;

        System.out.println("Processing packets...");

        while (reader.readNextPacket(raw)) {
            count++;

            if (!PacketParser.parse(raw, parsed)) {
                continue;
            }

            if (!parsed.has_ip) continue;

            StringBuilder line = new StringBuilder();
            line.append("Packet ").append(count).append(": ")
                .append(parsed.src_ip).append(":").append(parsed.src_port)
                .append(" -> ").append(parsed.dest_ip).append(":").append(parsed.dest_port);

            // Try SNI extraction for HTTPS packets
            if (parsed.has_tcp && parsed.dest_port == 443 && parsed.payload_length > 0) {
                // Calculate payload offset
                int payloadOffset = 14; // Ethernet
                int ipIhl = raw.data[14] & 0x0F;
                payloadOffset += ipIhl * 4;
                int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                payloadOffset += tcpOffset * 4;

                if (payloadOffset < raw.data.length) {
                    int payloadLen = raw.data.length - payloadOffset;
                    byte[] payload = new byte[payloadLen];
                    System.arraycopy(raw.data, payloadOffset, payload, 0, payloadLen);

                    Optional<String> sni = SNIExtractor.extract(payload, payloadLen);
                    if (sni.isPresent()) {
                        line.append(" [SNI: ").append(sni.get()).append("]");
                        tlsCount++;
                    }
                }
            }

            System.out.println(line.toString());
        }

        System.out.println("\nTotal packets: " + count);
        System.out.println("SNI extracted: " + tlsCount);

        reader.close();
    }
}