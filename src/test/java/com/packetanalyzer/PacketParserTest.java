package com.packetanalyzer;

import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PacketParserTest {

    @Test
    void parsedPacketsHaveSaneFields() {
        PcapReader reader = new PcapReader();
        assertTrue(reader.open("test_dpi.pcap"));

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int parsedCount = 0;

        while (reader.readNextPacket(raw) && parsedCount < 5) {
            if (!PacketParser.parse(raw, parsed)) continue;

            // Ethernet layer: MAC addresses should be present
            assertNotNull(parsed.src_mac, "Source MAC should not be null");
            assertNotNull(parsed.dest_mac, "Dest MAC should not be null");

            if (parsed.has_ip) {
                // IP addresses should be in valid dotted-decimal format
                assertNotNull(parsed.src_ip, "Source IP should not be null");
                assertNotNull(parsed.dest_ip, "Dest IP should not be null");
                assertTrue(parsed.src_ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"),
                        "Source IP should be dotted-decimal: " + parsed.src_ip);
                assertTrue(parsed.dest_ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"),
                        "Dest IP should be dotted-decimal: " + parsed.dest_ip);

                if (parsed.has_tcp || parsed.has_udp) {
                    // Ports should be in valid range
                    assertTrue(parsed.src_port >= 0 && parsed.src_port <= 65535,
                            "Source port out of range: " + parsed.src_port);
                    assertTrue(parsed.dest_port >= 0 && parsed.dest_port <= 65535,
                            "Dest port out of range: " + parsed.dest_port);
                }
            }

            parsedCount++;
        }

        assertTrue(parsedCount > 0, "Should have parsed at least one packet");
        reader.close();
    }
}
