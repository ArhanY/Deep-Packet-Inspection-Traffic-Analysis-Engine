package com.packetanalyzer;

import com.packetanalyzer.analyzer.PcapGlobalHeader;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PcapReaderTest {

    @Test
    void globalHeaderParsesCorrectly() {
        PcapReader reader = new PcapReader();
        assertTrue(reader.open("test_dpi.pcap"), "Should open test_dpi.pcap successfully");

        PcapGlobalHeader hdr = reader.getGlobalHeader();
        assertEquals(2, hdr.version_major, "PCAP major version should be 2");
        assertEquals(4, hdr.version_minor, "PCAP minor version should be 4");
        assertEquals(65535, hdr.snaplen, "Snaplen should be 65535");
        assertEquals(1, hdr.network, "Link type should be 1 (Ethernet)");

        reader.close();
    }

    @Test
    void canReadAtLeastOnePacket() {
        PcapReader reader = new PcapReader();
        assertTrue(reader.open("test_dpi.pcap"));

        RawPacket packet = new RawPacket();
        assertTrue(reader.readNextPacket(packet), "Should read at least one packet");
        assertNotNull(packet.data, "Packet data should not be null");
        assertTrue(packet.data.length > 0, "Packet data should not be empty");

        reader.close();
    }
}
