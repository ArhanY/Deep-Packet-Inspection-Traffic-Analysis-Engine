package com.packetanalyzer.analyzer;

import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader implements AutoCloseable {

    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private FileInputStream file;
    private PcapGlobalHeader globalHeader = new PcapGlobalHeader();
    private boolean needsByteSwap = false;
    private long bytesRead = 0;

    public PcapReader() {}

    public boolean open(String filename) {
        // Close any previously opened file
        close();

        try {
            file = new FileInputStream(filename);
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }

        try {
            byte[] header = readExactly(24); // sizeof(PcapGlobalHeader)
            if (header == null) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            globalHeader.magic_number = readU32LE(header, 0);
            globalHeader.version_major = (int) readU16LE(header, 4);
            globalHeader.version_minor = (int) readU16LE(header, 6);
            globalHeader.thiszone = (int) readU32LE(header, 8);
            globalHeader.sigfigs = readU32LE(header, 12);
            globalHeader.snaplen = readU32LE(header, 16);
            globalHeader.network = readU32LE(header, 20);

            if (globalHeader.magic_number == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            } else if (globalHeader.magic_number == PCAP_MAGIC_SWAPPED) {
                needsByteSwap = true;
                globalHeader.version_major = (int) maybeSwap16(globalHeader.version_major);
                globalHeader.version_minor = (int) maybeSwap16(globalHeader.version_minor);
                globalHeader.snaplen = maybeSwap32(globalHeader.snaplen);
                globalHeader.network = maybeSwap32(globalHeader.network);
            } else {
                System.err.println("Error: Invalid PCAP magic number: 0x" +
                        Long.toHexString(globalHeader.magic_number));
                close();
                return false;
            }

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.version_major + "." + globalHeader.version_minor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network +
                    (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }
    }

    public void close() {
        if (file != null) {
            try {
                file.close();
            } catch (IOException ignored) {
            }
            file = null;
        }
        needsByteSwap = false;
        bytesRead = 0;
    }

    public boolean readNextPacket(RawPacket packet) {
        if (file == null) {
            return false;
        }

        while (true) {
            try {
                byte[] header = readExactly(16); // sizeof(PcapPacketHeader)
                if (header == null) {
                    return false; // End of file or error
                }

                packet.header.ts_sec = readU32LE(header, 0);
                packet.header.ts_usec = readU32LE(header, 4);
                packet.header.incl_len = readU32LE(header, 8);
                packet.header.orig_len = readU32LE(header, 12);

                if (needsByteSwap) {
                    packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
                    packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
                    packet.header.incl_len = maybeSwap32(packet.header.incl_len);
                    packet.header.orig_len = maybeSwap32(packet.header.orig_len);
                }

                if (packet.header.incl_len > globalHeader.snaplen ||
                    packet.header.incl_len > 65535) {
                    System.err.println("[PcapReader] Skipping corrupt packet at offset " + bytesRead +
                            ": invalid packet length " + packet.header.incl_len);
                    continue;
                }

                int len = (int) packet.header.incl_len;
                byte[] data = readExactly(len);
                if (data == null) {
                    System.err.println("[PcapReader] Skipping corrupt packet at offset " + bytesRead +
                            ": truncated packet data (expected " + len + " bytes)");
                    return false; // EOF mid-packet, no more data to read
                }
                packet.data = data;

                return true;
            } catch (IOException e) {
                System.err.println("[PcapReader] Skipping corrupt packet at offset " + bytesRead +
                        ": " + e.getMessage());
                continue;
            }
        }
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return file != null;
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }

    private long maybeSwap16(long value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    private long maybeSwap32(long value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF000000L) >> 24) |
               ((value & 0x00FF0000L) >> 8)  |
               ((value & 0x0000FF00L) << 8)  |
               ((value & 0x000000FFL) << 24);
    }

    // --- Low-level binary input helpers ---

    private byte[] readExactly(int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int read = file.read(buf, off, n - off);
            if (read == -1) return null; // EOF, mirrors file_.good() == false
            off += read;
            bytesRead += read;
        }
        return buf;
    }

    private static long readU32LE(byte[] b, int offset) {
        return (b[offset] & 0xFFL) |
               ((b[offset + 1] & 0xFFL) << 8) |
               ((b[offset + 2] & 0xFFL) << 16) |
               ((b[offset + 3] & 0xFFL) << 24);
    }

    private static long readU16LE(byte[] b, int offset) {
        return (b[offset] & 0xFFL) | ((b[offset + 1] & 0xFFL) << 8);
    }
}
