package com.packetanalyzer.dpi;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class SNIExtractor {

    private SNIExtractor() {}

    // TLS Constants
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long readUint24BE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 16) |
               ((data[offset + 1] & 0xFF) << 8) |
               (data[offset + 2] & 0xFF);
    }

    public static boolean isTLSClientHello(byte[] payload, int length) {
        // Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if (length < 9) return false;

        // Byte 0: Content Type (should be 0x16 = Handshake)
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // Bytes 1-2: TLS Version (accept 0x0300 through 0x0304)
        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Bytes 3-4: Record length
        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;

        // Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if ((payload[5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) {
            return Optional.empty();
        }

        // Skip TLS record header (5 bytes)
        int offset = 5;

        // Skip handshake header (type already checked; bytes 1-3 are length)
        offset += 4;

        // Client version (2 bytes)
        offset += 2;

        // Random (32 bytes)
        offset += 32;

        // Session ID
        if (offset >= length) return Optional.empty();
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        // Cipher suites
        if (offset + 2 > length) return Optional.empty();
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;

        // Compression methods
        if (offset >= length) return Optional.empty();
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        // Extensions
        if (offset + 2 > length) return Optional.empty();
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; // Truncated, but try to parse anyway
        }

        // Parse extensions to find SNI
        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;

                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;

                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                String sni = new String(payload, offset + 5, sniLength, java.nio.charset.StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }

            offset += extensionLength;
        }

        return Optional.empty();
    }

    public static List<Map.Entry<Integer, String>> extractExtensions(byte[] payload, int length) {
        List<Map.Entry<Integer, String>> extensions = new ArrayList<>();
        return extensions;
    }
}