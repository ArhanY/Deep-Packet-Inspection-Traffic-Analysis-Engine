package com.packetanalyzer.dpi;

import java.util.Optional;

public final class DNSExtractor {

    private DNSExtractor() {}

    public static boolean isDNSQuery(byte[] payload, int length) {
        // Minimum DNS header is 12 bytes
        if (length < 12) return false;

        // Check QR bit (byte 2, bit 7) - should be 0 for query
        int flags = payload[2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // This is a response, not a query

        // Check QDCOUNT (bytes 4-5) - should be > 0
        int qdcount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        if (qdcount == 0) return false;

        return true;
    }

    public static Optional<String> extractQuery(byte[] payload, int length) {
        if (!isDNSQuery(payload, length)) {
            return Optional.empty();
        }

        // DNS query starts at byte 12
        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLength = payload[offset] & 0xFF;

            if (labelLength == 0) {
                // End of domain name
                break;
            }

            if (labelLength > 63) {
                // Compression pointer or invalid
                break;
            }

            offset++;
            if (offset + labelLength > length) break;

            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength, java.nio.charset.StandardCharsets.US_ASCII));
            offset += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}