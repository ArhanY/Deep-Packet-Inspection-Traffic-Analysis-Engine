package com.packetanalyzer.dpi;

import java.util.Arrays;
import java.util.Optional;

public final class QUICSNIExtractor {

    private QUICSNIExtractor() {}

    public static boolean isQUICInitial(byte[] payload, int length) {
        if (length < 5) return false;

        int firstByte = payload[0] & 0xFF;

        // Long header form
        if ((firstByte & 0x80) == 0) return false;

        // Version check omitted, matching the lenient original implementation
        return true;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isQUICInitial(payload, length)) {
            return Optional.empty();
        }

        // Search for TLS Client Hello pattern within the QUIC packet
        for (int i = 0; i + 50 < length; i++) {
            if ((payload[i] & 0xFF) == 0x01) { // Client Hello handshake type
                int subOffset = i - 5;
                int subLength = length - i + 5;
                if (subOffset >= 0 && subOffset + subLength <= payload.length && subLength > 0) {
                    byte[] sub = Arrays.copyOfRange(payload, subOffset, subOffset + subLength);
                    Optional<String> result = SNIExtractor.extract(sub, subLength);
                    if (result.isPresent()) return result;
                }
            }
        }

        return Optional.empty();
    }
}