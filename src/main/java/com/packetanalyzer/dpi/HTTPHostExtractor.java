package com.packetanalyzer.dpi;

import java.util.Optional;

public final class HTTPHostExtractor {

    private HTTPHostExtractor() {}

    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;

        for (String method : METHODS) {
            boolean match = true;
            for (int i = 0; i < 4; i++) {
                if (payload[i] != (byte) method.charAt(i)) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }

        return false;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isHTTPRequest(payload, length)) {
            return Optional.empty();
        }

        final int hostHeaderLen = 6; // "Host: "

        for (int i = 0; i + hostHeaderLen < length; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                payload[i + 4] == ':') {

                // Skip "Host:" and any whitespace
                int start = i + 5;
                while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line
                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start, java.nio.charset.StandardCharsets.US_ASCII);

                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }

                    return Optional.of(host);
                }
            }
        }

        return Optional.empty();
    }
}