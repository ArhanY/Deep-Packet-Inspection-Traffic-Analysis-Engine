package com.packetanalyzer;

import com.packetanalyzer.analyzer.PacketParser;
import com.packetanalyzer.analyzer.ParsedPacket;
import com.packetanalyzer.analyzer.PcapGlobalHeader;
import com.packetanalyzer.analyzer.PcapPacketHeader;
import com.packetanalyzer.analyzer.PcapReader;
import com.packetanalyzer.analyzer.RawPacket;
import com.packetanalyzer.dpi.AppType;
import com.packetanalyzer.dpi.DpiTypes;
import com.packetanalyzer.dpi.FiveTuple;
import com.packetanalyzer.dpi.HTTPHostExtractor;
import com.packetanalyzer.dpi.SNIExtractor;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class MainWorking {

    static class Flow {
        FiveTuple tuple;
        AppType app_type = AppType.UNKNOWN;
        String sni = "";
        long packets = 0;
        long bytes = 0;
        boolean blocked = false;
    }

    static class BlockingRules {
        final Set<Long> blocked_ips = new HashSet<>();
        final Set<AppType> blocked_apps = new HashSet<>();
        final List<String> blocked_domains = new ArrayList<>(); // Simple substring match

        void blockIP(String ip) {
            long addr = parseIP(ip);
            blocked_ips.add(addr);
            System.out.println("[Rules] Blocked IP: " + ip);
        }

        void blockApp(String app) {
            for (int i = 0; i < AppType.APP_COUNT.ordinal(); i++) {
                AppType type = AppType.values()[i];
                if (DpiTypes.appTypeToString(type).equals(app)) {
                    blocked_apps.add(type);
                    System.out.println("[Rules] Blocked app: " + app);
                    return;
                }
            }
            System.err.println("[Rules] Unknown app: " + app);
        }

        void blockDomain(String domain) {
            blocked_domains.add(domain);
            System.out.println("[Rules] Blocked domain: " + domain);
        }

        boolean isBlocked(long src_ip, AppType app, String sni) {
            if (blocked_ips.contains(src_ip)) return true;
            if (blocked_apps.contains(app)) return true;
            for (String dom : blocked_domains) {
                if (sni.contains(dom)) return true;
            }
            return false;
        }

        static long parseIP(String ip) {
            long result = 0;
            int octet = 0, shift = 0;
            for (int i = 0; i < ip.length(); i++) {
                char c = ip.charAt(i);
                if (c == '.') {
                    result |= ((long) octet << shift);
                    shift += 8;
                    octet = 0;
                } else if (c >= '0' && c <= '9') {
                    octet = octet * 10 + (c - '0');
                }
            }
            result |= ((long) octet << shift);
            return result & 0xFFFFFFFFL;
        }
    }

    static void printUsage(String prog) {
        System.out.println("\nDPI Engine - Deep Packet Inspection System\n" +
                "==========================================\n\n" +
                "Usage: " + prog + " <input.pcap> <output.pcap> [options]\n\n" +
                "Options:\n" +
                "  --block-ip <ip>        Block traffic from source IP\n" +
                "  --block-app <app>      Block application (YouTube, Facebook, etc.)\n" +
                "  --block-domain <dom>   Block domain (substring match)\n\n" +
                "Example:\n" +
                "  " + prog + " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50\n");
    }

    // Mirrors the local parseIP lambda used inside main()
    private static long parseIP(String ip) {
        return BlockingRules.parseIP(ip);
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            printUsage("MainWorking");
            System.exit(1);
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];

        BlockingRules rules = new BlockingRules();

        // Parse options
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                rules.blockIP(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            }
        }

        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0                            \u2551");
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");

        // Open input
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.exit(1);
            return;
        }

        // Open output
        FileOutputStream output;
        try {
            output = new FileOutputStream(outputFile);
        } catch (IOException e) {
            System.err.println("Error: Cannot open output file");
            System.exit(1);
            return;
        }

        // Write PCAP header
        PcapGlobalHeader header = reader.getGlobalHeader();
        writeGlobalHeader(output, header);

        // Flow table
        Map<FiveTuple, Flow> flows = new HashMap<>();

        // Statistics
        long totalPackets = 0;
        long forwarded = 0;
        long dropped = 0;
        Map<AppType, Long> appStats = new HashMap<>();

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();

        System.out.println("[DPI] Processing packets...");

        while (reader.readNextPacket(raw)) {
            totalPackets++;

            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

            // Create five-tuple
            FiveTuple tuple = new FiveTuple();
            tuple.src_ip = parseIP(parsed.src_ip);
            tuple.dst_ip = parseIP(parsed.dest_ip);
            tuple.src_port = parsed.src_port;
            tuple.dst_port = parsed.dest_port;
            tuple.protocol = parsed.protocol;

            // Get or create flow
            Flow flow = flows.computeIfAbsent(tuple, t -> new Flow());
            if (flow.packets == 0) {
                flow.tuple = tuple;
            }
            flow.packets++;
            flow.bytes += raw.data.length;

            // Try SNI extraction - even for flows already marked as generic HTTPS
            if ((flow.app_type == AppType.UNKNOWN || flow.app_type == AppType.HTTPS) &&
                flow.sni.isEmpty() && parsed.has_tcp && parsed.dest_port == 443) {

                int payloadOffset = 14;
                int ipIhl = raw.data[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                if (payloadOffset + 12 < raw.data.length) {
                    int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                    payloadOffset += tcpOffset * 4;

                    if (payloadOffset < raw.data.length) {
                        int payloadLen = raw.data.length - payloadOffset;
                        if (payloadLen > 5) { // Minimum TLS record header
                            byte[] payload = new byte[payloadLen];
                            System.arraycopy(raw.data, payloadOffset, payload, 0, payloadLen);

                            Optional<String> sni = SNIExtractor.extract(payload, payloadLen);
                            if (sni.isPresent()) {
                                flow.sni = sni.get();
                                flow.app_type = DpiTypes.sniToAppType(sni.get());
                            }
                        }
                    }
                }
            }

            // HTTP Host extraction
            if ((flow.app_type == AppType.UNKNOWN || flow.app_type == AppType.HTTP) &&
                flow.sni.isEmpty() && parsed.has_tcp && parsed.dest_port == 80) {

                int payloadOffset = 14;
                int ipIhl = raw.data[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                if (payloadOffset + 12 < raw.data.length) {
                    int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                    payloadOffset += tcpOffset * 4;

                    if (payloadOffset < raw.data.length) {
                        int payloadLen = raw.data.length - payloadOffset;
                        byte[] payload = new byte[payloadLen];
                        System.arraycopy(raw.data, payloadOffset, payload, 0, payloadLen);

                        Optional<String> host = HTTPHostExtractor.extract(payload, payloadLen);
                        if (host.isPresent()) {
                            flow.sni = host.get();
                            flow.app_type = DpiTypes.sniToAppType(host.get());
                        }
                    }
                }
            }

            // DNS classification
            if (flow.app_type == AppType.UNKNOWN &&
                (parsed.dest_port == 53 || parsed.src_port == 53)) {
                flow.app_type = AppType.DNS;
            }

            // Port-based fallback
            if (flow.app_type == AppType.UNKNOWN) {
                if (parsed.dest_port == 443) flow.app_type = AppType.HTTPS;
                else if (parsed.dest_port == 80) flow.app_type = AppType.HTTP;
            }

            // Check blocking rules
            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
                if (flow.blocked) {
                    StringBuilder line = new StringBuilder();
                    line.append("[BLOCKED] ").append(parsed.src_ip).append(" -> ").append(parsed.dest_ip)
                        .append(" (").append(DpiTypes.appTypeToString(flow.app_type));
                    if (!flow.sni.isEmpty()) line.append(": ").append(flow.sni);
                    line.append(")");
                    System.out.println(line.toString());
                }
            }

            // Update app stats
            appStats.merge(flow.app_type, 1L, Long::sum);

            // Forward or drop
            if (flow.blocked) {
                dropped++;
            } else {
                forwarded++;
                // Write to output
                writePacket(output, raw);
            }
        }

        reader.close();
        output.close();

        // Print report
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                      PROCESSING REPORT                       \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551 Total Packets:      " + String.format("%10d", totalPackets) + "                             \u2551");
        System.out.println("\u2551 Forwarded:          " + String.format("%10d", forwarded) + "                             \u2551");
        System.out.println("\u2551 Dropped:            " + String.format("%10d", dropped) + "                             \u2551");
        System.out.println("\u2551 Active Flows:       " + String.format("%10d", flows.size()) + "                             \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551                    APPLICATION BREAKDOWN                     \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");

        // Sort by count
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = 100.0 * entry.getValue() / totalPackets;
            int barLen = (int) (pct / 5);
            StringBuilder bar = new StringBuilder();
            for (int i = 0; i < barLen; i++) bar.append('#');

            System.out.println("\u2551 " +
                    String.format("%-15s", DpiTypes.appTypeToString(entry.getKey())) +
                    String.format("%8d", entry.getValue()) +
                    " " + String.format("%5.1f", pct) + "% " +
                    String.format("%-20s", bar.toString()) + "  \u2551");
        }

        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");

        // List unique SNIs
        System.out.println("\n[Detected Applications/Domains]");
        Map<String, AppType> uniqueSnis = new HashMap<>();
        for (Flow flow : flows.values()) {
            if (!flow.sni.isEmpty()) {
                uniqueSnis.put(flow.sni, flow.app_type);
            }
        }
        for (Map.Entry<String, AppType> entry : uniqueSnis.entrySet()) {
            System.out.println("  - " + entry.getKey() + " -> " + DpiTypes.appTypeToString(entry.getValue()));
        }

        System.out.println("\nOutput written to: " + outputFile);
    }

    private static void writeGlobalHeader(FileOutputStream out, PcapGlobalHeader header) throws IOException {
        byte[] buf = new byte[24];
        writeU32LE(buf, 0, header.magic_number);
        writeU16LE(buf, 4, header.version_major);
        writeU16LE(buf, 6, header.version_minor);
        writeU32LE(buf, 8, header.thiszone);
        writeU32LE(buf, 12, header.sigfigs);
        writeU32LE(buf, 16, header.snaplen);
        writeU32LE(buf, 20, header.network);
        out.write(buf);
    }

    private static void writePacket(FileOutputStream out, RawPacket raw) throws IOException {
        byte[] header = new byte[16];
        writeU32LE(header, 0, raw.header.ts_sec);
        writeU32LE(header, 4, raw.header.ts_usec);
        writeU32LE(header, 8, raw.data.length);
        writeU32LE(header, 12, raw.data.length);
        out.write(header);
        out.write(raw.data);
    }

    private static void writeU32LE(byte[] buf, int offset, long value) {
        buf[offset] = (byte) (value & 0xFF);
        buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
        buf[offset + 2] = (byte) ((value >> 16) & 0xFF);
        buf[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static void writeU16LE(byte[] buf, int offset, int value) {
        buf[offset] = (byte) (value & 0xFF);
        buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
    }
}