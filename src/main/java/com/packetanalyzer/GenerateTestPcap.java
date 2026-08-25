package com.packetanalyzer;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/** Generates the sample PCAP used to exercise the DPI engine. */
public final class GenerateTestPcap {
    private static final Random RANDOM = new Random();
    private static long timestamp = 1_700_000_000L;

    private GenerateTestPcap() {
    }

    public static void main(String[] args) throws IOException {
        String output = args.length > 0 ? args[0] : "test_dpi.pcap";
        try (FileOutputStream file = new FileOutputStream(output)) {
            writeGlobalHeader(file);
            generateTraffic(file);
        }
        System.out.println("Created " + output + " with test traffic");
        System.out.println("  - 16 TLS connections with SNI");
        System.out.println("  - 2 HTTP connections");
        System.out.println("  - 4 DNS queries");
        System.out.println("  - 5 packets from blocked IP 192.168.1.50");
    }

    private static void generateTraffic(FileOutputStream file) throws IOException {
        String[][] tlsConnections = {
                {"142.250.185.206", "www.google.com"}, {"142.250.185.110", "www.youtube.com"},
                {"157.240.1.35", "www.facebook.com"}, {"157.240.1.174", "www.instagram.com"},
                {"104.244.42.65", "twitter.com"}, {"52.94.236.248", "www.amazon.com"},
                {"23.52.167.61", "www.netflix.com"}, {"140.82.114.4", "github.com"},
                {"104.16.85.20", "discord.com"}, {"35.186.224.25", "zoom.us"},
                {"35.186.227.140", "web.telegram.org"}, {"99.86.0.100", "www.tiktok.com"},
                {"35.186.224.47", "open.spotify.com"}, {"192.0.78.24", "www.cloudflare.com"},
                {"13.107.42.14", "www.microsoft.com"}, {"17.253.144.10", "www.apple.com"}
        };
        long sequence = 1_000;
        for (String[] connection : tlsConnections) {
            int sourcePort = randomPort();
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", connection[0], 6, tcp(sourcePort, 443, sequence, 0, 0x02)));
            writePacket(file, ethernet("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"),
                    ipv4(connection[0], "192.168.1.100", 6, tcp(443, sourcePort, sequence + 1_000, sequence + 1, 0x12)));
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", connection[0], 6, tcp(sourcePort, 443, sequence + 1, sequence + 1_001, 0x10)));
            byte[] tls = tlsClientHello(connection[1]);
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", connection[0], 6, join(tcp(sourcePort, 443, sequence + 1, sequence + 1_001, 0x18), tls)));
            sequence += 10_000;
        }

        String[][] httpConnections = {{"93.184.216.34", "example.com"}, {"185.199.108.153", "httpbin.org"}};
        for (String[] connection : httpConnections) {
            int sourcePort = randomPort();
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", connection[0], 6, tcp(sourcePort, 80, sequence, 0, 0x02)));
            byte[] request = ("GET / HTTP/1.1\r\nHost: " + connection[1] + "\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", connection[0], 6, join(tcp(sourcePort, 80, sequence + 1, 1, 0x18), request)));
            sequence += 10_000;
        }

        for (String domain : new String[]{"www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com"}) {
            int sourcePort = randomPort();
            byte[] dns = dnsQuery(domain);
            writePacket(file, ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.100", "8.8.8.8", 17, join(udp(sourcePort, 53, dns.length), dns)));
        }

        for (int i = 0; i < 5; i++) {
            writePacket(file, ethernet("00:11:22:33:44:56", "aa:bb:cc:dd:ee:ff"),
                    ipv4("192.168.1.50", "172.217.0.100", 6, tcp(randomPort(), 443, sequence, 0, 0x02)));
            sequence += 1_000;
        }
    }

    private static void writeGlobalHeader(FileOutputStream file) throws IOException {
        writeLe32(file, 0xa1b2c3d4L); writeLe16(file, 2); writeLe16(file, 4);
        writeLe32(file, 0); writeLe32(file, 0); writeLe32(file, 65535); writeLe32(file, 1);
    }

    private static void writePacket(FileOutputStream file, byte[] ethernet, byte[] ipPacket) throws IOException {
        byte[] packet = join(ethernet, ipPacket);
        writeLe32(file, timestamp++); writeLe32(file, RANDOM.nextInt(1_000_000));
        writeLe32(file, packet.length); writeLe32(file, packet.length); file.write(packet);
    }

    private static byte[] ethernet(String source, String destination) {
        return join(mac(destination), mac(source), new byte[]{0x08, 0x00});
    }

    private static byte[] ipv4(String source, String destination, int protocol, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x45); out.write(0); writeBe16(out, 20 + payload.length); writeBe16(out, RANDOM.nextInt(65535) + 1);
        writeBe16(out, 0x4000); out.write(64); out.write(protocol); writeBe16(out, 0); writeIp(out, source); writeIp(out, destination);
        return join(out.toByteArray(), payload);
    }

    private static byte[] tcp(int sourcePort, int destinationPort, long sequence, long acknowledgement, int flags) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBe16(out, sourcePort); writeBe16(out, destinationPort); writeBe32(out, sequence); writeBe32(out, acknowledgement);
        out.write(0x50); out.write(flags); writeBe16(out, 65535); writeBe16(out, 0); writeBe16(out, 0);
        return out.toByteArray();
    }

    private static byte[] udp(int sourcePort, int destinationPort, int payloadLength) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBe16(out, sourcePort); writeBe16(out, destinationPort); writeBe16(out, 8 + payloadLength); writeBe16(out, 0);
        return out.toByteArray();
    }

    private static byte[] tlsClientHello(String hostname) {
        byte[] host = hostname.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeBe16(extensions, 0); writeBe16(extensions, host.length + 5); writeBe16(extensions, host.length + 3); extensions.write(0); writeBe16(extensions, host.length); extensions.write(host, 0, host.length);
        writeBe16(extensions, 0x002b); writeBe16(extensions, 3); extensions.write(2); writeBe16(extensions, 0x0304);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeBe16(body, 0x0303); byte[] random = new byte[32]; RANDOM.nextBytes(random); body.write(random, 0, random.length); body.write(0);
        writeBe16(body, 4); writeBe16(body, 0x1301); writeBe16(body, 0x1302); body.write(1); body.write(0); writeBe16(body, extensions.size()); body.write(extensions.toByteArray(), 0, extensions.size());
        ByteArrayOutputStream handshake = new ByteArrayOutputStream(); handshake.write(1); writeBe24(handshake, body.size()); handshake.write(body.toByteArray(), 0, body.size());
        ByteArrayOutputStream record = new ByteArrayOutputStream(); record.write(0x16); writeBe16(record, 0x0301); writeBe16(record, handshake.size()); record.write(handshake.toByteArray(), 0, handshake.size());
        return record.toByteArray();
    }

    private static byte[] dnsQuery(String domain) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBe16(out, RANDOM.nextInt(65535) + 1); writeBe16(out, 0x0100); writeBe16(out, 1); writeBe16(out, 0); writeBe16(out, 0); writeBe16(out, 0);
        for (String label : domain.split("\\.")) { byte[] bytes = label.getBytes(StandardCharsets.US_ASCII); out.write(bytes.length); out.write(bytes, 0, bytes.length); }
        out.write(0); writeBe16(out, 1); writeBe16(out, 1); return out.toByteArray();
    }

    private static int randomPort() { return 49152 + RANDOM.nextInt(16384); }
    private static byte[] mac(String address) { String[] parts = address.split(":"); byte[] result = new byte[6]; for (int i = 0; i < 6; i++) result[i] = (byte) Integer.parseInt(parts[i], 16); return result; }
    private static void writeIp(ByteArrayOutputStream out, String ip) { for (String part : ip.split("\\.")) out.write(Integer.parseInt(part)); }
    private static byte[] join(byte[]... parts) { ByteArrayOutputStream out = new ByteArrayOutputStream(); for (byte[] part : parts) out.write(part, 0, part.length); return out.toByteArray(); }
    private static void writeLe16(FileOutputStream out, int value) throws IOException { out.write(value); out.write(value >>> 8); }
    private static void writeLe32(FileOutputStream out, long value) throws IOException { out.write((int) value); out.write((int) (value >>> 8)); out.write((int) (value >>> 16)); out.write((int) (value >>> 24)); }
    private static void writeBe16(ByteArrayOutputStream out, int value) { out.write(value >>> 8); out.write(value); }
    private static void writeBe24(ByteArrayOutputStream out, int value) { out.write(value >>> 16); out.write(value >>> 8); out.write(value); }
    private static void writeBe32(ByteArrayOutputStream out, long value) { out.write((int) (value >>> 24)); out.write((int) (value >>> 16)); out.write((int) (value >>> 8)); out.write((int) value); }
}
