package com.packetanalyzer;

import com.packetanalyzer.dpi.DPIEngine;

public class MainDpi {

    static void printUsage(String program) {
        System.out.println("\n" +
            "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n" +
            "\u2551                    DPI ENGINE v1.0                            \u2551\n" +
            "\u2551               Deep Packet Inspection System                   \u2551\n" +
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n\n" +
            "Usage: " + program + " <input.pcap> <output.pcap> [options]\n\n" +
            "Arguments:\n" +
            "  input.pcap     Input PCAP file (captured user traffic)\n" +
            "  output.pcap    Output PCAP file (filtered traffic to internet)\n\n" +
            "Options:\n" +
            "  --block-ip <ip>        Block packets from source IP\n" +
            "  --block-app <app>      Block application (e.g., YouTube, Facebook)\n" +
            "  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)\n" +
            "  --rules <file>         Load blocking rules from file\n" +
            "  --lbs <n>              Number of load balancer threads (default: 2)\n" +
            "  --fps <n>              FP threads per LB (default: 2)\n" +
            "  --verbose              Enable verbose output\n\n" +
            "Examples:\n" +
            "  " + program + " capture.pcap filtered.pcap\n" +
            "  " + program + " capture.pcap filtered.pcap --block-app YouTube\n" +
            "  " + program + " capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com\n" +
            "  " + program + " capture.pcap filtered.pcap --rules blocking_rules.txt\n\n" +
            "Supported Apps for Blocking:\n" +
            "  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,\n" +
            "  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub\n\n" +
            "Architecture:\n" +
            "  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n" +
            "  \u2502 PCAP Reader \u2502  Reads packets from input file\n" +
            "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2518\n" +
            "         \u2502 hash(5-tuple) % num_lbs\n" +
            "         \u25bc\n" +
            "  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n" +
            "  \u2502 Load Balancer \u2502  2 LB threads distribute to FPs\n" +
            "  \u2502   LB0 \u2502 LB1   \u2502\n" +
            "  \u2514\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2518\n" +
            "     \u2502         \u2502  hash(5-tuple) % fps_per_lb\n" +
            "     \u25bc         \u25bc\n" +
            "  \u250c\u2500\u2500\u2534\u2500\u2500\u2510   \u250c\u2500\u2500\u2534\u2500\u2500\u2510\n" +
            "  \u2502FP0-1\u2502   \u2502FP2-3\u2502  4 FP threads: DPI, classification, blocking\n" +
            "  \u2514\u2500\u2500\u252c\u2500\u2500\u2518   \u2514\u2500\u2500\u252c\u2500\u2500\u2518\n" +
            "     \u2502         \u2502\n" +
            "     \u25bc         \u25bc\n" +
            "  \u250c\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2510\n" +
            "  \u2502 Output Writer \u2502  Writes forwarded packets to output\n" +
            "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("MainDpi");
            System.exit(1);
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];

        // Parse options
        DPIEngine.Config config = new DPIEngine.Config();
        config.num_load_balancers = 2;
        config.fps_per_lb = 2;

        java.util.List<String> blockIps = new java.util.ArrayList<>();
        java.util.List<String> blockApps = new java.util.ArrayList<>();
        java.util.List<String> blockDomains = new java.util.ArrayList<>();
        String rulesFile = "";

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--rules") && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.num_load_balancers = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.fps_per_lb = Integer.parseInt(args[++i]);
            } else if (arg.equals("--verbose")) {
                config.verbose = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                printUsage("MainDpi");
                return;
            }
        }

        // Create DPI engine
        DPIEngine engine = new DPIEngine(config);

        // Initialize
        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
            return;
        }

        // Load rules from file if specified
        if (!rulesFile.isEmpty()) {
            engine.loadRules(rulesFile);
        }

        // Apply command-line blocking rules
        for (String ip : blockIps) {
            engine.blockIP(ip);
        }

        for (String app : blockApps) {
            engine.blockApp(app);
        }

        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }

        // Process the file
        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            System.exit(1);
            return;
        }

        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }
}