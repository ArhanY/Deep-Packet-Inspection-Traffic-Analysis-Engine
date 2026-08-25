# Packet Analyzer

A Java-based PCAP analyzer and deep packet inspection (DPI) engine. It reads Ethernet/IPv4/TCP/UDP packets from a PCAP capture, identifies application-layer metadata such as HTTP hosts, DNS names, TLS SNI, and QUIC SNI, and can write a filtered capture based on blocking rules.

## Features

- Parses classic Ethernet PCAP files and common IPv4, TCP, and UDP headers.
- Extracts HTTP hostnames, DNS queries, TLS SNI, and QUIC SNI where available.
- Supports blocking by source IP, application, and domain pattern.
- Includes single-threaded and multi-threaded DPI entry points.
- Provides JUnit tests for PCAP reading, packet parsing, and five-tuple hashing.

## Requirements

- Java 8 or later
- Maven 3.6 or later

## Build and test

```bash
mvn clean test
mvn package
```

The packaged JAR starts the packet-summary CLI:

```bash
java -jar target/packet-analyzer.jar test_dpi.pcap 10
```

Regenerate the sample capture used by the tests and examples:

```bash
java -cp target/classes com.packetanalyzer.GenerateTestPcap test_dpi.pcap
```

## Run the DPI engine

Build the project first, then run one of the following entry points.

```bash
# Single-threaded DPI engine
java -cp target/classes com.packetanalyzer.MainDpi input.pcap filtered.pcap \
  --block-app YouTube --block-domain "*.example.com"

# Multi-threaded DPI engine
java -cp target/classes com.packetanalyzer.DpiMt input.pcap filtered.pcap \
  --lbs 4 --fps 4
```

Run an entry point without arguments to see its complete command-line help.

## Project layout

```text
src/
├── main/java/com/packetanalyzer/
│   ├── analyzer/   PCAP reading and packet parsing
│   ├── dpi/        Classification, rules, flow tracking, and processing
│   ├── net/        Network byte-order helpers
│   └── Main*.java  Command-line entry points
└── test/java/com/packetanalyzer/
    └── *Test.java  JUnit tests
```

`test_dpi.pcap` is a small committed test fixture. Output captures (`*.pcap`) and Maven build artifacts are ignored by Git.

## Entry points

| Class | Purpose |
| --- | --- |
| `Main` | Prints a readable packet-by-packet summary. |
| `MainDpi` | Runs the configurable DPI engine. |
| `DpiMt` | Runs the multi-threaded DPI engine. |
| `MainSimple` | Minimal parser and DPI test harness. |
| `MainWorking` | Simplified single-threaded DPI example. |
| `GenerateTestPcap` | Generates a PCAP fixture with TLS, HTTP, DNS, and blocked-IP traffic. |

## Notes

This project processes offline PCAP files; it does not capture live network traffic. Only inspect packet captures you are authorized to access.
