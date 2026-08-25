# Deep Packet Inspection Traffic Analysis Engine

A Java-based **Deep Packet Inspection (DPI) and network traffic analysis engine** for analyzing offline PCAP captures, parsing network protocols, identifying application-level traffic, tracking connections, applying blocking rules, and generating filtered PCAP output.

The project implements a complete packet-processing pipeline from **raw Ethernet frames → IPv4 → TCP/UDP → application-layer metadata → traffic classification → rule evaluation → packet forwarding/dropping**.

It also includes a **multi-threaded processing architecture** with load balancers, fast-path processors, connection tracking, thread-safe queues, and synchronized statistics.

---

## Overview

Network packet captures contain large amounts of low-level information that is difficult to interpret directly. This project provides a Java implementation of a packet analysis and DPI pipeline that converts raw PCAP data into useful protocol and application-level information.

The analyzer can:

* Read packets from classic PCAP files
* Parse Ethernet, IPv4, TCP, and UDP headers
* Identify transport-layer protocols and ports
* Extract DNS queries
* Extract HTTP host information
* Extract TLS Server Name Indication (SNI)
* Extract QUIC SNI information where available
* Classify traffic into application categories
* Track network connections using five-tuples
* Apply configurable blocking rules
* Block traffic based on IP, port, application, or domain
* Process packets using multiple worker threads
* Maintain packet, byte, protocol, application, and connection statistics
* Write permitted traffic into a filtered PCAP file

The project is designed as an **offline packet-processing system** and does not perform live network packet capture.

---

## Key Features

### PCAP Processing

* Reads classic PCAP capture files
* Parses PCAP global and packet headers
* Handles packet timestamps and captured packet lengths
* Processes raw packet data sequentially
* Supports generation of test PCAP files for development and testing

### Network Protocol Parsing

The packet parser understands several layers of the networking stack:

```text
Ethernet
   │
   └── IPv4
        │
        ├── TCP
        │
        └── UDP
```

The parser extracts information such as:

* Source and destination MAC addresses
* Source and destination IPv4 addresses
* Protocol type
* TCP/UDP source ports
* TCP/UDP destination ports
* Packet length
* TCP flags
* Payload data

---

## Deep Packet Inspection

The DPI layer performs application-aware inspection of packet payloads and metadata.

### Supported metadata extraction

| Protocol / Metadata | Detection |
| ------------------- | --------- |
| HTTP Host           | Yes       |
| DNS Query           | Yes       |
| TLS SNI             | Yes       |
| QUIC SNI            | Yes       |
| TCP                 | Yes       |
| UDP                 | Yes       |
| IPv4                | Yes       |
| Ethernet            | Yes       |

This allows the engine to move beyond simple IP/port filtering and perform higher-level traffic classification.

---

## Application Classification

The engine maps detected domains/SNI information to application categories.

Supported application classifications include:

* Google
* YouTube
* Facebook
* Instagram
* WhatsApp
* Twitter/X
* Netflix
* Amazon
* Microsoft
* Apple
* Telegram
* TikTok
* Spotify
* Zoom
* Discord
* GitHub
* Cloudflare
* HTTP
* HTTPS
* DNS
* TLS
* QUIC
* Unknown

Application detection is performed through domain/SNI-based classification.

---

## Traffic Filtering and Blocking

The project provides a rule-management system that can evaluate packets against multiple blocking criteria.

### Supported blocking rules

#### IP-based blocking

Block traffic originating from a specific IPv4 address.

```text
Block IP → 192.168.1.10
```

#### Port-based blocking

Block traffic destined for a specific port.

```text
Block Port → 443
```

#### Application-based blocking

Block traffic classified as a specific application.

```text
Block Application → YouTube
```

#### Domain-based blocking

Block traffic associated with a specific domain.

```text
Block Domain → example.com
```

Wildcard domain patterns are also supported:

```text
*.example.com
```

The rule manager evaluates IP, port, application, and domain rules and records the reason for a packet being blocked.

---

## Connection Tracking

Network flows are represented using a **five-tuple**:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.5
      ↓
142.250.183.14
      ↓
TCP
      ↓
Source Port: 52341
Destination Port: 443
```

The connection tracker maintains state for active flows and can:

* Create new connections
* Find existing connections
* Match reverse-direction traffic
* Track packets and bytes
* Track inbound/outbound traffic
* Classify connections
* Mark blocked connections
* Close connections
* Remove stale connections
* Evict old connections when the connection table reaches its configured capacity

This provides flow-level state instead of treating every packet as an isolated event.

---

## Multi-Threaded DPI Architecture

A major component of the project is its multi-threaded packet-processing architecture.

The system separates packet distribution and packet processing into different components.

```text
                    PCAP INPUT
                        │
                        ▼
                ┌───────────────┐
                │ Packet Reader │
                └───────┬───────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Load Balancer(s)  │
              └─────────┬─────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        ┌───────────┐       ┌───────────┐
        │ Fast Path │       │ Fast Path │
        │ Processor │       │ Processor │
        └─────┬─────┘       └─────┬─────┘
              │                   │
              └─────────┬─────────┘
                        ▼
                ┌───────────────┐
                │ Output Queue  │
                └───────┬───────┘
                        │
                        ▼
                 Filtered PCAP
```

### Multi-threaded components

The implementation includes:

* Load balancers
* Fast-path processors
* Worker threads
* Thread-safe queues
* Connection trackers
* Global connection table
* Packet jobs
* Output callbacks
* Atomic statistics
* Synchronization using Java concurrency primitives

The architecture allows packet processing to be distributed across multiple processing threads.

---

## Thread Safety

The multi-threaded DPI engine uses Java concurrency mechanisms to safely coordinate packet processing.

Examples include:

* `AtomicLong`
* `AtomicBoolean`
* `AtomicInteger`
* `ReentrantLock`
* `ReentrantReadWriteLock`
* `synchronized` methods
* Thread-safe queues

This is particularly important for:

* Packet counters
* Byte counters
* Connection tables
* Rule management
* Application statistics
* Packet queues
* Worker-thread coordination

---

## Processing Pipeline

The overall processing flow can be summarized as:

```text
PCAP File
   │
   ▼
PCAP Reader
   │
   ▼
Raw Packet
   │
   ▼
Ethernet Parser
   │
   ▼
IPv4 Parser
   │
   ├───────────────┐
   ▼               ▼
TCP Parser       UDP Parser
   │               │
   └───────┬───────┘
           ▼
     Payload Analysis
           │
     ┌─────┼───────────────┐
     ▼     ▼       ▼       ▼
    HTTP  DNS      TLS    QUIC
     │     │       │       │
     └─────┴───────┴───────┘
           │
           ▼
    Application Detection
           │
           ▼
    Connection Tracking
           │
           ▼
      Rule Evaluation
           │
      ┌────┴────┐
      ▼         ▼
   FORWARD     DROP
      │
      ▼
Filtered PCAP
```

---

## Statistics and Monitoring

The DPI engine maintains statistics during processing.

Examples include:

* Total packets processed
* Total bytes processed
* Forwarded packets
* Dropped packets
* TCP packet count
* UDP packet count
* Application-level packet counts
* Detected SNI values
* Active connections
* Total connections observed
* Classified connections
* Blocked connections

These statistics make it possible to understand traffic composition and the behavior of the DPI engine.

---

## Rule Persistence

The `RuleManager` also supports saving and loading filtering rules from a file.

Rules can represent:

```text
[BLOCKED_IPS]

[BLOCKED_APPS]

[BLOCKED_DOMAINS]

[BLOCKED_PORTS]
```

This makes the filtering configuration reusable across multiple analysis runs.

---

## Project Structure

```text
PacketAnalyzerJava/
│
├── pom.xml
├── README.md
├── .gitignore
├── test_dpi.pcap
│
└── src/
    │
    ├── main/
    │   └── java/
    │       └── com/
    │           └── packetanalyzer/
    │
    │               ├── Main.java
    │               ├── MainDpi.java
    │               ├── MainSimple.java
    │               ├── MainWorking.java
    │               ├── DpiMt.java
    │               ├── GenerateTestPcap.java
    │               │
    │               ├── analyzer/
    │               │   ├── EthernetHeader.java
    │               │   ├── IPv4Header.java
    │               │   ├── TCPHeader.java
    │               │   ├── UDPHeader.java
    │               │   ├── PacketParser.java
    │               │   ├── PcapReader.java
    │               │   ├── ParsedPacket.java
    │               │   └── ...
    │               │
    │               ├── dpi/
    │               │   ├── DPIEngine.java
    │               │   ├── RuleManager.java
    │               │   ├── ConnectionTracker.java
    │               │   ├── GlobalConnectionTable.java
    │               │   ├── FPManager.java
    │               │   ├── LBManager.java
    │               │   ├── LoadBalancer.java
    │               │   ├── FastPathProcessor.java
    │               │   ├── ThreadSafeQueue.java
    │               │   ├── FiveTuple.java
    │               │   ├── FiveTupleUtil.java
    │               │   ├── HTTPHostExtractor.java
    │               │   ├── DNSExtractor.java
    │               │   ├── SNIExtractor.java
    │               │   ├── QUICSNIExtractor.java
    │               │   ├── DPIStats.java
    │               │   └── ...
    │               │
    │               └── net/
    │                   └── PortableNet.java
    │
    └── test/
        └── java/
            └── com/
                └── packetanalyzer/
                    ├── PcapReaderTest.java
                    ├── PacketParserTest.java
                    └── FiveTupleHashDistributionTest.java
```

---

## Important Classes

| Class                   | Responsibility                                    |
| ----------------------- | ------------------------------------------------- |
| `PcapReader`            | Reads packets from a PCAP file                    |
| `PacketParser`          | Parses raw packet bytes                           |
| `EthernetHeader`        | Represents Ethernet header information            |
| `IPv4Header`            | Parses IPv4 information                           |
| `TCPHeader`             | Parses TCP header information                     |
| `UDPHeader`             | Parses UDP header information                     |
| `DPIEngine`             | Coordinates the DPI processing pipeline           |
| `RuleManager`           | Manages IP, port, application, and domain rules   |
| `ConnectionTracker`     | Maintains per-flow connection state               |
| `GlobalConnectionTable` | Coordinates connection tracking across processors |
| `FiveTuple`             | Represents a network flow identifier              |
| `HTTPHostExtractor`     | Extracts HTTP host metadata                       |
| `DNSExtractor`          | Extracts DNS queries                              |
| `SNIExtractor`          | Extracts TLS SNI                                  |
| `QUICSNIExtractor`      | Handles QUIC SNI extraction                       |
| `FPManager`             | Manages fast-path processors                      |
| `LBManager`             | Manages load balancers                            |
| `LoadBalancer`          | Distributes packets to processing paths           |
| `FastPathProcessor`     | Processes packets through the DPI pipeline        |
| `ThreadSafeQueue`       | Provides synchronized packet-job communication    |
| `DPIStats`              | Maintains DPI processing statistics               |

---

## Technologies Used

### Programming Language

* **Java 8+**

### Build System

* **Apache Maven**

### Testing

* **JUnit 5**

### Core Concepts

* Object-Oriented Programming
* Network Protocol Parsing
* Deep Packet Inspection
* PCAP File Processing
* TCP/IP Networking
* Multithreading
* Concurrency
* Thread Synchronization
* Producer/Consumer Queues
* Connection Tracking
* Hash-Based Flow Distribution
* Rule-Based Packet Filtering

---

## Requirements

Before building the project, make sure the following are installed:

* Java 8 or later
* Maven 3.6 or later

Verify the installation:

```bash
java -version
mvn -version
```

---

## Build the Project

Clone the repository:

```bash
git clone <your-repository-url>
cd PacketAnalyzerJava
```

Build the project:

```bash
mvn clean package
```

Run the test suite:

```bash
mvn clean test
```

The packaged JAR will be generated at:

```text
target/packet-analyzer.jar
```

---

## Run Packet Analysis

The default JAR entry point runs the packet-summary CLI.

```bash
java -jar target/packet-analyzer.jar test_dpi.pcap 10
```

The command processes the PCAP and displays packet-level information.

---

## Generate a Test PCAP

The project includes a test PCAP generator.

After compiling:

```bash
java -cp target/classes com.packetanalyzer.GenerateTestPcap test_dpi.pcap
```

This creates a sample capture containing traffic useful for testing protocol parsing and DPI functionality.

---

## Run the Single-Threaded DPI Engine

Build the project first:

```bash
mvn clean package
```

Then run:

```bash
java -cp target/classes com.packetanalyzer.MainDpi \
    input.pcap \
    filtered.pcap \
    --block-app YouTube \
    --block-domain "*.example.com"
```

### What this does

The engine:

1. Reads packets from `input.pcap`
2. Parses the network headers
3. Performs DPI
4. Identifies application/domain information
5. Evaluates the configured blocking rules
6. Drops matching packets
7. Writes permitted packets to `filtered.pcap`

---

## Run the Multi-Threaded DPI Engine

The project also provides a multi-threaded DPI entry point:

```bash
java -cp target/classes com.packetanalyzer.DpiMt \
    input.pcap \
    filtered.pcap \
    --lbs 4 \
    --fps 4
```

Here:

```text
--lbs 4
```

configures 4 load balancers.

```text
--fps 4
```

configures 4 fast-path processors per load balancer.

This results in:

```text
4 × 4 = 16 Fast Path Threads
```

The architecture distributes packet processing across these processing paths.

---

## Command-Line Help

Run an entry point without arguments to view its available command-line options:

```bash
java -cp target/classes com.packetanalyzer.MainDpi
```

or:

```bash
java -cp target/classes com.packetanalyzer.DpiMt
```

---

## Testing

The project contains JUnit tests covering important components.

### PCAP Reader Tests

Validates PCAP file reading and packet extraction.

```text
PcapReaderTest
```

### Packet Parser Tests

Validates parsing of packet headers and protocol information.

```text
PacketParserTest
```

### Five-Tuple Distribution Tests

Tests the distribution behavior of five-tuple hashing used for flow assignment.

```text
FiveTupleHashDistributionTest
```

Run all tests:

```bash
mvn test
```

---

## Example Workflow

A typical analysis workflow looks like this:

```bash
# 1. Build
mvn clean package

# 2. Generate a test capture
java -cp target/classes com.packetanalyzer.GenerateTestPcap test_dpi.pcap

# 3. Analyze packets
java -jar target/packet-analyzer.jar test_dpi.pcap 10

# 4. Run DPI with filtering
java -cp target/classes com.packetanalyzer.MainDpi \
    test_dpi.pcap \
    filtered.pcap \
    --block-app YouTube

# 5. Run multi-threaded processing
java -cp target/classes com.packetanalyzer.DpiMt \
    test_dpi.pcap \
    filtered-mt.pcap \
    --lbs 4 \
    --fps 4
```

---

## Architecture

The project is divided into three major layers.

### 1. Analyzer Layer

Responsible for reading and parsing raw PCAP data.

```text
PCAP
 ↓
PcapReader
 ↓
PacketParser
 ↓
Ethernet / IPv4 / TCP / UDP
```

### 2. DPI Layer

Responsible for understanding application-level traffic.

```text
Parsed Packet
 ↓
HTTP / DNS / TLS / QUIC Extraction
 ↓
Application Classification
 ↓
Connection Tracking
```

### 3. Processing and Filtering Layer

Responsible for high-throughput processing and packet decisions.

```text
Packet
 ↓
Load Balancer
 ↓
Fast Path Processor
 ↓
Rule Manager
 ↓
FORWARD / DROP
 ↓
Output PCAP
```

---

## Design Highlights

### Five-Tuple Flow Identification

Each network connection can be represented by:

```text
(srcIP, dstIP, srcPort, dstPort, protocol)
```

The five-tuple is used for consistent flow identification and distribution.

### Fast-Path Processing

Packets are assigned to fast-path processors that maintain their own processing state and connection tracking.

### Load Balancing

Load balancers distribute packets across fast-path processors, allowing packet processing to scale across multiple worker threads.

### Global Connection Table

A global connection table provides access to connection-tracking information across processing paths.

### Thread-Safe Communication

Packet jobs move between processing stages using thread-safe queues, reducing unsafe shared-state access between worker threads.

### Rule Synchronization

The rule manager uses read/write locking to safely handle rule access while multiple processing threads are evaluating packets.

---

## Output

The analyzer can produce a filtered PCAP containing packets that were allowed by the configured rules.

Conceptually:

```text
Input PCAP
   │
   ├── Allowed Packet ───────► Output PCAP
   │
   └── Blocked Packet ───────► Dropped
```

This makes the project useful for experimenting with packet filtering and traffic-control pipelines.

---

## Limitations

This project currently focuses on **offline PCAP analysis**.

It does not:

* Capture packets directly from a network interface
* Act as a production firewall
* Provide a graphical user interface
* Decrypt encrypted HTTPS/TLS payloads
* Perform full application-layer protocol reconstruction for every protocol
* Replace production network monitoring or security tools

For encrypted protocols, classification relies primarily on available metadata such as TLS SNI, QUIC SNI, domains, ports, and other observable packet information.

---

## Security and Responsible Use

This project is intended for:

* Educational purposes
* Network programming practice
* Cybersecurity learning
* PCAP analysis
* Protocol parsing experiments
* DPI research and experimentation
* Controlled lab environments

Only analyze packet captures and network traffic that you are authorized to inspect.

---

## Future Improvements

Potential extensions include:

* Live network-interface packet capture
* IPv6 support
* Additional protocol parsers
* More advanced TLS/QUIC metadata extraction
* CIDR/subnet-based rules
* Configurable rule files from the command line
* Real-time traffic dashboards
* Performance benchmarking
* More detailed flow-level analytics
* Export to JSON/CSV
* Additional automated integration tests
* Improved packet-processing scalability

---

## Learning Outcomes

This project demonstrates practical experience with:

* Java network programming
* TCP/IP networking concepts
* Binary packet parsing
* PCAP file formats
* Deep Packet Inspection
* Application-layer protocol identification
* Multithreaded programming
* Java concurrency
* Producer-consumer architecture
* Thread synchronization
* Hash-based flow distribution
* Connection-state management
* Rule-based filtering
* Unit testing with JUnit
* Maven project management

---

## Project Status

The project is an actively developed Java-based PCAP analysis and DPI implementation designed to demonstrate packet parsing, traffic classification, rule-based filtering, connection tracking, and concurrent packet processing.

---

## License

If this repository is intended for public use, add the license that matches how you want others to use the project.

For example:

```text
MIT License
```

A license file should be added to the repository separately.

---

## Author

**Arhan Yezdani**

Java | Data Structures & Algorithms | Networking | Multithreading | Cybersecurity

---

## Quick Start

```bash
# Clone
git clone <your-repository-url>

# Enter project
cd PacketAnalyzerJava

# Build + test
mvn clean test

# Package
mvn package

# Analyze a PCAP
java -jar target/packet-analyzer.jar test_dpi.pcap 10

# Run single-threaded DPI
java -cp target/classes com.packetanalyzer.MainDpi \
    input.pcap filtered.pcap \
    --block-app YouTube

# Run multi-threaded DPI
java -cp target/classes com.packetanalyzer.DpiMt \
    input.pcap filtered.pcap \
    --lbs 4 --fps 4
```

---

**Deep Packet Inspection Traffic Analysis Engine — Java implementation for offline PCAP analysis, protocol parsing, traffic classification, connection tracking, packet filtering, and concurrent DPI processing.**
