package com.packetanalyzer.dpi;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {

    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public long blocked_ips;
        public long blocked_apps;
        public long blocked_domains;
        public long blocked_ports;
    }

    private final ReadWriteLock ipMutex = new ReentrantReadWriteLock();
    private final Set<Long> blockedIps = new HashSet<>();

    private final ReadWriteLock appMutex = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<>();

    private final ReadWriteLock domainMutex = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>(); // For wildcard matching

    private final ReadWriteLock portMutex = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    public RuleManager() {}

    private static long parseIP(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 0;

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

    // Helper: Convert packed value back to IP string
    private static String ipToString(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    // ========== IP Blocking ==========

    public void blockIP(long ip) {
        ipMutex.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
        } finally {
            ipMutex.writeLock().unlock();
        }
    }

    public void blockIP(String ip) {
        blockIP(parseIP(ip));
    }

    public void unblockIP(long ip) {
        ipMutex.writeLock().lock();
        try {
            blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
        } finally {
            ipMutex.writeLock().unlock();
        }
    }

    public void unblockIP(String ip) {
        unblockIP(parseIP(ip));
    }

    public boolean isIPBlocked(long ip) {
        ipMutex.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipMutex.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipMutex.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) {
                result.add(ipToString(ip));
            }
            return result;
        } finally {
            ipMutex.readLock().unlock();
        }
    }

    // ========== Application Blocking ==========

    public void blockApp(AppType app) {
        appMutex.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + DpiTypes.appTypeToString(app));
        } finally {
            appMutex.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        appMutex.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + DpiTypes.appTypeToString(app));
        } finally {
            appMutex.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appMutex.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appMutex.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appMutex.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appMutex.readLock().unlock();
        }
    }

    // ========== Domain Blocking ==========

    public void blockDomain(String domain) {
        domainMutex.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally {
            domainMutex.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainMutex.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally {
            domainMutex.writeLock().unlock();
        }
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        // Handle *.example.com pattern
        if (pattern.length() >= 2 && pattern.charAt(0) == '*' && pattern.charAt(1) == '.') {
            String suffix = pattern.substring(1); // .example.com

            // Check if domain ends with the pattern
            if (domain.length() >= suffix.length() &&
                domain.regionMatches(domain.length() - suffix.length(), suffix, 0, suffix.length())) {
                return true;
            }

            // Also match the bare domain (example.com matches *.example.com)
            if (domain.equals(pattern.substring(2))) {
                return true;
            }
        }

        return false;
    }

    public boolean isDomainBlocked(String domain) {
        domainMutex.readLock().lock();
        try {
            // Check exact match
            if (blockedDomains.contains(domain)) {
                return true;
            }

            String lowerDomain = domain.toLowerCase();

            for (String pattern : domainPatterns) {
                String lowerPattern = pattern.toLowerCase();
                if (domainMatchesPattern(lowerDomain, lowerPattern)) {
                    return true;
                }
            }

            return false;
        } finally {
            domainMutex.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainMutex.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainMutex.readLock().unlock();
        }
    }

    // ========== Port Blocking ==========

    public void blockPort(int port) {
        portMutex.writeLock().lock();
        try {
            blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        } finally {
            portMutex.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        portMutex.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            portMutex.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portMutex.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portMutex.readLock().unlock();
        }
    }

    // ========== Combined Check ==========

    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        // Check IP first (most specific)
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, ipToString(srcIp)));
        }

        // Check port
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, Integer.toString(dstPort)));
        }

        // Check app
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, DpiTypes.appTypeToString(app)));
        }

        // Check domain
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }

        return Optional.empty();
    }

    // ========== Rule Persistence ==========

    public boolean saveRules(String filename) {
        try (FileWriter file = new FileWriter(filename)) {
            // Save blocked IPs
            file.write("[BLOCKED_IPS]\n");
            for (String ip : getBlockedIPs()) {
                file.write(ip + "\n");
            }

            // Save blocked apps
            file.write("\n[BLOCKED_APPS]\n");
            for (AppType app : getBlockedApps()) {
                file.write(DpiTypes.appTypeToString(app) + "\n");
            }

            // Save blocked domains
            file.write("\n[BLOCKED_DOMAINS]\n");
            for (String domain : getBlockedDomains()) {
                file.write(domain + "\n");
            }

            // Save blocked ports
            file.write("\n[BLOCKED_PORTS]\n");
            portMutex.readLock().lock();
            try {
                for (int port : blockedPorts) {
                    file.write(port + "\n");
                }
            } finally {
                portMutex.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";

            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) continue;

                if (line.charAt(0) == '[') {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;
                    case "[BLOCKED_APPS]":
                        for (AppType app : AppType.values()) {
                            if (app == AppType.APP_COUNT) break;
                            if (DpiTypes.appTypeToString(app).equals(line)) {
                                blockApp(app);
                                break;
                            }
                        }
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        blockPort(Integer.parseInt(line.trim()));
                        break;
                    default:
                        break;
                }
            }

            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        ipMutex.writeLock().lock();
        try {
            blockedIps.clear();
        } finally {
            ipMutex.writeLock().unlock();
        }

        appMutex.writeLock().lock();
        try {
            blockedApps.clear();
        } finally {
            appMutex.writeLock().unlock();
        }

        domainMutex.writeLock().lock();
        try {
            blockedDomains.clear();
            domainPatterns.clear();
        } finally {
            domainMutex.writeLock().unlock();
        }

        portMutex.writeLock().lock();
        try {
            blockedPorts.clear();
        } finally {
            portMutex.writeLock().unlock();
        }

        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();

        ipMutex.readLock().lock();
        try {
            stats.blocked_ips = blockedIps.size();
        } finally {
            ipMutex.readLock().unlock();
        }

        appMutex.readLock().lock();
        try {
            stats.blocked_apps = blockedApps.size();
        } finally {
            appMutex.readLock().unlock();
        }

        domainMutex.readLock().lock();
        try {
            stats.blocked_domains = blockedDomains.size() + domainPatterns.size();
        } finally {
            domainMutex.readLock().unlock();
        }

        portMutex.readLock().lock();
        try {
            stats.blocked_ports = blockedPorts.size();
        } finally {
            portMutex.readLock().unlock();
        }

        return stats;
    }
}