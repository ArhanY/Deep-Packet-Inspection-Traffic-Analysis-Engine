package com.packetanalyzer.dpi;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

public class LoadBalancer {

    public static class LBStats {
        public long packets_received;
        public long packets_dispatched;
        public long[] per_fp_packets; // Packets sent to each FP
    }

    private final int lbId;
    private final int fpStartId;
    private final int numFps;

    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10000);
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final AtomicLongArray perFpCounts;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.fpQueues = fpQueues;
        this.perFpCounts = new AtomicLongArray(fpQueues.size());
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        thread = new Thread(this::run, "LB-" + lbId);
        thread.start();

        System.out.println("[LB" + lbId + "] Started (serving FP" +
                fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);
        inputQueue.shutdown();

        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running.get()) {
            // Get packet from input queue (with timeout to check running flag)
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (!jobOpt.isPresent()) {
                continue; // Timeout or shutdown
            }

            packetsReceived.incrementAndGet();

            PacketJob job = jobOpt.get();

            // Select target FP based on five-tuple hash
            int fpIndex = selectFP(job.tuple);

            // Push to selected FP's queue
            fpQueues.get(fpIndex).push(job);

            packetsDispatched.incrementAndGet();
            perFpCounts.incrementAndGet(fpIndex);
        }
    }

    private int selectFP(FiveTuple tuple) {
        // Hash the five-tuple and map to one of our FPs
        int hash = tuple.hashCode();
        int mixed = Integer.rotateLeft(hash, 15) ^ (hash >>> 3);
        return Math.floorMod(mixed, numFps);
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packets_received = packetsReceived.get();
        stats.packets_dispatched = packetsDispatched.get();

        stats.per_fp_packets = new long[perFpCounts.length()];
        for (int i = 0; i < perFpCounts.length(); i++) {
            stats.per_fp_packets[i] = perFpCounts.get(i);
        }

        return stats;
    }

    public int getId() {
        return lbId;
    }

    public boolean isRunning() {
        return running.get();
    }
}