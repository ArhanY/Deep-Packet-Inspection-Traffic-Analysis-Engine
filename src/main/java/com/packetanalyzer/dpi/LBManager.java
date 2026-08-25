package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;

public class LBManager {

    public static class AggregatedStats {
        public long total_received;
        public long total_dispatched;
    }

    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final int fpsPerLb;

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;

        // Create load balancers, each handling a subset of FPs
        for (int lbId = 0; lbId < numLbs; lbId++) {
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            int fpStart = lbId * fpsPerLb;

            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }

            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created " + numLbs + " load balancers, " +
                fpsPerLb + " FPs each");
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) {
            lb.start();
        }
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) {
            lb.stop();
        }
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        // First level of load balancing: select LB based on hash
        int hash = tuple.hashCode();
        int lbIndex = Math.floorMod(hash, lbs.size());
        return lbs.get(lbIndex);
    }

    public LoadBalancer getLB(int id) {
        return lbs.get(id);
    }

    public int getNumLBs() {
        return lbs.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        stats.total_received = 0;
        stats.total_dispatched = 0;

        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats lbStats = lb.getStats();
            stats.total_received += lbStats.packets_received;
            stats.total_dispatched += lbStats.packets_dispatched;
        }

        return stats;
    }
}