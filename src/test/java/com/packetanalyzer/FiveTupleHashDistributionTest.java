package com.packetanalyzer;

import com.packetanalyzer.dpi.FiveTuple;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FiveTupleHashDistributionTest {

    @Test
    void hashDistributionIsReasonablyUniform() {
        int numBuckets = 4;
        int numSamples = 50;
        int[] buckets = new int[numBuckets];

        for (int i = 0; i < numSamples; i++) {
            FiveTuple tuple = new FiveTuple(
                    (192L << 24) | (168L << 16) | ((i / 256) << 8) | (i % 256), // varied src_ip
                    (10L << 24) | (0L << 16) | (0L << 8) | ((i * 7 + 3) % 256), // varied dst_ip
                    1024 + i * 13,      // varied src_port
                    80 + (i % 5) * 100, // varied dst_port
                    i % 2 == 0 ? 6 : 17 // mix of TCP and UDP
            );

            int bucket = Math.floorMod(tuple.hashCode(), numBuckets);
            buckets[bucket]++;
        }

        // No single bucket should hold more than 60% of all samples
        int maxAllowed = (int) (numSamples * 0.6);
        for (int b = 0; b < numBuckets; b++) {
            assertTrue(buckets[b] <= maxAllowed,
                    "Bucket " + b + " has " + buckets[b] + " of " + numSamples +
                    " samples (max allowed: " + maxAllowed + "). Hash distribution is too skewed.");
        }

        // At least 3 out of 4 buckets should be non-empty
        int nonEmpty = 0;
        for (int count : buckets) {
            if (count > 0) nonEmpty++;
        }
        assertTrue(nonEmpty >= 3,
                "Only " + nonEmpty + " of " + numBuckets + " buckets are non-empty. " +
                "Hash distribution is too concentrated.");
    }
}
