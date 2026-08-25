package com.packetanalyzer.dpi;

import java.util.ArrayDeque;
import java.util.Optional;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;


public class ThreadSafeQueue<T> {

    private final ArrayDeque<T> queue = new ArrayDeque<>();
    private final ReentrantLock mutex = new ReentrantLock();
    private final Condition notEmpty = mutex.newCondition();
    private final Condition notFull = mutex.newCondition();
    private final int maxSize;
    private volatile boolean shutdown = false;

    public ThreadSafeQueue() {
        this(10000);
    }

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    // Push item to queue (blocks if full)
    public void push(T item) {
        mutex.lock();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.awaitUninterruptibly();
            }
            if (shutdown) return;

            queue.addLast(item);
            notEmpty.signal();
        } finally {
            mutex.unlock();
        }
    }

    // Try to push without blocking
    public boolean tryPush(T item) {
        mutex.lock();
        try {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.addLast(item);
            notEmpty.signal();
            return true;
        } finally {
            mutex.unlock();
        }
    }

    // Pop item from queue (blocks if empty)
    public Optional<T> pop() {
        mutex.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.awaitUninterruptibly();
            }
            if (queue.isEmpty()) return Optional.empty();

            T item = queue.pollFirst();
            notFull.signal();
            return Optional.of(item);
        } finally {
            mutex.unlock();
        }
    }

    // Pop with timeout (in milliseconds)
    public Optional<T> popWithTimeout(long timeoutMillis) {
        mutex.lock();
        try {
            long nanos = java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            while (queue.isEmpty() && !shutdown) {
                if (nanos <= 0) return Optional.empty(); // Timeout
                try {
                    nanos = notEmpty.awaitNanos(nanos);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Optional.empty();
                }
            }

            if (queue.isEmpty()) return Optional.empty();

            T item = queue.pollFirst();
            notFull.signal();
            return Optional.of(item);
        } finally {
            mutex.unlock();
        }
    }

    // Check if empty
    public boolean isEmpty() {
        mutex.lock();
        try {
            return queue.isEmpty();
        } finally {
            mutex.unlock();
        }
    }

    // Get current size
    public int size() {
        mutex.lock();
        try {
            return queue.size();
        } finally {
            mutex.unlock();
        }
    }

    // Signal shutdown (wake up all waiting threads)
    public void shutdown() {
        mutex.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            mutex.unlock();
        }
    }

    public boolean isShutdown() {
        mutex.lock();
        try {
            return shutdown;
        } finally {
            mutex.unlock();
        }
    }
}