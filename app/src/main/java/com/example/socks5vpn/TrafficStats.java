package com.example.socks5vpn;

import java.util.concurrent.atomic.AtomicLong;

public class TrafficStats {
    private static TrafficStats instance;
    
    private final AtomicLong bytesIn = new AtomicLong(0);
    private final AtomicLong bytesOut = new AtomicLong(0);
    private final AtomicLong packetsIn = new AtomicLong(0);
    private final AtomicLong packetsOut = new AtomicLong(0);
    private final AtomicLong connectionsProxy = new AtomicLong(0);
    private final AtomicLong connectionsDirect = new AtomicLong(0);
    private final AtomicLong connectionsBlocked = new AtomicLong(0);
    
    public static synchronized TrafficStats getInstance() {
        if (instance == null) {
            instance = new TrafficStats();
        }
        return instance;
    }
    
    private TrafficStats() {}
    
    public void reset() {
        bytesIn.set(0);
        bytesOut.set(0);
        packetsIn.set(0);
        packetsOut.set(0);
        connectionsProxy.set(0);
        connectionsDirect.set(0);
        connectionsBlocked.set(0);
    }
    
    public void addBytesIn(long bytes) {
        bytesIn.addAndGet(bytes);
    }
    
    public void addBytesOut(long bytes) {
        bytesOut.addAndGet(bytes);
    }
    
    public void addPacketIn() {
        packetsIn.incrementAndGet();
    }
    
    public void addPacketOut() {
        packetsOut.incrementAndGet();
    }
    
    public void addProxyConnection() {
        connectionsProxy.incrementAndGet();
    }
    
    public void addDirectConnection() {
        connectionsDirect.incrementAndGet();
    }
    
    public void addBlockedConnection() {
        connectionsBlocked.incrementAndGet();
    }
    
    public long getBytesIn() { return bytesIn.get(); }
    public long getBytesOut() { return bytesOut.get(); }
    public long getPacketsIn() { return packetsIn.get(); }
    public long getPacketsOut() { return packetsOut.get(); }
    public long getConnectionsProxy() { return connectionsProxy.get(); }
    public long getConnectionsDirect() { return connectionsDirect.get(); }
    public long getConnectionsBlocked() { return connectionsBlocked.get(); }
    
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
}