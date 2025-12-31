package com.example.socks5vpn;

import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UdpHandler {
    private static final String TAG = "UDP";
    private static final int UDP_TIMEOUT = 10000;
    
    private final VpnService vpnService;
    private final RouteManager routeManager;
    private final TrafficStats trafficStats;
    private final LogManager logManager;
    private final ExecutorService executorService;
    private volatile boolean running;
    private volatile boolean blockAllUdp;
    
    public UdpHandler(VpnService vpnService, boolean blockAllUdp) {
        this.vpnService = vpnService;
        this.routeManager = RouteManager.getInstance();
        this.trafficStats = TrafficStats.getInstance();
        this.logManager = LogManager.getInstance();
        this.executorService = Executors.newCachedThreadPool();
        this.running = true;
        this.blockAllUdp = blockAllUdp;
        
        Log.d(TAG, "UdpHandler initialized, blockAll=" + blockAllUdp);
        logManager.i(TAG, "UDP Handler started" + (blockAllUdp ? " (ALL BLOCKED)" : ""));
    }
    
    public void setBlockAllUdp(boolean block) {
        this.blockAllUdp = block;
        logManager.i(TAG, "Block all UDP: " + block);
    }
    
    public void handlePacket(Packet packet, FileOutputStream vpnOutput) {
        if (!running) return;
        
        InetAddress srcAddr = packet.ip4Header.sourceAddress;
        int srcPort = packet.udpHeader.sourcePort;
        InetAddress dstAddr = packet.ip4Header.destinationAddress;
        int dstPort = packet.udpHeader.destinationPort;
        
        int headerSize = packet.ip4Header.headerLength + Packet.UDP_HEADER_SIZE;
        int payloadSize = packet.ip4Header.totalLength - headerSize;
        
        if (payloadSize <= 0) return;
        
        trafficStats.addPacketOut();
        trafficStats.addBytesOut(packet.ip4Header.totalLength);
        
        String dest = dstAddr.getHostAddress() + ":" + dstPort;
        
        // Проверяем глобальную блокировку UDP
        if (blockAllUdp) {
            logManager.block(TAG, dest + " (" + payloadSize + "B) - ALL UDP BLOCKED");
            trafficStats.addBlockedConnection();
            return;
        }
        
        // Проверяем правила маршрутизации
        RouteManager.RouteAction action = routeManager.getActionForIp(dstAddr);
        
        if (action == RouteManager.RouteAction.BLOCK) {
            logManager.block(TAG, dest + " (" + payloadSize + "B)");
            trafficStats.addBlockedConnection();
            return;
        }
        
        // UDP всегда идёт напрямую
        logManager.direct(TAG, dest + " (" + payloadSize + "B)");
        
        ByteBuffer buffer = packet.backingBuffer.duplicate();
        buffer.position(headerSize);
        byte[] payload = new byte[payloadSize];
        buffer.get(payload);
        
        executorService.submit(() -> {
            forwardUdp(srcAddr, srcPort, dstAddr, dstPort, payload, vpnOutput);
        });
    }
    
    private void forwardUdp(InetAddress srcAddr, int srcPort, 
                           InetAddress dstAddr, int dstPort,
                           byte[] payload, FileOutputStream vpnOutput) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(UDP_TIMEOUT);
            
            if (vpnService != null) {
                vpnService.protect(socket);
            }
            
            DatagramPacket outPacket = new DatagramPacket(payload, payload.length, dstAddr, dstPort);
            socket.send(outPacket);
            
            byte[] receiveBuffer = new byte[4096];
            DatagramPacket inPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(inPacket);
            
            int receivedLength = inPacket.getLength();
            trafficStats.addBytesIn(receivedLength);
            trafficStats.addPacketIn();
            trafficStats.addDirectConnection();
            
            logManager.d(TAG, "← " + dstAddr.getHostAddress() + ":" + dstPort + " (" + receivedLength + "B)");
            
            sendUdpResponse(dstAddr, dstPort, srcAddr, srcPort, 
                           receiveBuffer, receivedLength, vpnOutput);
            
        } catch (Exception e) {
            logManager.w(TAG, dstAddr.getHostAddress() + ":" + dstPort + " - " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }
    
    private void sendUdpResponse(InetAddress srcAddr, int srcPort,
                                InetAddress dstAddr, int dstPort,
                                byte[] payload, int payloadLength,
                                FileOutputStream vpnOutput) throws IOException {
        int totalLength = Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE + payloadLength;
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        
        // IP Header
        buffer.put((byte) 0x45);
        buffer.put((byte) 0x00);
        buffer.putShort((short) totalLength);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0x4000);
        buffer.put((byte) 64);
        buffer.put((byte) 17);
        buffer.putShort((short) 0);
        buffer.put(srcAddr.getAddress());
        buffer.put(dstAddr.getAddress());
        
        // UDP Header
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putShort((short) (Packet.UDP_HEADER_SIZE + payloadLength));
        buffer.putShort((short) 0);
        
        buffer.put(payload, 0, payloadLength);
        
        // IP checksum
        byte[] data = buffer.array();
        int sum = 0;
        for (int i = 0; i < Packet.IP4_HEADER_SIZE; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        data[10] = (byte) ((~sum >> 8) & 0xFF);
        data[11] = (byte) (~sum & 0xFF);
        
        synchronized (vpnOutput) {
            vpnOutput.write(data);
            vpnOutput.flush();
        }
    }
    
    public void stop() {
        running = false;
        executorService.shutdownNow();
        logManager.i(TAG, "UDP Handler stopped");
    }
}