package com.example.socks5vpn;

import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class TcpHandler {
    private static final String TAG = "TCP";
    private static final int BUFFER_SIZE = 16384;
    private static final int CONNECT_TIMEOUT = 10000;
    
    private final VpnConfig config;
    private final VpnService vpnService;
    private final RouteManager routeManager;
    private final TrafficStats trafficStats;
    private final LogManager logManager;
    private final ExecutorService executorService;
    private final Map<String, TcpConnection> connections;
    private volatile boolean running;
    private final AtomicInteger connectionCounter = new AtomicInteger(0);
    
    public TcpHandler(VpnConfig config, VpnService vpnService) {
        this.config = config;
        this.vpnService = vpnService;
        this.routeManager = RouteManager.getInstance();
        this.trafficStats = TrafficStats.getInstance();
        this.logManager = LogManager.getInstance();
        this.executorService = Executors.newCachedThreadPool();
        this.connections = new ConcurrentHashMap<>();
        this.running = true;
        
        Log.d(TAG, "TcpHandler initialized");
        logManager.i(TAG, "TCP Handler started");
    }
    
    public void handlePacket(Packet packet, FileOutputStream vpnOutput) {
        if (!running) return;
        
        String connectionKey = getConnectionKey(packet);
        TcpConnection connection = connections.get(connectionKey);
        
        int payloadSize = packet.ip4Header.totalLength - 
                          packet.ip4Header.headerLength - 
                          packet.tcpHeader.headerLength;
        
        trafficStats.addPacketOut();
        trafficStats.addBytesOut(packet.ip4Header.totalLength);
        
        if (packet.tcpHeader.isSYN() && !packet.tcpHeader.isACK()) {
            InetAddress destAddr = packet.ip4Header.destinationAddress;
            int destPort = packet.tcpHeader.destinationPort;
            String dest = destAddr.getHostAddress() + ":" + destPort;
            
            // Определяем действие по правилам маршрутизации
            RouteManager.RouteAction action = routeManager.getActionForIp(destAddr);
            
            if (connection != null) {
                connection.close();
                connections.remove(connectionKey);
            }
            
            if (action == RouteManager.RouteAction.BLOCK) {
                trafficStats.addBlockedConnection();
                logManager.block(TAG, dest);
                sendRstForOrphan(packet, vpnOutput);
                return;
            }
            
            int connId = connectionCounter.incrementAndGet();
            connection = new TcpConnection(connId, packet, vpnOutput, action);
            connections.put(connectionKey, connection);
            executorService.submit(connection);
            
        } else if (connection != null) {
            connection.processPacket(packet);
        } else {
            sendRstForOrphan(packet, vpnOutput);
        }
    }
    
    private void sendRstForOrphan(Packet packet, FileOutputStream vpnOutput) {
        try {
            byte[] rstPacket = buildTcpPacket(
                packet.ip4Header.destinationAddress,
                packet.tcpHeader.destinationPort,
                packet.ip4Header.sourceAddress,
                packet.tcpHeader.sourcePort,
                0,
                packet.tcpHeader.sequenceNumber + 1,
                (byte) (Packet.TCPHeader.RST | Packet.TCPHeader.ACK),
                null, 0
            );
            
            synchronized (vpnOutput) {
                vpnOutput.write(rstPacket);
                vpnOutput.flush();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error sending RST: " + e.getMessage());
        }
    }
    
    private byte[] buildTcpPacket(InetAddress srcAddr, int srcPort,
                                   InetAddress dstAddr, int dstPort,
                                   long seqNum, long ackNum,
                                   byte flags,
                                   byte[] payload, int payloadLen) {
        
        int ipHeaderLen = 20;
        int tcpHeaderLen = 20;
        int totalLen = ipHeaderLen + tcpHeaderLen + payloadLen;
        
        byte[] packet = new byte[totalLen];
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        
        // IP Header
        buffer.put((byte) 0x45);
        buffer.put((byte) 0x00);
        buffer.putShort((short) totalLen);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0x4000);
        buffer.put((byte) 64);
        buffer.put((byte) 6);
        buffer.putShort((short) 0);
        buffer.put(srcAddr.getAddress());
        buffer.put(dstAddr.getAddress());
        
        // TCP Header
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putInt((int) seqNum);
        buffer.putInt((int) ackNum);
        buffer.put((byte) 0x50);
        buffer.put(flags);
        buffer.putShort((short) 65535);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        
        if (payload != null && payloadLen > 0) {
            buffer.put(payload, 0, payloadLen);
        }
        
        // IP Checksum
        int ipChecksum = calculateChecksum(packet, 0, ipHeaderLen);
        packet[10] = (byte) (ipChecksum >> 8);
        packet[11] = (byte) ipChecksum;
        
        // TCP Checksum
        int tcpChecksum = calculateTcpChecksum(packet, srcAddr, dstAddr, tcpHeaderLen + payloadLen);
        packet[ipHeaderLen + 16] = (byte) (tcpChecksum >> 8);
        packet[ipHeaderLen + 17] = (byte) tcpChecksum;
        
        return packet;
    }
    
    private int calculateChecksum(byte[] data, int offset, int length) {
        int sum = 0;
        int i = offset;
        
        while (length > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            length -= 2;
        }
        
        if (length > 0) {
            sum += (data[i] & 0xFF) << 8;
        }
        
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        return ~sum & 0xFFFF;
    }
    
    private int calculateTcpChecksum(byte[] packet, InetAddress srcAddr, InetAddress dstAddr, int tcpLen) {
        int sum = 0;
        
        byte[] srcBytes = srcAddr.getAddress();
        byte[] dstBytes = dstAddr.getAddress();
        
        sum += ((srcBytes[0] & 0xFF) << 8) | (srcBytes[1] & 0xFF);
        sum += ((srcBytes[2] & 0xFF) << 8) | (srcBytes[3] & 0xFF);
        sum += ((dstBytes[0] & 0xFF) << 8) | (dstBytes[1] & 0xFF);
        sum += ((dstBytes[2] & 0xFF) << 8) | (dstBytes[3] & 0xFF);
        sum += 6;
        sum += tcpLen;
        
        int offset = 20;
        int remaining = tcpLen;
        
        while (remaining > 1) {
            sum += ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
            offset += 2;
            remaining -= 2;
        }
        
        if (remaining > 0) {
            sum += (packet[offset] & 0xFF) << 8;
        }
        
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        return ~sum & 0xFFFF;
    }
    
    private String getConnectionKey(Packet packet) {
        return packet.ip4Header.sourceAddress.getHostAddress() + ":" + 
               packet.tcpHeader.sourcePort + "-" +
               packet.ip4Header.destinationAddress.getHostAddress() + ":" + 
               packet.tcpHeader.destinationPort;
    }
    
    public void stop() {
        running = false;
        for (TcpConnection connection : connections.values()) {
            connection.close();
        }
        connections.clear();
        executorService.shutdownNow();
        logManager.i(TAG, "TCP Handler stopped");
    }
    
    private class TcpConnection implements Runnable {
        private final int connectionId;
        private final InetAddress sourceAddress;
        private final int sourcePort;
        private final InetAddress destAddress;
        private final int destPort;
        private final FileOutputStream vpnOutput;
        private final RouteManager.RouteAction routeAction;
        
        private Socket remoteSocket;
        private InputStream remoteIn;
        private OutputStream remoteOut;
        private Socks5Proxy proxy;
        
        private volatile boolean closed;
        
        private long localSequenceNum;
        private long localAckNum;
        private long remoteSequenceNum;
        
        private volatile boolean synAckSent = false;
        private volatile boolean established = false;
        
        private final Object lock = new Object();
        private final Object writeLock = new Object();
        
        public TcpConnection(int id, Packet synPacket, FileOutputStream vpnOutput, 
                            RouteManager.RouteAction action) {
            this.connectionId = id;
            this.sourceAddress = synPacket.ip4Header.sourceAddress;
            this.sourcePort = synPacket.tcpHeader.sourcePort;
            this.destAddress = synPacket.ip4Header.destinationAddress;
            this.destPort = synPacket.tcpHeader.destinationPort;
            this.vpnOutput = vpnOutput;
            this.routeAction = action;
            
            this.localSequenceNum = (long) (Math.random() * Integer.MAX_VALUE);
            this.remoteSequenceNum = synPacket.tcpHeader.sequenceNumber;
            this.closed = false;
        }
        
        private String dest() {
            return destAddress.getHostAddress() + ":" + destPort;
        }
        
        @Override
        public void run() {
            try {
                if (routeAction == RouteManager.RouteAction.PROXY) {
                    connectViaProxy();
                    trafficStats.addProxyConnection();
                    logManager.proxy(TAG, "#" + connectionId + " " + dest());
                } else {
                    connectDirect();
                    trafficStats.addDirectConnection();
                    logManager.direct(TAG, "#" + connectionId + " " + dest());
                }
                
                sendSynAck();
                synAckSent = true;
                
                startForwarding();
                
            } catch (Exception e) {
                logManager.e(TAG, "#" + connectionId + " " + dest() + " - " + e.getMessage());
                if (!synAckSent) {
                    sendRst();
                }
            } finally {
                close();
                connections.remove(getConnectionKey());
            }
        }
        
        private void connectViaProxy() throws IOException {
            proxy = new Socks5Proxy(config, vpnService);
            proxy.connect(destAddress, destPort, CONNECT_TIMEOUT);
            remoteSocket = proxy.getSocket();
            remoteIn = proxy.getInputStream();
            remoteOut = proxy.getOutputStream();
        }
        
        private void connectDirect() throws IOException {
            remoteSocket = new Socket();
            
            if (vpnService != null) {
                vpnService.protect(remoteSocket);
            }
            
            remoteSocket.setTcpNoDelay(true);
            remoteSocket.setSoTimeout(CONNECT_TIMEOUT);
            remoteSocket.connect(new InetSocketAddress(destAddress, destPort), CONNECT_TIMEOUT);
            
            remoteIn = remoteSocket.getInputStream();
            remoteOut = remoteSocket.getOutputStream();
        }
        
        private String getConnectionKey() {
            return sourceAddress.getHostAddress() + ":" + sourcePort + "-" +
                   destAddress.getHostAddress() + ":" + destPort;
        }
        
        public void processPacket(Packet packet) {
            synchronized (lock) {
                if (closed) return;
                
                if (packet.tcpHeader.isRST()) {
                    close();
                    return;
                }
                
                if (packet.tcpHeader.isFIN()) {
                    localAckNum = packet.tcpHeader.sequenceNumber + 1;
                    sendFinAck();
                    close();
                    return;
                }
                
                if (packet.tcpHeader.isACK() && !established && synAckSent) {
                    established = true;
                }
                
                int payloadSize = packet.ip4Header.totalLength - 
                                  packet.ip4Header.headerLength - 
                                  packet.tcpHeader.headerLength;
                
                if (payloadSize > 0 && remoteOut != null) {
                    try {
                        ByteBuffer buffer = packet.backingBuffer.duplicate();
                        buffer.position(packet.ip4Header.headerLength + packet.tcpHeader.headerLength);
                        byte[] data = new byte[payloadSize];
                        buffer.get(data);
                        
                        remoteOut.write(data);
                        remoteOut.flush();
                        
                        trafficStats.addBytesOut(payloadSize);
                        
                        localAckNum = packet.tcpHeader.sequenceNumber + payloadSize;
                        sendAck();
                        
                    } catch (IOException e) {
                        logManager.e(TAG, "#" + connectionId + " forward error: " + e.getMessage());
                        close();
                    }
                }
            }
        }
        
        private void startForwarding() {
            byte[] buffer = new byte[BUFFER_SIZE];
            
            try {
                remoteSocket.setSoTimeout(50);
                
                while (!closed && running) {
                    try {
                        int read = remoteIn.read(buffer);
                        
                        if (read == -1) {
                            sendFin();
                            break;
                        }
                        
                        if (read > 0) {
                            trafficStats.addBytesIn(read);
                            trafficStats.addPacketIn();
                            sendData(buffer, read);
                        }
                    } catch (SocketTimeoutException e) {
                        // Continue
                    }
                }
            } catch (IOException e) {
                if (!closed) {
                    logManager.e(TAG, "#" + connectionId + " read error: " + e.getMessage());
                }
            }
        }
        
        private void sendSynAck() {
            try {
                localAckNum = remoteSequenceNum + 1;
                
                byte[] packet = buildTcpPacket(
                    destAddress, destPort,
                    sourceAddress, sourcePort,
                    localSequenceNum, localAckNum,
                    (byte) (Packet.TCPHeader.SYN | Packet.TCPHeader.ACK),
                    null, 0
                );
                
                localSequenceNum++;
                
                synchronized (vpnOutput) {
                    vpnOutput.write(packet);
                    vpnOutput.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending SYN-ACK", e);
            }
        }
        
        private void sendAck() {
            try {
                byte[] packet = buildTcpPacket(
                    destAddress, destPort,
                    sourceAddress, sourcePort,
                    localSequenceNum, localAckNum,
                    (byte) Packet.TCPHeader.ACK,
                    null, 0
                );
                
                synchronized (vpnOutput) {
                    vpnOutput.write(packet);
                    vpnOutput.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending ACK", e);
            }
        }
        
        private void sendData(byte[] data, int length) {
            synchronized (writeLock) {
                if (closed) return;
                
                try {
                    byte[] packet = buildTcpPacket(
                        destAddress, destPort,
                        sourceAddress, sourcePort,
                        localSequenceNum, localAckNum,
                        (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                        data, length
                    );
                    
                    synchronized (vpnOutput) {
                        vpnOutput.write(packet);
                        vpnOutput.flush();
                    }
                    
                    localSequenceNum += length;
                    
                } catch (Exception e) {
                    Log.e(TAG, "Error sending data", e);
                }
            }
        }
        
        private void sendFin() {
            try {
                byte[] packet = buildTcpPacket(
                    destAddress, destPort,
                    sourceAddress, sourcePort,
                    localSequenceNum, localAckNum,
                    (byte) (Packet.TCPHeader.FIN | Packet.TCPHeader.ACK),
                    null, 0
                );
                
                localSequenceNum++;
                
                synchronized (vpnOutput) {
                    vpnOutput.write(packet);
                    vpnOutput.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending FIN", e);
            }
        }
        
        private void sendFinAck() {
            try {
                byte[] packet = buildTcpPacket(
                    destAddress, destPort,
                    sourceAddress, sourcePort,
                    localSequenceNum, localAckNum,
                    (byte) (Packet.TCPHeader.FIN | Packet.TCPHeader.ACK),
                    null, 0
                );
                
                localSequenceNum++;
                
                synchronized (vpnOutput) {
                    vpnOutput.write(packet);
                    vpnOutput.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending FIN-ACK", e);
            }
        }
        
        private void sendRst() {
            try {
                byte[] packet = buildTcpPacket(
                    destAddress, destPort,
                    sourceAddress, sourcePort,
                    localSequenceNum, 0,
                    (byte) Packet.TCPHeader.RST,
                    null, 0
                );
                
                synchronized (vpnOutput) {
                    vpnOutput.write(packet);
                    vpnOutput.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending RST", e);
            }
        }
        
        public void close() {
            synchronized (lock) {
                if (closed) return;
                closed = true;
                
                if (proxy != null) {
                    proxy.close();
                }
                
                if (remoteSocket != null && !remoteSocket.isClosed()) {
                    try {
                        remoteSocket.close();
                    } catch (IOException ignored) {}
                }
            }
        }
    }
}
