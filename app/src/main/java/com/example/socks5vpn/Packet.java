package com.example.socks5vpn;

import android.util.Log;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Packet {
    private static final String TAG = "Packet";
    
    public static final int IP4_HEADER_SIZE = 20;
    public static final int TCP_HEADER_SIZE = 20;
    public static final int UDP_HEADER_SIZE = 8;
    
    public IP4Header ip4Header;
    public TCPHeader tcpHeader;
    public UDPHeader udpHeader;
    public ByteBuffer backingBuffer;
    public boolean isTCP;
    public boolean isUDP;
    
    public Packet(ByteBuffer buffer) throws UnknownHostException {
        this.backingBuffer = buffer;
        this.ip4Header = new IP4Header(buffer);
        
        if (ip4Header.protocol == IP4Header.TransportProtocol.TCP) {
            this.tcpHeader = new TCPHeader(buffer);
            this.isTCP = true;
        } else if (ip4Header.protocol == IP4Header.TransportProtocol.UDP) {
            this.udpHeader = new UDPHeader(buffer);
            this.isUDP = true;
        }
    }
    
    public void updateTCPBuffer(ByteBuffer buffer, byte flags, long sequenceNum, long ackNum, int payloadSize) {
        buffer.position(0);
        fillHeader(buffer);
        backingBuffer = buffer;
        
        tcpHeader.flags = flags;
        tcpHeader.sequenceNumber = sequenceNum;
        tcpHeader.acknowledgementNumber = ackNum;
        
        // Update TCP fields in buffer
        buffer.position(IP4_HEADER_SIZE + 4);
        buffer.putInt((int) sequenceNum);
        buffer.putInt((int) ackNum);
        buffer.position(IP4_HEADER_SIZE + 13);
        buffer.put(flags);
        
        int ip4TotalLength = IP4_HEADER_SIZE + TCP_HEADER_SIZE + payloadSize;
        backingBuffer.putShort(2, (short) ip4TotalLength);
        ip4Header.totalLength = ip4TotalLength;
        
        // Recalculate checksums
        updateIP4Checksum();
        updateTCPChecksum(payloadSize);
    }
    
    public void updateUDPBuffer(ByteBuffer buffer, int payloadSize) {
        buffer.position(0);
        fillHeader(buffer);
        backingBuffer = buffer;
        
        int udpTotalLength = UDP_HEADER_SIZE + payloadSize;
        backingBuffer.putShort(IP4_HEADER_SIZE + 4, (short) udpTotalLength);
        
        int ip4TotalLength = IP4_HEADER_SIZE + udpTotalLength;
        backingBuffer.putShort(2, (short) ip4TotalLength);
        
        updateUDPChecksum(payloadSize);
        updateIP4Checksum();
    }
    
    private void fillHeader(ByteBuffer buffer) {
        ip4Header.fillHeader(buffer);
        if (isTCP) {
            tcpHeader.fillHeader(buffer);
        } else if (isUDP) {
            udpHeader.fillHeader(buffer);
        }
    }
    
    private void updateIP4Checksum() {
        // Zero out existing checksum
        backingBuffer.putShort(10, (short) 0);
        
        int sum = 0;
        backingBuffer.position(0);
        
        for (int i = 0; i < IP4_HEADER_SIZE / 2; i++) {
            sum += backingBuffer.getShort() & 0xFFFF;
        }
        
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        sum = ~sum & 0xFFFF;
        backingBuffer.putShort(10, (short) sum);
    }
    
    private void updateTCPChecksum(int payloadSize) {
        int tcpLength = TCP_HEADER_SIZE + payloadSize;
        
        // Pseudo header sum
        int sum = 0;
        
        // Source address
        byte[] srcBytes = ip4Header.sourceAddress.getAddress();
        sum += ((srcBytes[0] & 0xFF) << 8) | (srcBytes[1] & 0xFF);
        sum += ((srcBytes[2] & 0xFF) << 8) | (srcBytes[3] & 0xFF);
        
        // Destination address
        byte[] dstBytes = ip4Header.destinationAddress.getAddress();
        sum += ((dstBytes[0] & 0xFF) << 8) | (dstBytes[1] & 0xFF);
        sum += ((dstBytes[2] & 0xFF) << 8) | (dstBytes[3] & 0xFF);
        
        // Protocol
        sum += 6; // TCP
        
        // TCP Length
        sum += tcpLength;
        
        // Zero out checksum field
        backingBuffer.putShort(IP4_HEADER_SIZE + 16, (short) 0);
        
        // Sum TCP header and data
        backingBuffer.position(IP4_HEADER_SIZE);
        int remaining = tcpLength;
        
        while (remaining > 1) {
            sum += backingBuffer.getShort() & 0xFFFF;
            remaining -= 2;
        }
        
        if (remaining > 0) {
            sum += (backingBuffer.get() & 0xFF) << 8;
        }
        
        // Fold sum
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        sum = ~sum & 0xFFFF;
        backingBuffer.putShort(IP4_HEADER_SIZE + 16, (short) sum);
    }
    
    private void updateUDPChecksum(int payloadSize) {
        // UDP checksum is optional for IPv4, set to 0
        backingBuffer.putShort(IP4_HEADER_SIZE + 6, (short) 0);
    }
    
    public static class IP4Header {
        public byte version;
        public byte IHL;
        public int headerLength;
        public short typeOfService;
        public int totalLength;
        public int identification;
        public short flags;
        public long fragmentOffset;
        public short TTL;
        public TransportProtocol protocol;
        public int headerChecksum;
        public InetAddress sourceAddress;
        public InetAddress destinationAddress;
        
        public enum TransportProtocol {
            TCP(6),
            UDP(17),
            OTHER(0xFF);
            
            private int protocolNumber;
            
            TransportProtocol(int protocolNumber) {
                this.protocolNumber = protocolNumber;
            }
            
            public int getNumber() {
                return protocolNumber;
            }
            
            public static TransportProtocol fromNumber(int number) {
                if (number == 6) return TCP;
                if (number == 17) return UDP;
                return OTHER;
            }
        }
        
        public IP4Header(ByteBuffer buffer) throws UnknownHostException {
            byte versionAndIHL = buffer.get();
            this.version = (byte) ((versionAndIHL >> 4) & 0x0F);
            this.IHL = (byte) (versionAndIHL & 0x0F);
            this.headerLength = this.IHL * 4;
            
            this.typeOfService = (short) (buffer.get() & 0xFF);
            this.totalLength = buffer.getShort() & 0xFFFF;
            this.identification = buffer.getShort() & 0xFFFF;
            
            short flagsAndFragmentOffset = buffer.getShort();
            this.flags = (short) ((flagsAndFragmentOffset >> 13) & 0x07);
            this.fragmentOffset = flagsAndFragmentOffset & 0x1FFF;
            
            this.TTL = (short) (buffer.get() & 0xFF);
            this.protocol = TransportProtocol.fromNumber(buffer.get() & 0xFF);
            this.headerChecksum = buffer.getShort() & 0xFFFF;
            
            byte[] addressBytes = new byte[4];
            buffer.get(addressBytes);
            this.sourceAddress = InetAddress.getByAddress(addressBytes);
            
            buffer.get(addressBytes);
            this.destinationAddress = InetAddress.getByAddress(addressBytes);
            
            // Skip options if present
            int optionsLength = this.headerLength - 20;
            if (optionsLength > 0) {
                buffer.position(buffer.position() + optionsLength);
            }
        }
        
        public void fillHeader(ByteBuffer buffer) {
            buffer.put((byte) ((4 << 4) | 5)); // IPv4, IHL=5
            buffer.put((byte) this.typeOfService);
            buffer.putShort((short) this.totalLength);
            buffer.putShort((short) this.identification);
            buffer.putShort((short) ((this.flags << 13) | this.fragmentOffset));
            buffer.put((byte) this.TTL);
            buffer.put((byte) this.protocol.getNumber());
            buffer.putShort((short) this.headerChecksum);
            buffer.put(this.sourceAddress.getAddress());
            buffer.put(this.destinationAddress.getAddress());
        }
    }
    
    public static class TCPHeader {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;
        
        public int sourcePort;
        public int destinationPort;
        public long sequenceNumber;
        public long acknowledgementNumber;
        public byte dataOffset;
        public int headerLength;
        public byte flags;
        public int window;
        public int checksum;
        public int urgentPointer;
        
        public TCPHeader(ByteBuffer buffer) {
            this.sourcePort = buffer.getShort() & 0xFFFF;
            this.destinationPort = buffer.getShort() & 0xFFFF;
            this.sequenceNumber = buffer.getInt() & 0xFFFFFFFFL;
            this.acknowledgementNumber = buffer.getInt() & 0xFFFFFFFFL;
            
            byte dataOffsetAndReserved = buffer.get();
            this.dataOffset = (byte) ((dataOffsetAndReserved >> 4) & 0x0F);
            this.headerLength = this.dataOffset * 4;
            
            this.flags = buffer.get();
            this.window = buffer.getShort() & 0xFFFF;
            this.checksum = buffer.getShort() & 0xFFFF;
            this.urgentPointer = buffer.getShort() & 0xFFFF;
            
            // Skip TCP options
            int optionsLength = this.headerLength - TCP_HEADER_SIZE;
            if (optionsLength > 0 && buffer.remaining() >= optionsLength) {
                buffer.position(buffer.position() + optionsLength);
            }
        }
        
        public boolean isFIN() { return (flags & FIN) == FIN; }
        public boolean isSYN() { return (flags & SYN) == SYN; }
        public boolean isRST() { return (flags & RST) == RST; }
        public boolean isPSH() { return (flags & PSH) == PSH; }
        public boolean isACK() { return (flags & ACK) == ACK; }
        public boolean isURG() { return (flags & URG) == URG; }
        
        public void fillHeader(ByteBuffer buffer) {
            buffer.putShort((short) this.sourcePort);
            buffer.putShort((short) this.destinationPort);
            buffer.putInt((int) this.sequenceNumber);
            buffer.putInt((int) this.acknowledgementNumber);
            buffer.put((byte) (5 << 4)); // Data offset = 5 (20 bytes)
            buffer.put(this.flags);
            buffer.putShort((short) this.window);
            buffer.putShort((short) this.checksum);
            buffer.putShort((short) this.urgentPointer);
        }
    }
    
    public static class UDPHeader {
        public int sourcePort;
        public int destinationPort;
        public int length;
        public int checksum;
        
        public UDPHeader(ByteBuffer buffer) {
            this.sourcePort = buffer.getShort() & 0xFFFF;
            this.destinationPort = buffer.getShort() & 0xFFFF;
            this.length = buffer.getShort() & 0xFFFF;
            this.checksum = buffer.getShort() & 0xFFFF;
        }
        
        public void fillHeader(ByteBuffer buffer) {
            buffer.putShort((short) this.sourcePort);
            buffer.putShort((short) this.destinationPort);
            buffer.putShort((short) this.length);
            buffer.putShort((short) this.checksum);
        }
    }
}
