package com.example.socks5vpn;

import android.net.VpnService;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

public class Socks5Proxy {
    private static final String TAG = "Socks5Proxy";
    
    private static final byte SOCKS_VERSION = 0x05;
    private static final byte AUTH_NONE = 0x00;
    private static final byte AUTH_USERNAME_PASSWORD = 0x02;
    private static final byte AUTH_NO_ACCEPTABLE = (byte) 0xFF;
    
    private static final byte CMD_CONNECT = 0x01;
    
    private static final byte ADDR_TYPE_IPV4 = 0x01;
    
    private static final byte REPLY_SUCCEEDED = 0x00;
    
    private final VpnConfig config;
    private final VpnService vpnService;
    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;
    
    public Socks5Proxy(VpnConfig config, VpnService vpnService) {
        this.config = config;
        this.vpnService = vpnService;
    }
    
    public Socket connect(InetAddress destAddress, int destPort, int timeout) throws IOException {
        Log.d(TAG, "=== Starting SOCKS5 connection ===");
        Log.d(TAG, "SOCKS5 Server: " + config.getServerAddress() + ":" + config.getServerPort());
        Log.d(TAG, "Destination: " + destAddress.getHostAddress() + ":" + destPort);
        
        socket = new Socket();
        socket.setReuseAddress(true);
        socket.setTcpNoDelay(true);
        
        // Protect socket from VPN - ВАЖНО: не бросаем исключение, просто логируем
        if (vpnService != null) {
            boolean protectResult = vpnService.protect(socket);
            Log.d(TAG, "Socket protect() result: " + protectResult);
            if (!protectResult) {
                Log.w(TAG, "protect() returned false, but continuing anyway (known Android bug on some devices)");
            }
        } else {
            Log.w(TAG, "VpnService is null, cannot protect socket");
        }
        
        socket.setSoTimeout(timeout);
        
        Log.d(TAG, "Connecting to SOCKS5 proxy...");
        try {
            socket.connect(new InetSocketAddress(config.getServerAddress(), config.getServerPort()), timeout);
        } catch (IOException e) {
            Log.e(TAG, "Failed to connect to SOCKS5 server: " + e.getMessage());
            throw e;
        }
        Log.d(TAG, "Connected to SOCKS5 proxy successfully");
        
        inputStream = socket.getInputStream();
        outputStream = socket.getOutputStream();
        
        // Step 1: Authentication negotiation
        Log.d(TAG, "Starting authentication negotiation...");
        authenticate();
        
        // Step 2: Connect request
        Log.d(TAG, "Sending connect request to " + destAddress.getHostAddress() + ":" + destPort);
        sendConnectRequest(destAddress, destPort);
        
        Log.d(TAG, "=== SOCKS5 tunnel established successfully ===");
        
        return socket;
    }
    
    private void authenticate() throws IOException {
        ByteBuffer authRequest;
        
        if (config.hasAuth()) {
            Log.d(TAG, "Offering auth methods: NO_AUTH, USERNAME_PASSWORD");
            authRequest = ByteBuffer.allocate(4);
            authRequest.put(SOCKS_VERSION);
            authRequest.put((byte) 2);
            authRequest.put(AUTH_NONE);
            authRequest.put(AUTH_USERNAME_PASSWORD);
        } else {
            Log.d(TAG, "Offering auth method: NO_AUTH only");
            authRequest = ByteBuffer.allocate(3);
            authRequest.put(SOCKS_VERSION);
            authRequest.put((byte) 1);
            authRequest.put(AUTH_NONE);
        }
        
        Log.d(TAG, "Sending auth request: " + bytesToHex(authRequest.array()));
        outputStream.write(authRequest.array());
        outputStream.flush();
        
        byte[] response = new byte[2];
        int read = readFully(inputStream, response);
        Log.d(TAG, "Auth response: " + bytesToHex(response) + ", bytes read: " + read);
        
        if (read != 2) {
            throw new IOException("Invalid SOCKS5 auth response, read " + read + " bytes");
        }
        
        if (response[0] != SOCKS_VERSION) {
            throw new IOException("Invalid SOCKS version: " + (response[0] & 0xFF));
        }
        
        byte authMethod = response[1];
        Log.d(TAG, "Server selected auth method: " + (authMethod & 0xFF));
        
        if (authMethod == AUTH_NO_ACCEPTABLE) {
            throw new IOException("No acceptable authentication methods");
        }
        
        if (authMethod == AUTH_USERNAME_PASSWORD) {
            if (!config.hasAuth()) {
                throw new IOException("Server requires authentication but no credentials provided");
            }
            performUsernamePasswordAuth();
        }
        
        Log.d(TAG, "Authentication completed successfully");
    }
    
    private void performUsernamePasswordAuth() throws IOException {
        String username = config.getUsername();
        String password = config.getPassword();
        
        Log.d(TAG, "Performing username/password auth for user: " + username);
        
        byte[] usernameBytes = username.getBytes("UTF-8");
        byte[] passwordBytes = password.getBytes("UTF-8");
        
        ByteBuffer authRequest = ByteBuffer.allocate(3 + usernameBytes.length + passwordBytes.length);
        authRequest.put((byte) 0x01);
        authRequest.put((byte) usernameBytes.length);
        authRequest.put(usernameBytes);
        authRequest.put((byte) passwordBytes.length);
        authRequest.put(passwordBytes);
        
        outputStream.write(authRequest.array());
        outputStream.flush();
        
        byte[] response = new byte[2];
        int read = readFully(inputStream, response);
        
        Log.d(TAG, "Username/password auth response: " + bytesToHex(response));
        
        if (read != 2 || response[1] != 0x00) {
            throw new IOException("SOCKS5 username/password authentication failed");
        }
        
        Log.d(TAG, "Username/password authentication successful");
    }
    
    private void sendConnectRequest(InetAddress destAddress, int destPort) throws IOException {
        byte[] addressBytes = destAddress.getAddress();
        
        ByteBuffer request = ByteBuffer.allocate(10);
        request.put(SOCKS_VERSION);
        request.put(CMD_CONNECT);
        request.put((byte) 0x00);
        request.put(ADDR_TYPE_IPV4);
        request.put(addressBytes);
        request.putShort((short) destPort);
        
        Log.d(TAG, "Sending connect request: " + bytesToHex(request.array()));
        outputStream.write(request.array());
        outputStream.flush();
        
        // Read response header first (4 bytes minimum)
        byte[] responseHeader = new byte[4];
        int read = readFully(inputStream, responseHeader);
        
        Log.d(TAG, "Connect response header: " + bytesToHex(responseHeader) + ", bytes read: " + read);
        
        if (read < 4) {
            throw new IOException("Invalid SOCKS5 connect response header, read " + read + " bytes");
        }
        
        if (responseHeader[0] != SOCKS_VERSION) {
            throw new IOException("Invalid SOCKS version in response: " + (responseHeader[0] & 0xFF));
        }
        
        if (responseHeader[1] != REPLY_SUCCEEDED) {
            String errorMsg = getSocks5ErrorMessage(responseHeader[1]);
            throw new IOException("SOCKS5 connect failed: " + errorMsg + " (code: " + (responseHeader[1] & 0xFF) + ")");
        }
        
        // Read rest of response based on address type
        byte addrType = responseHeader[3];
        int remainingBytes;
        
        switch (addrType) {
            case ADDR_TYPE_IPV4:
                remainingBytes = 4 + 2; // 4 bytes IP + 2 bytes port
                break;
            case 0x04: // IPv6
                remainingBytes = 16 + 2; // 16 bytes IP + 2 bytes port
                break;
            case 0x03: // Domain name
                // First byte is length
                byte[] lenByte = new byte[1];
                readFully(inputStream, lenByte);
                remainingBytes = (lenByte[0] & 0xFF) + 2; // domain + 2 bytes port
                break;
            default:
                remainingBytes = 6; // Assume IPv4
        }
        
        byte[] remaining = new byte[remainingBytes];
        readFully(inputStream, remaining);
        Log.d(TAG, "Connect response remaining: " + bytesToHex(remaining));
        
        Log.d(TAG, "Connect request successful");
    }
    
    private String getSocks5ErrorMessage(byte code) {
        switch (code) {
            case 0x01: return "General SOCKS server failure";
            case 0x02: return "Connection not allowed by ruleset";
            case 0x03: return "Network unreachable";
            case 0x04: return "Host unreachable";
            case 0x05: return "Connection refused";
            case 0x06: return "TTL expired";
            case 0x07: return "Command not supported";
            case 0x08: return "Address type not supported";
            default: return "Unknown error";
        }
    }
    
    private int readFully(InputStream is, byte[] buffer) throws IOException {
        int totalRead = 0;
        int remaining = buffer.length;
        int retries = 0;
        
        while (remaining > 0 && retries < 50) {
            int read = is.read(buffer, totalRead, remaining);
            if (read == -1) {
                Log.w(TAG, "readFully: EOF reached, totalRead=" + totalRead);
                break;
            }
            if (read == 0) {
                retries++;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    break;
                }
                continue;
            }
            totalRead += read;
            remaining -= read;
            retries = 0;
        }
        
        return totalRead;
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
    
    public Socket getSocket() {
        return socket;
    }
    
    public InputStream getInputStream() {
        return inputStream;
    }
    
    public OutputStream getOutputStream() {
        return outputStream;
    }
    
    public void close() {
        Log.d(TAG, "Closing SOCKS5 connection");
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException ignored) {}
        
        try {
            if (outputStream != null) {
                outputStream.close();
            }
        } catch (IOException ignored) {}
        
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing socket", e);
        }
    }
}