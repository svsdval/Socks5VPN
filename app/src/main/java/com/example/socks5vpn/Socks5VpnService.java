package com.example.socks5vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Socks5VpnService extends VpnService {
    private static final String TAG = "VPN";
    private static final String CHANNEL_ID = "vpn_channel";
    private static final int NOTIFICATION_ID = 1;
    private static final int MTU = 1500;
    private static final long STATS_UPDATE_INTERVAL = 1000;
    
    public static final String ACTION_CONNECT = "com.example.socks5vpn.CONNECT";
    public static final String ACTION_DISCONNECT = "com.example.socks5vpn.DISCONNECT";
    
    public static final String EXTRA_SERVER = "server";
    public static final String EXTRA_PORT = "port";
    public static final String EXTRA_USERNAME = "username";
    public static final String EXTRA_PASSWORD = "password";
    public static final String EXTRA_BLOCK_UDP = "block_udp";
    
    private ParcelFileDescriptor vpnInterface;
    private VpnConfig config;
    private TcpHandler tcpHandler;
    private UdpHandler udpHandler;
    private ExecutorService executorService;
    private volatile boolean running;
    
    private Handler statsHandler;
    private Runnable statsRunnable;
    private LogManager logManager;
    
    private static Socks5VpnService instance;
    private static VpnCallback callback;
    
    public interface VpnCallback {
        void onVpnStateChanged(boolean connected);
        void onStatsUpdated(long bytesIn, long bytesOut, long proxyConns, long directConns, long blockedConns);
    }
    
    public static void setCallback(VpnCallback cb) {
        callback = cb;
    }
    
    public static boolean isRunning() {
        return instance != null && instance.running;
    }
    
    public static TrafficStats getTrafficStats() {
        return TrafficStats.getInstance();
    }
    
    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        logManager = LogManager.getInstance();
        createNotificationChannel();
        
        RouteManager.getInstance().load(this);
        
        statsHandler = new Handler(Looper.getMainLooper());
        Log.d(TAG, "VpnService created");
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_STICKY;
        }
        
        String action = intent.getAction();
        
        if (ACTION_CONNECT.equals(action)) {
            String server = intent.getStringExtra(EXTRA_SERVER);
            int port = intent.getIntExtra(EXTRA_PORT, 1080);
            String username = intent.getStringExtra(EXTRA_USERNAME);
            String password = intent.getStringExtra(EXTRA_PASSWORD);
            boolean blockUdp = intent.getBooleanExtra(EXTRA_BLOCK_UDP, false);
            
            config = new VpnConfig(server, port, username, password);
            config.setBlockUdp(blockUdp);
            
            logManager.i(TAG, "Connecting to " + server + ":" + port);
            if (blockUdp) {
                logManager.w(TAG, "UDP traffic will be blocked");
            }
            
            startVpn();
        } else if (ACTION_DISCONNECT.equals(action)) {
            logManager.i(TAG, "Disconnecting...");
            stopVpn();
        }
        
        return START_STICKY;
    }
    
    private void startVpn() {
        if (running) {
            return;
        }
        
        TrafficStats.getInstance().reset();
        logManager.clear();
        logManager.i(TAG, "=== VPN Starting ===");
        
        startForeground(NOTIFICATION_ID, createNotification("Connecting...", 0, 0));
        
        executorService = Executors.newFixedThreadPool(4);
        running = true;
        
        executorService.submit(() -> {
            try {
                logManager.i(TAG, "Setting up VPN interface...");
                if (!setupVpnInterface()) {
                    logManager.e(TAG, "Failed to setup VPN interface");
                    notifyStateChanged(false);
                    stopVpn();
                    return;
                }
                logManager.i(TAG, "VPN interface ready");
                
                logManager.i(TAG, "Testing SOCKS5 server...");
                if (!testSocks5Connection()) {
                    logManager.e(TAG, "SOCKS5 server unreachable");
                    notifyStateChanged(false);
                    stopVpn();
                    return;
                }
                logManager.i(TAG, "SOCKS5 server OK");
                
                logManager.i(TAG, "Starting handlers...");
                tcpHandler = new TcpHandler(config, Socks5VpnService.this);
                udpHandler = new UdpHandler(Socks5VpnService.this, config.isBlockUdp());
                
                notifyStateChanged(true);
                startStatsUpdater();
                
                logManager.i(TAG, "=== VPN Connected ===");
                processPackets();
                
            } catch (Exception e) {
                logManager.e(TAG, "VPN error: " + e.getMessage());
                notifyStateChanged(false);
                stopVpn();
            }
        });
    }
    
    private void startStatsUpdater() {
        statsRunnable = new Runnable() {
            @Override
            public void run() {
                if (!running) return;
                
                TrafficStats stats = TrafficStats.getInstance();
                long bytesIn = stats.getBytesIn();
                long bytesOut = stats.getBytesOut();
                long proxyConns = stats.getConnectionsProxy();
                long directConns = stats.getConnectionsDirect();
                long blockedConns = stats.getConnectionsBlocked();
                
                updateNotification(
                    "↑ " + TrafficStats.formatBytes(bytesOut) + 
                    "  ↓ " + TrafficStats.formatBytes(bytesIn),
                    bytesIn, bytesOut
                );
                
                if (callback != null) {
                    callback.onStatsUpdated(bytesIn, bytesOut, proxyConns, directConns, blockedConns);
                }
                
                statsHandler.postDelayed(this, STATS_UPDATE_INTERVAL);
            }
        };
        
        statsHandler.post(statsRunnable);
    }
    
    private void stopStatsUpdater() {
        if (statsHandler != null && statsRunnable != null) {
            statsHandler.removeCallbacks(statsRunnable);
        }
    }
    
    private boolean setupVpnInterface() {
        try {
            Builder builder = new Builder();
            
            builder.setSession("SOCKS5 VPN")
                   .setMtu(MTU)
                   .addAddress("10.0.0.2", 32)
                   .addRoute("0.0.0.0", 0)
                   .addDnsServer("8.8.8.8")
                   .addDnsServer("8.8.4.4")
                   .setBlocking(true);
            
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception e) {
                logManager.w(TAG, "Could not exclude own package");
            }
            
            vpnInterface = builder.establish();
            
            if (vpnInterface == null) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            logManager.e(TAG, "Setup error: " + e.getMessage());
            return false;
        }
    }
    
    private boolean testSocks5Connection() {
        Socket socket = null;
        try {
            socket = new Socket();
            protect(socket);
            socket.connect(new InetSocketAddress(config.getServerAddress(), config.getServerPort()), 5000);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (IOException ignored) {}
            }
        }
    }
    
    private void processPackets() {
        FileInputStream vpnInput = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream vpnOutput = new FileOutputStream(vpnInterface.getFileDescriptor());
        
        ByteBuffer buffer = ByteBuffer.allocate(MTU);
        
        while (running && vpnInterface != null) {
            try {
                buffer.clear();
                int length = vpnInput.read(buffer.array());
                
                if (length <= 0) continue;
                
                buffer.limit(length);
                
                int version = (buffer.get(0) >> 4) & 0x0F;
                if (version != 4) continue;
                
                try {
                    Packet packet = new Packet(buffer.duplicate());
                    
                    if (packet.isTCP) {
                        tcpHandler.handlePacket(packet, vpnOutput);
                    } else if (packet.isUDP) {
                        udpHandler.handlePacket(packet, vpnOutput);
                    }
                    
                } catch (Exception e) {
                    // Ignore parsing errors
                }
                
            } catch (IOException e) {
                if (running) {
                    logManager.e(TAG, "Read error: " + e.getMessage());
                }
                break;
            }
        }
        
        logManager.i(TAG, "Packet processing stopped");
    }
    
    private void stopVpn() {
        logManager.i(TAG, "=== VPN Stopping ===");
        running = false;
        
        stopStatsUpdater();
        
        if (tcpHandler != null) {
            tcpHandler.stop();
            tcpHandler = null;
        }
        
        if (udpHandler != null) {
            udpHandler.stop();
            udpHandler = null;
        }
        
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                logManager.e(TAG, "Close error: " + e.getMessage());
            }
            vpnInterface = null;
        }
        
        if (executorService != null) {
            executorService.shutdownNow();
            executorService = null;
        }
        
        notifyStateChanged(false);
        stopForeground(true);
        stopSelf();
        
        logManager.i(TAG, "=== VPN Stopped ===");
    }
    
    private void notifyStateChanged(boolean connected) {
        if (callback != null) {
            callback.onVpnStateChanged(connected);
        }
    }
    
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("VPN connection status");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
    
    private Notification createNotification(String text, long bytesIn, long bytesOut) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        
        Intent disconnectIntent = new Intent(this, Socks5VpnService.class);
        disconnectIntent.setAction(ACTION_DISCONNECT);
        PendingIntent disconnectPending = PendingIntent.getService(
            this, 0, disconnectIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        
        String contentText = text;
        if (bytesIn > 0 || bytesOut > 0) {
            contentText = "↑ " + TrafficStats.formatBytes(bytesOut) + 
                         "  ↓ " + TrafficStats.formatBytes(bytesIn);
        }
        
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SOCKS5 VPN - " + config.getServerAddress())
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPending)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build();
    }
    
    private void updateNotification(String text, long bytesIn, long bytesOut) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, createNotification(text, bytesIn, bytesOut));
        }
    }
    
    @Override
    public void onDestroy() {
        stopVpn();
        instance = null;
        super.onDestroy();
    }
    
    @Override
    public void onRevoke() {
        stopVpn();
        super.onRevoke();
    }
}
