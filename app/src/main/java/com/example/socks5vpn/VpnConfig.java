package com.example.socks5vpn;

import android.content.Context;
import android.content.SharedPreferences;

public class VpnConfig {
    private static final String PREFS_NAME = "vpn_config";
    private static final String KEY_SERVER = "server";
    private static final String KEY_PORT = "port";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_PASSWORD = "password";
    private static final String KEY_BLOCK_UDP = "block_udp";
    private static final String KEY_ENABLE_LOGS = "enable_logs";
    
    private String serverAddress;
    private int serverPort;
    private String username;
    private String password;
    private boolean blockUdp;
    private boolean enableLogs;
    
    public VpnConfig(String serverAddress, int serverPort, String username, String password) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.username = username;
        this.password = password;
        this.blockUdp = false;
        this.enableLogs = true;
    }
    
    public String getServerAddress() { return serverAddress; }
    public int getServerPort() { return serverPort; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public boolean isBlockUdp() { return blockUdp; }
    public boolean isEnableLogs() { return enableLogs; }
    
    public void setBlockUdp(boolean blockUdp) { this.blockUdp = blockUdp; }
    public void setEnableLogs(boolean enableLogs) { this.enableLogs = enableLogs; }
    
    public boolean hasAuth() {
        return username != null && !username.isEmpty() && password != null && !password.isEmpty();
    }
    
    public void save(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
            .putString(KEY_SERVER, serverAddress)
            .putInt(KEY_PORT, serverPort)
            .putString(KEY_USERNAME, username)
            .putString(KEY_PASSWORD, password)
            .putBoolean(KEY_BLOCK_UDP, blockUdp)
            .putBoolean(KEY_ENABLE_LOGS, enableLogs)
            .apply();
    }
    
    public static VpnConfig load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        VpnConfig config = new VpnConfig(
            prefs.getString(KEY_SERVER, "127.0.0.1"),
            prefs.getInt(KEY_PORT, 1080),
            prefs.getString(KEY_USERNAME, ""),
            prefs.getString(KEY_PASSWORD, "")
        );
        config.setBlockUdp(prefs.getBoolean(KEY_BLOCK_UDP, false));
        config.setEnableLogs(prefs.getBoolean(KEY_ENABLE_LOGS, true));
        return config;
    }
    
    public static void saveBlockUdp(Context context, boolean blockUdp) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_BLOCK_UDP, blockUdp).apply();
    }
    
    public static boolean loadBlockUdp(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getBoolean(KEY_BLOCK_UDP, false);
    }
}