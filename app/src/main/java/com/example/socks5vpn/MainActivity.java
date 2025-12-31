package com.example.socks5vpn;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.android.material.textfield.TextInputEditText;

public class MainActivity extends AppCompatActivity implements Socks5VpnService.VpnCallback, LogManager.LogListener {
    
    private TextInputEditText serverAddress;
    private TextInputEditText serverPort;
    private TextInputEditText username;
    private TextInputEditText password;
    private SwitchMaterial blockUdpSwitch;
    private MaterialButton connectButton;
    private MaterialButton routesButton;
    private ImageView statusIcon;
    private TextView statusText;
    private TextView statsText;
    private LinearLayout statsLayout;
    private TextView proxyConnsText;
    private TextView directConnsText;
    private TextView blockedConnsText;
    private RecyclerView logsRecyclerView;
    private ImageButton clearLogsButton;
    
    private LogAdapter logAdapter;
    private boolean isConnected = false;
    private final Handler handler = new Handler(Looper.getMainLooper());
    
    private final ActivityResultLauncher<Intent> vpnPermissionLauncher = registerForActivityResult(
        new ActivityResultContracts.StartActivityForResult(),
        result -> {
            if (result.getResultCode() == Activity.RESULT_OK) {
                startVpnService();
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    );
    
    private final ActivityResultLauncher<String> notificationPermissionLauncher = registerForActivityResult(
        new ActivityResultContracts.RequestPermission(),
        isGranted -> {}
    );
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initViews();
        setupLogsRecyclerView();
        loadConfig();
        updateUI();
        requestNotificationPermission();
        
        Socks5VpnService.setCallback(this);
        LogManager.getInstance().addListener(this);
        
        // Load existing logs
        logAdapter.setLogs(LogManager.getInstance().getLogs());
        scrollLogsToBottom();
    }
    
    private void initViews() {
        serverAddress = findViewById(R.id.serverAddress);
        serverPort = findViewById(R.id.serverPort);
        username = findViewById(R.id.username);
        password = findViewById(R.id.password);
        blockUdpSwitch = findViewById(R.id.blockUdpSwitch);
        connectButton = findViewById(R.id.connectButton);
        routesButton = findViewById(R.id.routesButton);
        statusIcon = findViewById(R.id.statusIcon);
        statusText = findViewById(R.id.statusText);
        statsText = findViewById(R.id.statsText);
        statsLayout = findViewById(R.id.statsLayout);
        proxyConnsText = findViewById(R.id.proxyConnsText);
        directConnsText = findViewById(R.id.directConnsText);
        blockedConnsText = findViewById(R.id.blockedConnsText);
        logsRecyclerView = findViewById(R.id.logsRecyclerView);
        clearLogsButton = findViewById(R.id.clearLogsButton);
        
        connectButton.setOnClickListener(v -> toggleVpn());
        routesButton.setOnClickListener(v -> openRoutesActivity());
        clearLogsButton.setOnClickListener(v -> {
            LogManager.getInstance().clear();
            logAdapter.clear();
        });
    }
    
    private void setupLogsRecyclerView() {
        logAdapter = new LogAdapter();
        logsRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        logsRecyclerView.setAdapter(logAdapter);
    }
    
    private void scrollLogsToBottom() {
        if (logAdapter.getItemCount() > 0) {
            logsRecyclerView.scrollToPosition(logAdapter.getItemCount() - 1);
        }
    }
    
    private void openRoutesActivity() {
        Intent intent = new Intent(this, RoutesActivity.class);
        startActivity(intent);
    }
    
    private void loadConfig() {
        VpnConfig config = VpnConfig.load(this);
        serverAddress.setText(config.getServerAddress());
        serverPort.setText(String.valueOf(config.getServerPort()));
        username.setText(config.getUsername());
        password.setText(config.getPassword());
        blockUdpSwitch.setChecked(config.isBlockUdp());
    }
    
    private void saveConfig() {
        try {
            String server = serverAddress.getText().toString().trim();
            int port = Integer.parseInt(serverPort.getText().toString().trim());
            String user = username.getText().toString().trim();
            String pass = password.getText().toString();
            
            VpnConfig config = new VpnConfig(server, port, user, pass);
            config.setBlockUdp(blockUdpSwitch.isChecked());
            config.save(this);
        } catch (Exception e) {
            Toast.makeText(this, "Invalid configuration", Toast.LENGTH_SHORT).show();
        }
    }
    
    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) 
                    != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS);
            }
        }
    }
    
    private void toggleVpn() {
        if (isConnected || Socks5VpnService.isRunning()) {
            disconnectVpn();
        } else {
            connectVpn();
        }
    }
    
    private void connectVpn() {
        String server = serverAddress.getText().toString().trim();
        String portStr = serverPort.getText().toString().trim();
        
        if (server.isEmpty() || portStr.isEmpty()) {
            Toast.makeText(this, "Please enter server address and port", Toast.LENGTH_SHORT).show();
            return;
        }
        
        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid port number", Toast.LENGTH_SHORT).show();
            return;
        }
        
        saveConfig();
        
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            vpnPermissionLauncher.launch(intent);
        } else {
            startVpnService();
        }
    }
    
    private void startVpnService() {
        Intent intent = new Intent(this, Socks5VpnService.class);
        intent.setAction(Socks5VpnService.ACTION_CONNECT);
        intent.putExtra(Socks5VpnService.EXTRA_SERVER, serverAddress.getText().toString().trim());
        intent.putExtra(Socks5VpnService.EXTRA_PORT, 
            Integer.parseInt(serverPort.getText().toString().trim()));
        intent.putExtra(Socks5VpnService.EXTRA_USERNAME, username.getText().toString().trim());
        intent.putExtra(Socks5VpnService.EXTRA_PASSWORD, password.getText().toString());
        intent.putExtra(Socks5VpnService.EXTRA_BLOCK_UDP, blockUdpSwitch.isChecked());
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        
        setConnecting();
    }
    
    private void disconnectVpn() {
        Intent intent = new Intent(this, Socks5VpnService.class);
        intent.setAction(Socks5VpnService.ACTION_DISCONNECT);
        startService(intent);
    }
    
    private void setConnecting() {
        statusIcon.setImageResource(R.drawable.ic_vpn_off);
        statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.connecting));
        statusText.setText("Connecting...");
        statusText.setTextColor(ContextCompat.getColor(this, R.color.connecting));
        connectButton.setText("Cancel");
        setInputsEnabled(false);
    }
    
    private void updateUI() {
        if (isConnected || Socks5VpnService.isRunning()) {
            statusIcon.setImageResource(R.drawable.ic_vpn_on);
            statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.connected));
            statusText.setText("Connected");
            statusText.setTextColor(ContextCompat.getColor(this, R.color.connected));
            connectButton.setText("Disconnect");
            setInputsEnabled(false);
            statsLayout.setVisibility(View.VISIBLE);
            statsText.setVisibility(View.VISIBLE);
        } else {
            statusIcon.setImageResource(R.drawable.ic_vpn_off);
            statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.disconnected));
            statusText.setText("Disconnected");
            statusText.setTextColor(ContextCompat.getColor(this, R.color.disconnected));
            connectButton.setText("Connect");
            setInputsEnabled(true);
            statsLayout.setVisibility(View.GONE);
            statsText.setVisibility(View.GONE);
        }
    }
    
    private void setInputsEnabled(boolean enabled) {
        serverAddress.setEnabled(enabled);
        serverPort.setEnabled(enabled);
        username.setEnabled(enabled);
        password.setEnabled(enabled);
        blockUdpSwitch.setEnabled(enabled);
        routesButton.setEnabled(enabled);
    }
    
    @Override
    public void onVpnStateChanged(boolean connected) {
        handler.post(() -> {
            isConnected = connected;
            updateUI();
            
            if (connected) {
                Toast.makeText(this, "VPN Connected", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "VPN Disconnected", Toast.LENGTH_SHORT).show();
            }
        });
    }
    
    @Override
    public void onStatsUpdated(long bytesIn, long bytesOut, long proxyConns, long directConns, long blockedConns) {
        handler.post(() -> {
            statsText.setText("↑ " + TrafficStats.formatBytes(bytesOut) + "  ↓ " + TrafficStats.formatBytes(bytesIn));
            proxyConnsText.setText(String.valueOf(proxyConns));
            directConnsText.setText(String.valueOf(directConns));
            blockedConnsText.setText(String.valueOf(blockedConns));
        });
    }
    
    @Override
    public void onLogAdded(LogManager.LogEntry entry) {
        handler.post(() -> {
            if (entry == null) {
                logAdapter.clear();
            } else {
                logAdapter.addLog(entry);
                scrollLogsToBottom();
            }
        });
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        isConnected = Socks5VpnService.isRunning();
        updateUI();
        
        if (isConnected) {
            TrafficStats stats = TrafficStats.getInstance();
            onStatsUpdated(
                stats.getBytesIn(), stats.getBytesOut(),
                stats.getConnectionsProxy(), stats.getConnectionsDirect(),
                stats.getConnectionsBlocked()
            );
        }
        
        // Refresh logs
        logAdapter.setLogs(LogManager.getInstance().getLogs());
        scrollLogsToBottom();
    }
    
    @Override
    protected void onDestroy() {
        Socks5VpnService.setCallback(null);
        LogManager.getInstance().removeListener(this);
        super.onDestroy();
    }
}