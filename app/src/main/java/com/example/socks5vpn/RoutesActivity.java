package com.example.socks5vpn;

import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RoutesActivity extends AppCompatActivity {
    
    private EditText proxyHostsEdit;
    private EditText proxyIpsEdit;
    private EditText blockHostsEdit;
    private EditText blockIpsEdit;
    
    private RouteManager routeManager;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_routes);
        
        routeManager = RouteManager.getInstance();
        routeManager.load(this);
        
        initViews();
        loadCurrentRules();
    }
    
    private void initViews() {
        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());
        
        proxyHostsEdit = findViewById(R.id.proxyHostsEdit);
        proxyIpsEdit = findViewById(R.id.proxyIpsEdit);
        blockHostsEdit = findViewById(R.id.blockHostsEdit);
        blockIpsEdit = findViewById(R.id.blockIpsEdit);
        
        MaterialButton saveButton = findViewById(R.id.saveButton);
        saveButton.setOnClickListener(v -> saveRules());
    }
    
    private void loadCurrentRules() {
        // Proxy hosts
        Set<String> proxyHosts = routeManager.getProxyHosts();
        proxyHostsEdit.setText(String.join("\n", proxyHosts));
        
        // Proxy IPs
        List<String> proxyIps = routeManager.getProxyIpRangesAsStrings();
        proxyIpsEdit.setText(String.join("\n", proxyIps));
        
        // Block hosts
        Set<String> blockHosts = routeManager.getBlockHosts();
        blockHostsEdit.setText(String.join("\n", blockHosts));
        
        // Block IPs
        List<String> blockIps = routeManager.getBlockIpRangesAsStrings();
        blockIpsEdit.setText(String.join("\n", blockIps));
    }
    
    private void saveRules() {
        try {
            // Parse proxy hosts
            String proxyHostsText = proxyHostsEdit.getText().toString();
            Set<String> proxyHosts = parseLines(proxyHostsText);
            routeManager.setProxyHosts(proxyHosts);
            
            // Parse proxy IPs
            String proxyIpsText = proxyIpsEdit.getText().toString();
            List<String> proxyIps = parseLinesList(proxyIpsText);
            routeManager.setProxyIpRanges(proxyIps);
            
            // Parse block hosts
            String blockHostsText = blockHostsEdit.getText().toString();
            Set<String> blockHosts = parseLines(blockHostsText);
            routeManager.setBlockHosts(blockHosts);
            
            // Parse block IPs
            String blockIpsText = blockIpsEdit.getText().toString();
            List<String> blockIps = parseLinesList(blockIpsText);
            routeManager.setBlockIpRanges(blockIps);
            
            // Save
            routeManager.save(this);
            
            Toast.makeText(this, "Routes saved successfully!", Toast.LENGTH_SHORT).show();
            finish();
            
        } catch (Exception e) {
            Toast.makeText(this, "Error saving routes: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
    
    private Set<String> parseLines(String text) {
        Set<String> result = new HashSet<>();
        String[] lines = text.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
    
    private List<String> parseLinesList(String text) {
        List<String> result = new ArrayList<>();
        String[] lines = text.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}