package com.example.socks5vpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class RouteManager {
    private static final String TAG = "RouteManager";
    private static final String PREFS_NAME = "route_rules";
    private static final String KEY_PROXY_HOSTS = "proxy_hosts";
    private static final String KEY_BLOCK_HOSTS = "block_hosts";
    private static final String KEY_PROXY_IPS = "proxy_ips";
    private static final String KEY_BLOCK_IPS = "block_ips";
    
    public enum RouteAction {
        PROXY,      // Через SOCKS5
        BLOCK,      // Заблокировать
        DIRECT      // Напрямую
    }
    
    // Хосты для проксирования (поддомены)
    private final Set<String> proxyHosts = new HashSet<>();
    // Хосты для блокировки
    private final Set<String> blockHosts = new HashSet<>();
    // IP/подсети для проксирования
    private final List<IpRange> proxyIpRanges = new ArrayList<>();
    // IP/подсети для блокировки
    private final List<IpRange> blockIpRanges = new ArrayList<>();
    
    private static RouteManager instance;
    
    public static synchronized RouteManager getInstance() {
        if (instance == null) {
            instance = new RouteManager();
        }
        return instance;
    }
    
    private RouteManager() {
        // Добавим дефолтные правила
        addDefaultRules();
    }
    
    private void addDefaultRules() {
        // Примеры правил для проксирования
        // proxyHosts.add("google.com");
        // proxyHosts.add("youtube.com");
        
        // Примеры правил для блокировки
        // blockHosts.add("ads.example.com");
        // blockIpRanges.add(new IpRange("10.0.0.0", 8));
    }
    
    public void load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        
        proxyHosts.clear();
        blockHosts.clear();
        proxyIpRanges.clear();
        blockIpRanges.clear();
        
        Set<String> proxyHostsSet = prefs.getStringSet(KEY_PROXY_HOSTS, new HashSet<>());
        Set<String> blockHostsSet = prefs.getStringSet(KEY_BLOCK_HOSTS, new HashSet<>());
        Set<String> proxyIpsSet = prefs.getStringSet(KEY_PROXY_IPS, new HashSet<>());
        Set<String> blockIpsSet = prefs.getStringSet(KEY_BLOCK_IPS, new HashSet<>());
        
        proxyHosts.addAll(proxyHostsSet);
        blockHosts.addAll(blockHostsSet);
        
        for (String ip : proxyIpsSet) {
            IpRange range = IpRange.parse(ip);
            if (range != null) {
                proxyIpRanges.add(range);
            }
        }
        
        for (String ip : blockIpsSet) {
            IpRange range = IpRange.parse(ip);
            if (range != null) {
                blockIpRanges.add(range);
            }
        }
        
        Log.d(TAG, "Loaded rules: proxyHosts=" + proxyHosts.size() + 
              ", blockHosts=" + blockHosts.size() +
              ", proxyIps=" + proxyIpRanges.size() +
              ", blockIps=" + blockIpRanges.size());
    }
    
    public void save(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        
        Set<String> proxyIpsSet = new HashSet<>();
        for (IpRange range : proxyIpRanges) {
            proxyIpsSet.add(range.toString());
        }
        
        Set<String> blockIpsSet = new HashSet<>();
        for (IpRange range : blockIpRanges) {
            blockIpsSet.add(range.toString());
        }
        
        prefs.edit()
            .putStringSet(KEY_PROXY_HOSTS, new HashSet<>(proxyHosts))
            .putStringSet(KEY_BLOCK_HOSTS, new HashSet<>(blockHosts))
            .putStringSet(KEY_PROXY_IPS, proxyIpsSet)
            .putStringSet(KEY_BLOCK_IPS, blockIpsSet)
            .apply();
    }
    
    /**
     * Определяет действие для IP адреса
     */
    public RouteAction getActionForIp(InetAddress address) {
        String ip = address.getHostAddress();
        
        // Проверяем блокировку по IP
        for (IpRange range : blockIpRanges) {
            if (range.contains(address)) {
                Log.d(TAG, "BLOCK (IP range): " + ip);
                return RouteAction.BLOCK;
            }
        }
        
        // Проверяем проксирование по IP
        for (IpRange range : proxyIpRanges) {
            if (range.contains(address)) {
                Log.d(TAG, "PROXY (IP range): " + ip);
                return RouteAction.PROXY;
            }
        }
        
        // Если нет совпадений - DIRECT
        return RouteAction.DIRECT;
    }
    
    /**
     * Определяет действие для хоста (DNS имя)
     */
    public RouteAction getActionForHost(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return RouteAction.DIRECT;
        }
        
        String host = hostname.toLowerCase();
        
        // Проверяем блокировку
        if (matchesHost(host, blockHosts)) {
            Log.d(TAG, "BLOCK (host): " + hostname);
            return RouteAction.BLOCK;
        }
        
        // Проверяем проксирование
        if (matchesHost(host, proxyHosts)) {
            Log.d(TAG, "PROXY (host): " + hostname);
            return RouteAction.PROXY;
        }
        
        return RouteAction.DIRECT;
    }
    
    private boolean matchesHost(String hostname, Set<String> patterns) {
        for (String pattern : patterns) {
            // Точное совпадение
            if (hostname.equals(pattern)) {
                return true;
            }
            // Совпадение поддомена
            if (hostname.endsWith("." + pattern)) {
                return true;
            }
            // Wildcard pattern
            if (pattern.startsWith("*.") && hostname.endsWith(pattern.substring(1))) {
                return true;
            }
        }
        return false;
    }
    
    // Геттеры и сеттеры для UI
    public Set<String> getProxyHosts() {
        return new HashSet<>(proxyHosts);
    }
    
    public void setProxyHosts(Set<String> hosts) {
        proxyHosts.clear();
        for (String h : hosts) {
            proxyHosts.add(h.toLowerCase().trim());
        }
    }
    
    public Set<String> getBlockHosts() {
        return new HashSet<>(blockHosts);
    }
    
    public void setBlockHosts(Set<String> hosts) {
        blockHosts.clear();
        for (String h : hosts) {
            blockHosts.add(h.toLowerCase().trim());
        }
    }
    
    public List<String> getProxyIpRangesAsStrings() {
        List<String> result = new ArrayList<>();
        for (IpRange range : proxyIpRanges) {
            result.add(range.toString());
        }
        return result;
    }
    
    public void setProxyIpRanges(List<String> ranges) {
        proxyIpRanges.clear();
        for (String r : ranges) {
            IpRange range = IpRange.parse(r.trim());
            if (range != null) {
                proxyIpRanges.add(range);
            }
        }
    }
    
    public List<String> getBlockIpRangesAsStrings() {
        List<String> result = new ArrayList<>();
        for (IpRange range : blockIpRanges) {
            result.add(range.toString());
        }
        return result;
    }
    
    public void setBlockIpRanges(List<String> ranges) {
        blockIpRanges.clear();
        for (String r : ranges) {
            IpRange range = IpRange.parse(r.trim());
            if (range != null) {
                blockIpRanges.add(range);
            }
        }
    }
    
    public void addProxyHost(String host) {
        proxyHosts.add(host.toLowerCase().trim());
    }
    
    public void addBlockHost(String host) {
        blockHosts.add(host.toLowerCase().trim());
    }
    
    public void addProxyIpRange(String cidr) {
        IpRange range = IpRange.parse(cidr);
        if (range != null) {
            proxyIpRanges.add(range);
        }
    }
    
    public void addBlockIpRange(String cidr) {
        IpRange range = IpRange.parse(cidr);
        if (range != null) {
            blockIpRanges.add(range);
        }
    }
    
    public void removeProxyHost(String host) {
        proxyHosts.remove(host.toLowerCase().trim());
    }
    
    public void removeBlockHost(String host) {
        blockHosts.remove(host.toLowerCase().trim());
    }
    
    /**
     * Представляет IP адрес или подсеть (CIDR)
     */
    public static class IpRange {
        private final byte[] network;
        private final int prefixLength;
        
        public IpRange(byte[] network, int prefixLength) {
            this.network = network;
            this.prefixLength = prefixLength;
        }
        
        public static IpRange parse(String cidr) {
            try {
                String[] parts = cidr.split("/");
                String ip = parts[0];
                int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
                
                InetAddress addr = InetAddress.getByName(ip);
                return new IpRange(addr.getAddress(), prefix);
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse IP range: " + cidr, e);
                return null;
            }
        }
        
        public boolean contains(InetAddress address) {
            byte[] addrBytes = address.getAddress();
            
            if (addrBytes.length != network.length) {
                return false;
            }
            
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            
            // Проверяем полные байты
            for (int i = 0; i < fullBytes; i++) {
                if (addrBytes[i] != network[i]) {
                    return false;
                }
            }
            
            // Проверяем оставшиеся биты
            if (remainingBits > 0 && fullBytes < network.length) {
                int mask = 0xFF << (8 - remainingBits);
                if ((addrBytes[fullBytes] & mask) != (network[fullBytes] & mask)) {
                    return false;
                }
            }
            
            return true;
        }
        
        @Override
        public String toString() {
            try {
                InetAddress addr = InetAddress.getByAddress(network);
                return addr.getHostAddress() + "/" + prefixLength;
            } catch (Exception e) {
                return "invalid";
            }
        }
    }
}