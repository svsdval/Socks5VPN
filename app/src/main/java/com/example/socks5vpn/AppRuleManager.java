package com.example.socks5vpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.util.Log;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Правила маршрутизации по конкретным приложениям: два списка пакетов
 * (proxyApps / blockApps). Приложение, не входящее ни в один список,
 * маршрутизируется как обычно (по IP/доменным правилам или напрямую).
 *
 * VPN на уровне IP-пакетов не знает, какое приложение отправило пакет,
 * поэтому владелец соединения определяется через
 * {@link ConnectivityManager#getConnectionOwnerUid} - этот API доступен
 * только с Android 10 (API 29) и только для приложения, управляющего
 * активным VPN-туннелем (наш случай).
 */
public class AppRuleManager {
    private static final String TAG = "AppRuleManager";
    private static final String PREFS_NAME = "app_rules";
    private static final String KEY_PROXY_APPS = "proxy_apps";
    private static final String KEY_BLOCK_APPS = "block_apps";

    private final Set<String> proxyApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockApps = ConcurrentHashMap.newKeySet();

    private static AppRuleManager instance;

    public static synchronized AppRuleManager getInstance() {
        if (instance == null) {
            instance = new AppRuleManager();
        }
        return instance;
    }

    private AppRuleManager() {}

    public void load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        proxyApps.clear();
        blockApps.clear();
        proxyApps.addAll(prefs.getStringSet(KEY_PROXY_APPS, new HashSet<>()));
        blockApps.addAll(prefs.getStringSet(KEY_BLOCK_APPS, new HashSet<>()));

        Log.d(TAG, "Loaded app rules: proxy=" + proxyApps.size() + ", block=" + blockApps.size());
    }

    public void save(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
                .putStringSet(KEY_PROXY_APPS, new HashSet<>(proxyApps))
                .putStringSet(KEY_BLOCK_APPS, new HashSet<>(blockApps))
                .apply();
    }

    public Set<String> getProxyApps() {
        return new HashSet<>(proxyApps);
    }

    public Set<String> getBlockApps() {
        return new HashSet<>(blockApps);
    }

    public RouteManager.RouteAction getAppAction(String packageName) {
        if (packageName == null) return RouteManager.RouteAction.DIRECT;
        if (blockApps.contains(packageName)) return RouteManager.RouteAction.BLOCK;
        if (proxyApps.contains(packageName)) return RouteManager.RouteAction.PROXY;
        return RouteManager.RouteAction.DIRECT;
    }

    /**
     * Задаёт действие для пакета. DIRECT означает "убрать из обоих списков"
     * (обычная маршрутизация по IP/доменным правилам).
     */
    public void setAppAction(String packageName, RouteManager.RouteAction action) {
        proxyApps.remove(packageName);
        blockApps.remove(packageName);
        if (action == RouteManager.RouteAction.PROXY) {
            proxyApps.add(packageName);
        } else if (action == RouteManager.RouteAction.BLOCK) {
            blockApps.add(packageName);
        }
    }

    public boolean isEmpty() {
        return proxyApps.isEmpty() && blockApps.isEmpty();
    }

    /**
     * Определяет действие для конкретного TCP/UDP-соединения по приложению,
     * которому оно принадлежит. Возвращает DIRECT, если правил нет, если
     * версия Android не поддерживает определение владельца (< API 29),
     * или если владельца определить не удалось.
     */
    public RouteManager.RouteAction getActionForConnection(Context context, int protocol,
                                                            InetAddress localAddr, int localPort,
                                                            InetAddress remoteAddr, int remotePort) {
        if (isEmpty()) return RouteManager.RouteAction.DIRECT;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return RouteManager.RouteAction.DIRECT;

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return RouteManager.RouteAction.DIRECT;

            int uid = cm.getConnectionOwnerUid(protocol,
                    new InetSocketAddress(localAddr, localPort),
                    new InetSocketAddress(remoteAddr, remotePort));

            if (uid < 0) return RouteManager.RouteAction.DIRECT;

            String[] packages = context.getPackageManager().getPackagesForUid(uid);
            if (packages == null) return RouteManager.RouteAction.DIRECT;

            RouteManager.RouteAction result = RouteManager.RouteAction.DIRECT;
            for (String pkg : packages) {
                if (blockApps.contains(pkg)) return RouteManager.RouteAction.BLOCK;
                if (proxyApps.contains(pkg)) result = RouteManager.RouteAction.PROXY;
            }
            return result;
        } catch (Exception e) {
            Log.w(TAG, "Failed to resolve owning app for connection: " + e.getMessage());
            return RouteManager.RouteAction.DIRECT;
        }
    }
}
