package com.example.socks5vpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
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

    // Хосты для проксирования (поддомены). ConcurrentHashMap.newKeySet() -
    // читается на каждом пакете из потока обработки трафика, пока
    // RoutesActivity может менять набор из UI-потока; обычный HashSet здесь
    // кидал бы ConcurrentModificationException.
    private final Set<String> proxyHosts = ConcurrentHashMap.newKeySet();
    // Хосты для блокировки
    private final Set<String> blockHosts = ConcurrentHashMap.newKeySet();
    // IP/подсети для проксирования. CopyOnWriteArrayList по той же причине,
    // что и proxyHosts/blockHosts выше - читается конкурентно с редактированием.
    private final List<IpRange> proxyIpRanges = new CopyOnWriteArrayList<>();
    // IP/подсети для блокировки
    private final List<IpRange> blockIpRanges = new CopyOnWriteArrayList<>();

    // Кэш IP -> набор доменных имён, заполняется по подсмотренным DNS-ответам,
    // чтобы правила по hostname можно было применить к TCP/UDP пакетам,
    // которые содержат только IP-адрес назначения. Набор (а не одно имя),
    // потому что на одном IP может жить несколько доменов (CDN/shared hosting) -
    // хранить только "последний резолвленный" домен приводило бы к тому, что
    // правило для одного домена ошибочно применялось бы к трафику другого,
    // просто использующего тот же IP.
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, Long>> dnsCache = new ConcurrentHashMap<>();
    private static final long MIN_TTL_MS = 30_000L;
    private static final long MAX_TTL_MS = 30 * 60_000L;
    // Верхняя граница числа IP, отслеживаемых в dnsCache одновременно, чтобы
    // кэш не рос бесконечно в течение долгой VPN-сессии.
    private static final int MAX_CACHE_IPS = 4096;
    private static final int SWEEP_INTERVAL = 256;
    private final AtomicInteger dnsRecordCounter = new AtomicInteger();

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

        invalidateWildcardCache();

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
     * Объединяет решение по IP/домену с решением по приложению-владельцу
     * соединения (см. {@link AppRuleManager}). BLOCK из любого источника
     * побеждает всегда (правило блокировки - это veto), иначе побеждает
     * PROXY из любого источника, иначе DIRECT.
     */
    public static RouteAction combine(RouteAction ipOrHostAction, RouteAction appAction) {
        if (ipOrHostAction == RouteAction.BLOCK || appAction == RouteAction.BLOCK) {
            return RouteAction.BLOCK;
        }
        if (ipOrHostAction == RouteAction.PROXY || appAction == RouteAction.PROXY) {
            return RouteAction.PROXY;
        }
        return RouteAction.DIRECT;
    }

    /**
     * Определяет действие для IP адреса.
     * Сначала проверяются явные IP-правила пользователя (детерминированный,
     * надёжный сигнал), и только потом - правила по домену, определённому
     * через перехваченный DNS-ответ (см. {@link #recordDnsMapping}): такой
     * сигнал менее надёжен (один IP может обслуживать несколько доменов,
     * DNS-ответ теоретически мог быть подделан), поэтому он не должен
     * переопределять явно заданный пользователем IP-диапазон.
     */
    public RouteAction getActionForIp(InetAddress address) {
        String ip = address.getHostAddress();

        // 1. Явные IP/CIDR-правила пользователя - наивысший приоритет.
        for (IpRange range : blockIpRanges) {
            if (range.contains(address)) {
                Log.d(TAG, "BLOCK (IP range): " + ip);
                return RouteAction.BLOCK;
            }
        }

        for (IpRange range : proxyIpRanges) {
            if (range.contains(address)) {
                Log.d(TAG, "PROXY (IP range): " + ip);
                return RouteAction.PROXY;
            }
        }

        // 2. Правила по домену через DNS-кэш - менее надёжный сигнал.
        List<String> hosts = getHostsForIp(ip);
        if (!hosts.isEmpty()) {
            if (matchesAnyHost(hosts, blockHosts)) {
                Log.d(TAG, "BLOCK (host via DNS): " + hosts + " -> " + ip);
                return RouteAction.BLOCK;
            }

            if (matchesAnyHost(hosts, proxyHosts)) {
                Log.d(TAG, "PROXY (host via DNS): " + hosts + " -> " + ip);
                return RouteAction.PROXY;
            }
        }

        // Если нет совпадений - DIRECT
        return RouteAction.DIRECT;
    }

    /**
     * Сохраняет соответствие IP -> доменное имя, полученное из перехваченного
     * DNS-ответа. На один IP может приходиться несколько доменов (CDN/shared
     * hosting), поэтому имена накапливаются в наборе, а не перезаписывают
     * друг друга. Запись живёт не дольше TTL из ответа (в границах
     * [MIN_TTL_MS, MAX_TTL_MS]).
     */
    public void recordDnsMapping(String hostname, String ip, long ttlSeconds) {
        if (hostname == null || hostname.isEmpty() || ip == null) return;

        long ttlMs = Math.min(Math.max(ttlSeconds * 1000L, MIN_TTL_MS), MAX_TTL_MS);
        long expiresAt = System.currentTimeMillis() + ttlMs;
        String host = hostname.toLowerCase();

        ConcurrentHashMap<String, Long> hosts = dnsCache.get(ip);
        if (hosts == null) {
            if (dnsCache.size() >= MAX_CACHE_IPS) {
                sweepExpiredDnsEntries();
            }
            if (dnsCache.size() >= MAX_CACHE_IPS) {
                // Кэш переполнен новыми IP - подождём, пока протухнут старые записи.
                return;
            }
            hosts = dnsCache.computeIfAbsent(ip, k -> new ConcurrentHashMap<>());
        }
        hosts.put(host, expiresAt);

        if (dnsRecordCounter.incrementAndGet() % SWEEP_INTERVAL == 0) {
            sweepExpiredDnsEntries();
        }
    }

    /**
     * Возвращает живые (ещё не просроченные) доменные имена, резолвленные
     * в данный IP, удаляя протухшие записи по пути.
     */
    private List<String> getHostsForIp(String ip) {
        ConcurrentHashMap<String, Long> hosts = dnsCache.get(ip);
        if (hosts == null || hosts.isEmpty()) return Collections.emptyList();

        long now = System.currentTimeMillis();
        List<String> live = new ArrayList<>(hosts.size());
        for (Map.Entry<String, Long> entry : hosts.entrySet()) {
            if (entry.getValue() >= now) {
                live.add(entry.getKey());
            } else {
                hosts.remove(entry.getKey(), entry.getValue());
            }
        }
        return live;
    }

    /**
     * Проактивно вычищает протухшие записи из dnsCache (в т.ч. пустые
     * IP-записи), чтобы кэш не рос бесконечно, если для каких-то IP
     * больше не приходит повторных обращений (которые вычищали бы их лениво).
     */
    private void sweepExpiredDnsEntries() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, ConcurrentHashMap<String, Long>> entry : dnsCache.entrySet()) {
            ConcurrentHashMap<String, Long> hosts = entry.getValue();
            hosts.values().removeIf(expiresAt -> expiresAt < now);
            if (hosts.isEmpty()) {
                dnsCache.remove(entry.getKey(), hosts);
            }
        }
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

    private boolean matchesAnyHost(Collection<String> hostnames, Set<String> patterns) {
        for (String hostname : hostnames) {
            if (matchesHost(hostname, patterns)) return true;
        }
        return false;
    }

    private boolean matchesHost(String hostname, Set<String> patterns) {
        for (String pattern : patterns) {
            if (pattern.isEmpty()) continue;

            if (pattern.indexOf('*') < 0 && pattern.indexOf('?') < 0) {
                // Без wildcard: точное совпадение или совпадение поддомена
                if (hostname.equals(pattern) || hostname.endsWith("." + pattern)) {
                    return true;
                }
            } else if (wildcardPatternCache
                    .computeIfAbsent(pattern, RouteManager::compileWildcard)
                    .matcher(hostname).matches()) {
                return true;
            }
        }
        return false;
    }

    // Кэш скомпилированных regex для wildcard-выражений (*, ?), чтобы не
    // пересобирать Pattern на каждый пакет.
    private final ConcurrentHashMap<String, Pattern> wildcardPatternCache = new ConcurrentHashMap<>();

    private void invalidateWildcardCache() {
        wildcardPatternCache.clear();
    }

    private static Pattern compileWildcard(String pattern) {
        String literalChars = pattern.replace("*", "").replace("?", "");
        if (literalChars.isEmpty()) {
            Log.w(TAG, "Правило '" + pattern + "' состоит только из wildcard-символов и совпадёт " +
                    "с ЛЮБЫМ доменным именем - под него попадёт весь трафик");
        }

        StringBuilder regex = new StringBuilder("^");
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '*':
                    regex.append(".*");
                    break;
                case '?':
                    regex.append('.');
                    break;
                case '.':
                    regex.append("\\.");
                    break;
                default:
                    if ("\\^$|()[]{}+".indexOf(c) >= 0) {
                        regex.append('\\');
                    }
                    regex.append(c);
            }
        }
        regex.append('$');
        return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE);
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
        invalidateWildcardCache();
    }

    public Set<String> getBlockHosts() {
        return new HashSet<>(blockHosts);
    }

    public void setBlockHosts(Set<String> hosts) {
        blockHosts.clear();
        for (String h : hosts) {
            blockHosts.add(h.toLowerCase().trim());
        }
        invalidateWildcardCache();
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
        invalidateWildcardCache();
    }

    public void addBlockHost(String host) {
        blockHosts.add(host.toLowerCase().trim());
        invalidateWildcardCache();
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
        invalidateWildcardCache();
    }

    public void removeBlockHost(String host) {
        blockHosts.remove(host.toLowerCase().trim());
        invalidateWildcardCache();
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
