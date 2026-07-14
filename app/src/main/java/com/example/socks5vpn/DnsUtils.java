package com.example.socks5vpn;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Разбор DNS-ответов, летящих через UDP:53, чтобы узнать, каким доменным
 * именам соответствуют резолвленные IP-адреса (нужно для маршрутизации
 * по доменным правилам на уровне IP-пакетов, где имя хоста недоступно).
 */
public class DnsUtils {
    private static final int TYPE_A = 1;
    private static final int CLASS_IN = 1;
    private static final int MAX_POINTER_JUMPS = 20;

    public static class DnsAnswer {
        public final String queryName;
        public final List<String> addresses = new ArrayList<>();
        public long ttlSeconds = 60;

        DnsAnswer(String queryName) {
            this.queryName = queryName;
        }
    }

    /**
     * Читает 16-битный DNS transaction ID из заголовка (первые 2 байта),
     * используется и для запроса, и для ответа, чтобы убедиться, что ответ
     * соответствует именно отправленному запросу, а не подложен третьей стороной.
     */
    public static int readTransactionId(byte[] data, int length) {
        if (data == null || length < 2) return -1;
        return u16(data, 0);
    }

    /**
     * Возвращает разобранный ответ (имя запрошенного домена и, если есть,
     * резолвленные A-записи), если payload - валидный DNS-ответ с совпадающим
     * transaction ID, иначе null. addresses в результате может быть пустым
     * (CNAME-only ответ, NXDOMAIN и т.п.) - имя домена при этом всё равно
     * возвращается, чтобы сам факт обращения можно было залогировать.
     * expectedTransactionId должен совпадать с ID отправленного запроса -
     * это защищает от подмены ответа посторонним UDP-пакетом.
     */
    public static DnsAnswer parseResponse(byte[] data, int length, int expectedTransactionId) {
        try {
            if (length < 12) return null;
            if (expectedTransactionId < 0 || u16(data, 0) != expectedTransactionId) return null;

            int flags = u16(data, 2);
            boolean isResponse = (flags & 0x8000) != 0;
            if (!isResponse) return null;

            int qdCount = u16(data, 4);
            int anCount = u16(data, 6);
            if (qdCount != 1) return null;

            int[] offset = {12};
            String queryName = readName(data, length, offset);
            if (queryName == null || queryName.isEmpty()) return null;
            offset[0] += 4; // QTYPE + QCLASS

            DnsAnswer result = new DnsAnswer(queryName.toLowerCase());
            long minTtl = Long.MAX_VALUE;

            for (int i = 0; i < anCount; i++) {
                readName(data, length, offset); // имя записи (нам не важно)
                if (offset[0] + 10 > length) break;

                int type = u16(data, offset[0]);
                int cls = u16(data, offset[0] + 2);
                long ttl = u32(data, offset[0] + 4);
                int rdLength = u16(data, offset[0] + 8);
                offset[0] += 10;

                if (offset[0] + rdLength > length) break;

                if (type == TYPE_A && cls == CLASS_IN && rdLength == 4) {
                    byte[] addrBytes = new byte[4];
                    System.arraycopy(data, offset[0], addrBytes, 0, 4);
                    String ip = InetAddress.getByAddress(addrBytes).getHostAddress();
                    result.addresses.add(ip);
                    if (ttl < minTtl) minTtl = ttl;
                }

                offset[0] += rdLength;
            }

            // Возвращаем результат, даже если A-записей нет (CNAME-only ответ,
            // NXDOMAIN и т.п.) - имя запрошенного домена всё равно полезно
            // залогировать, просто без сопоставления с IP.
            result.ttlSeconds = (minTtl == Long.MAX_VALUE) ? 60 : minTtl;
            return result;

        } catch (Exception e) {
            return null;
        }
    }

    private static String readName(byte[] data, int length, int[] offsetHolder) {
        StringBuilder name = new StringBuilder();
        int offset = offsetHolder[0];
        boolean jumped = false;
        int jumps = 0;
        int afterPointerOffset = -1;

        while (offset < length) {
            int len = u8(data, offset);

            if (len == 0) {
                offset++;
                break;
            }

            if ((len & 0xC0) == 0xC0) {
                if (offset + 1 >= length) break;
                int pointer = ((len & 0x3F) << 8) | u8(data, offset + 1);
                if (!jumped) {
                    afterPointerOffset = offset + 2;
                }
                jumped = true;
                jumps++;
                if (jumps > MAX_POINTER_JUMPS || pointer >= length) break;
                offset = pointer;
                continue;
            }

            offset++;
            if (offset + len > length) break;
            if (name.length() > 0) name.append('.');
            name.append(new String(data, offset, len, StandardCharsets.US_ASCII));
            offset += len;
        }

        offsetHolder[0] = jumped ? afterPointerOffset : offset;
        return name.toString();
    }

    private static int u8(byte[] data, int index) {
        return data[index] & 0xFF;
    }

    private static int u16(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 2).getShort() & 0xFFFF;
    }

    private static long u32(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 4).getInt() & 0xFFFFFFFFL;
    }
}
