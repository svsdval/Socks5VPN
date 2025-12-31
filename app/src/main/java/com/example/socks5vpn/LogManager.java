package com.example.socks5vpn;

import android.os.Handler;
import android.os.Looper;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

public class LogManager {
    private static final int MAX_LOGS = 500;
    private static LogManager instance;
    
    private final CopyOnWriteArrayList<LogEntry> logs = new CopyOnWriteArrayList<>();
    private final List<LogListener> listeners = new ArrayList<>();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
    
    public enum LogLevel {
        DEBUG("D", 0xFF888888),
        INFO("I", 0xFF2196F3),
        WARNING("W", 0xFFFF9800),
        ERROR("E", 0xFFF44336),
        PROXY("P", 0xFF4CAF50),
        DIRECT("→", 0xFF9C27B0),
        BLOCK("✕", 0xFFE91E63);
        
        public final String symbol;
        public final int color;
        
        LogLevel(String symbol, int color) {
            this.symbol = symbol;
            this.color = color;
        }
    }
    
    public static class LogEntry {
        public final long timestamp;
        public final LogLevel level;
        public final String tag;
        public final String message;
        
        public LogEntry(LogLevel level, String tag, String message) {
            this.timestamp = System.currentTimeMillis();
            this.level = level;
            this.tag = tag;
            this.message = message;
        }
    }
    
    public interface LogListener {
        void onLogAdded(LogEntry entry);
    }
    
    public static synchronized LogManager getInstance() {
        if (instance == null) {
            instance = new LogManager();
        }
        return instance;
    }
    
    private LogManager() {}
    
    public void log(LogLevel level, String tag, String message) {
        LogEntry entry = new LogEntry(level, tag, message);
        
        logs.add(entry);
        
        // Ограничиваем размер
        while (logs.size() > MAX_LOGS) {
            logs.remove(0);
        }
        
        // Уведомляем слушателей в main thread
        mainHandler.post(() -> {
            for (LogListener listener : listeners) {
                listener.onLogAdded(entry);
            }
        });
    }
    
    public void d(String tag, String message) {
        log(LogLevel.DEBUG, tag, message);
    }
    
    public void i(String tag, String message) {
        log(LogLevel.INFO, tag, message);
    }
    
    public void w(String tag, String message) {
        log(LogLevel.WARNING, tag, message);
    }
    
    public void e(String tag, String message) {
        log(LogLevel.ERROR, tag, message);
    }
    
    public void proxy(String tag, String message) {
        log(LogLevel.PROXY, tag, message);
    }
    
    public void direct(String tag, String message) {
        log(LogLevel.DIRECT, tag, message);
    }
    
    public void block(String tag, String message) {
        log(LogLevel.BLOCK, tag, message);
    }
    
    public List<LogEntry> getLogs() {
        return new ArrayList<>(logs);
    }
    
    public void clear() {
        logs.clear();
        mainHandler.post(() -> {
            for (LogListener listener : listeners) {
                listener.onLogAdded(null); // Signal to clear
            }
        });
    }
    
    public void addListener(LogListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
    
    public void removeListener(LogListener listener) {
        listeners.remove(listener);
    }
    
    public String formatTime(long timestamp) {
        return timeFormat.format(new Date(timestamp));
    }
}