package com.example.socks5vpn;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class LogAdapter extends RecyclerView.Adapter<LogAdapter.LogViewHolder> {
    
    private final List<LogManager.LogEntry> logs = new ArrayList<>();
    private final LogManager logManager = LogManager.getInstance();
    
    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
            .inflate(R.layout.item_log, parent, false);
        return new LogViewHolder(view);
    }
    
    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        LogManager.LogEntry entry = logs.get(position);
        
        String time = logManager.formatTime(entry.timestamp);
        String text = time + " [" + entry.level.symbol + "] " + entry.tag + ": " + entry.message;
        
        holder.logText.setText(text);
        holder.logText.setTextColor(entry.level.color);
    }
    
    @Override
    public int getItemCount() {
        return logs.size();
    }
    
    public void addLog(LogManager.LogEntry entry) {
        logs.add(entry);
        // Ограничиваем размер
        while (logs.size() > 200) {
            logs.remove(0);
        }
        notifyDataSetChanged();
    }
    
    public void setLogs(List<LogManager.LogEntry> newLogs) {
        logs.clear();
        logs.addAll(newLogs);
        notifyDataSetChanged();
    }
    
    public void clear() {
        logs.clear();
        notifyDataSetChanged();
    }
    
    static class LogViewHolder extends RecyclerView.ViewHolder {
        TextView logText;
        
        LogViewHolder(View itemView) {
            super(itemView);
            logText = itemView.findViewById(R.id.logText);
        }
    }
}