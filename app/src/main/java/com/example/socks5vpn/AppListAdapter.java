package com.example.socks5vpn;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class AppListAdapter extends RecyclerView.Adapter<AppListAdapter.AppViewHolder> {

    private final List<AppInfo> allApps;
    private final List<AppInfo> filteredApps;

    public AppListAdapter(List<AppInfo> apps) {
        this.allApps = apps;
        this.filteredApps = new ArrayList<>(apps);
    }

    @NonNull
    @Override
    public AppViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_app_route, parent, false);
        return new AppViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull AppViewHolder holder, int position) {
        AppInfo app = filteredApps.get(position);

        holder.icon.setImageDrawable(app.icon);
        holder.name.setText(app.label);
        holder.packageName.setText(app.packageName);

        // Снимаем слушатели перед setChecked, чтобы переиспользование
        // ViewHolder при скролле не порождало ложных срабатываний.
        holder.proxyCheck.setOnCheckedChangeListener(null);
        holder.blockCheck.setOnCheckedChangeListener(null);

        holder.proxyCheck.setChecked(app.action == RouteManager.RouteAction.PROXY);
        holder.blockCheck.setChecked(app.action == RouteManager.RouteAction.BLOCK);

        holder.proxyCheck.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                app.action = RouteManager.RouteAction.PROXY;
                holder.blockCheck.setChecked(false);
            } else if (app.action == RouteManager.RouteAction.PROXY) {
                app.action = RouteManager.RouteAction.DIRECT;
            }
        });

        holder.blockCheck.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                app.action = RouteManager.RouteAction.BLOCK;
                holder.proxyCheck.setChecked(false);
            } else if (app.action == RouteManager.RouteAction.BLOCK) {
                app.action = RouteManager.RouteAction.DIRECT;
            }
        });
    }

    @Override
    public int getItemCount() {
        return filteredApps.size();
    }

    public void filter(String query) {
        String q = query.toLowerCase().trim();
        filteredApps.clear();
        if (q.isEmpty()) {
            filteredApps.addAll(allApps);
        } else {
            for (AppInfo app : allApps) {
                if (app.label.toLowerCase().contains(q) || app.packageName.toLowerCase().contains(q)) {
                    filteredApps.add(app);
                }
            }
        }
        notifyDataSetChanged();
    }

    public List<AppInfo> getAllApps() {
        return allApps;
    }

    static class AppViewHolder extends RecyclerView.ViewHolder {
        ImageView icon;
        TextView name;
        TextView packageName;
        CheckBox proxyCheck;
        CheckBox blockCheck;

        AppViewHolder(View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.appIcon);
            name = itemView.findViewById(R.id.appName);
            packageName = itemView.findViewById(R.id.appPackage);
            proxyCheck = itemView.findViewById(R.id.proxyCheck);
            blockCheck = itemView.findViewById(R.id.blockCheck);
        }
    }
}
