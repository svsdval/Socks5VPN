package com.example.socks5vpn;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AppRoutesActivity extends AppCompatActivity {

    private RecyclerView appsRecyclerView;
    private ProgressBar progressBar;
    private TextInputEditText searchEdit;
    private AppListAdapter adapter;
    private AppRuleManager appRuleManager;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_routes);

        appRuleManager = AppRuleManager.getInstance();
        appRuleManager.load(this);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        searchEdit = findViewById(R.id.searchEdit);
        progressBar = findViewById(R.id.progressBar);
        appsRecyclerView = findViewById(R.id.appsRecyclerView);
        appsRecyclerView.setLayoutManager(new LinearLayoutManager(this));

        MaterialButton saveButton = findViewById(R.id.saveButton);
        saveButton.setOnClickListener(v -> saveRules());

        loadInstalledApps();
    }

    private void loadInstalledApps() {
        progressBar.setVisibility(View.VISIBLE);

        executor.submit(() -> {
            PackageManager pm = getPackageManager();
            String selfPackage = getPackageName();
            List<ApplicationInfo> installed = pm.getInstalledApplications(PackageManager.GET_META_DATA);

            List<AppInfo> apps = new ArrayList<>();
            for (ApplicationInfo info : installed) {
                if (selfPackage.equals(info.packageName)) continue;

                String label = pm.getApplicationLabel(info).toString();
                RouteManager.RouteAction action = appRuleManager.getAppAction(info.packageName);
                apps.add(new AppInfo(info.packageName, label, pm.getApplicationIcon(info), action));
            }

            Collections.sort(apps, Comparator.comparing(a -> a.label.toLowerCase()));

            mainHandler.post(() -> {
                adapter = new AppListAdapter(apps);
                appsRecyclerView.setAdapter(adapter);
                progressBar.setVisibility(View.GONE);

                searchEdit.addTextChangedListener(new TextWatcher() {
                    @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
                    @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                        adapter.filter(s.toString());
                    }
                    @Override public void afterTextChanged(Editable s) {}
                });
            });
        });
    }

    private void saveRules() {
        if (adapter == null) return;

        for (AppInfo app : adapter.getAllApps()) {
            appRuleManager.setAppAction(app.packageName, app.action);
        }
        appRuleManager.save(this);

        Toast.makeText(this, "App rules saved", Toast.LENGTH_SHORT).show();
        finish();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
