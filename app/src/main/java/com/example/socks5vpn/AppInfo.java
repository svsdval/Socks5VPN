package com.example.socks5vpn;

import android.graphics.drawable.Drawable;

/**
 * Элемент списка приложений на экране выбора правил маршрутизации.
 * action - текущий выбор пользователя (PROXY/BLOCK/DIRECT), меняется
 * адаптером при нажатии на чекбоксы и сохраняется целиком при нажатии Save.
 */
public class AppInfo {
    public final String packageName;
    public final String label;
    public final Drawable icon;
    public RouteManager.RouteAction action;

    public AppInfo(String packageName, String label, Drawable icon, RouteManager.RouteAction action) {
        this.packageName = packageName;
        this.label = label;
        this.icon = icon;
        this.action = action;
    }
}
