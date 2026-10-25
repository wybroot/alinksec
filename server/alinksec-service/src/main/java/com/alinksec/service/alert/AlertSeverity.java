package com.alinksec.service.alert;

import java.util.Map;

/** Raw event numbers remain immutable; the database view supplies display levels. */
public final class AlertSeverity {
    private AlertSeverity() { }

    public static String label(Map<String, Object> row) {
        int level = ((Number) row.get("severity_level")).intValue();
        String name = switch (level) {
            case 0 -> "信息";
            case 1 -> "低危";
            case 2 -> "中危";
            case 3 -> "高危";
            case 4 -> "严重";
            default -> "未知";
        };
        if ("legacy_unclassified".equals(row.get("severity_source"))) {
            int raw = ((Number) row.get("severity")).intValue();
            return (raw == 5 ? "危急" : name) + "（" + raw + "） · 历史记录，沿用旧含义";
        }
        return name + "（原值 " + row.get("severity") + "）";
    }
}
