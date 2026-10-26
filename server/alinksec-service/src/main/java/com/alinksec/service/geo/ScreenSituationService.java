package com.alinksec.service.geo;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.query.AlertQueryService;
import com.alinksec.service.alert.SecurityEventTaxonomy;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;

@Service
public class ScreenSituationService {
    private final AlertQueryService alerts;
    private final GeoIpService geo;
    public ScreenSituationService(AlertQueryService alerts, GeoIpService geo) { this.alerts = alerts; this.geo = geo; }
    public Map<String, Object> snapshot() {
        @SuppressWarnings("unchecked") var rows = (List<Map<String, Object>>) alerts.list(null, null, null, null, 1, 20).get("list");
        var events = rows.stream().map(row -> {
            String source = "";
            String type = String.valueOf(row.get("event_type"));
            try { source = SecurityEventTaxonomy.sourceIp(type, JsonUtils.read(String.valueOf(row.get("detail")))); } catch (Exception ignored) {}
            String ip = row.get("host_ip") == null ? "" : row.get("host_ip").toString();
            return Map.of("id", row.get("id"), "network", SecurityEventTaxonomy.network(type),
                    "source", Map.of("ip", source, "location", source.isBlank() ? GeoIpService.state(SecurityEventTaxonomy.network(type) ? "source_missing" : "no_network_source") : geo.locate(source)),
                    "target", Map.of("agentId", String.valueOf(row.get("agent_id")), "ip", ip, "location", geo.asset(String.valueOf(row.get("agent_id")), ip)));
        }).toList();
        return Map.of("provider", geo.metadata().get("primary"), "providerInfo", geo.metadata(), "providerStatus", geo.status(), "events", events);
    }
}
