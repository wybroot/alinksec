package com.alinksec.service.heartbeat;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.HostInfo;
import com.alinksec.proto.RptHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Heartbeat history is available in both SQLite and PostgreSQL deployments. */
@Service
public class HostRuntimeService {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    @Autowired
    public HostRuntimeService(JdbcTemplate jdbc) { this(jdbc, Clock.systemUTC()); }
    public HostRuntimeService(JdbcTemplate jdbc, Clock clock) { this.jdbc=jdbc; this.clock=clock; }

    public void heartbeat(String agent, RptHeartbeat hb) {
        long now=clock.millis(), bucket=now/60_000*60_000;
        // Legacy reports lack validity flags. Default zero is not a measured
        // zero; new Agents can explicitly report genuine idle samples.
        Double cpu=percent(hb.getCpuUsage(), hb.hasHost()?hb.getCpuUsageValid():hb.getCpuUsage()>0);
        Double memory=percent(hb.getMemUsage(), hb.hasHost()?hb.getMemUsageValid():hb.getMemUsage()>0);
        Long uptime=hb.getUptimeSec()>0 && hb.getUptimeSec()<3_155_760_000L?hb.getUptimeSec():null;
        String info=hb.hasHost()?JsonUtils.write(hardware(hb.getHost(),now)):null;
        jdbc.update("""
                INSERT INTO t_host_runtime(agent_id,sampled_at,cpu_percent,memory_percent,uptime_sec,host_info,host_info_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                sampled_at=EXCLUDED.sampled_at,cpu_percent=EXCLUDED.cpu_percent,memory_percent=EXCLUDED.memory_percent,
                uptime_sec=EXCLUDED.uptime_sec,host_info=COALESCE(EXCLUDED.host_info,t_host_runtime.host_info),
                host_info_at=COALESCE(EXCLUDED.host_info_at,t_host_runtime.host_info_at)
                """,agent,now,cpu,memory,uptime,info,info==null?null:now);
        jdbc.update("""
                INSERT INTO t_host_metric(agent_id,bucket,sampled_at,cpu_percent,memory_percent) VALUES(?,?,?,?,?)
                ON CONFLICT(agent_id,bucket) DO UPDATE SET sampled_at=EXCLUDED.sampled_at,
                cpu_percent=EXCLUDED.cpu_percent,memory_percent=EXCLUDED.memory_percent
                """,agent,bucket,now,cpu,memory);
        if (hb.hasHost()) {
            var h=hb.getHost();
            jdbc.update("""
                    UPDATE t_agent SET hostname=COALESCE(NULLIF(?,''),hostname),
                    os_version=COALESCE(NULLIF(?,''),os_version),kernel=COALESCE(NULLIF(?,''),kernel),
                    arch=COALESCE(NULLIF(?,''),arch) WHERE agent_id=?
                    """,text(h.getHostname()),text(h.getOsVersion()),text(h.getKernel()),text(h.getArch()),agent);
        }
    }

    public Map<String,Object> snapshot(String agent) {
        long now=clock.millis(), first=(now/60_000-59)*60_000;
        var result=new LinkedHashMap<String,Object>();
        var rows=jdbc.queryForList("SELECT * FROM t_host_runtime WHERE agent_id=?",agent);
        Map<String,Object> latest=rows.isEmpty()?new LinkedHashMap<>():rows.get(0);
        Object info=latest.remove("host_info");
        latest.put("host",info instanceof String value?JsonUtils.read(value):Map.of());
        latest.remove("agent_id");
        result.put("latest",latest);
        result.put("samples",jdbc.queryForList("SELECT bucket,sampled_at,cpu_percent,memory_percent FROM t_host_metric WHERE agent_id=? AND bucket>=? AND bucket<=? ORDER BY bucket LIMIT 60",agent,first,now));
        result.put("serverTime",now);result.put("source","heartbeat");result.put("retentionMinutes",60);
        return result;
    }

    // Also removes history for hosts that have gone offline.
    @Scheduled(fixedDelay=60_000,initialDelay=60_000)
    public void prune() { jdbc.update("DELETE FROM t_host_metric WHERE bucket<?",(clock.millis()/60_000-59)*60_000); }

    private static Double percent(float value,boolean valid) {
        return valid && Float.isFinite(value) && value>=0 && value<=100?(double)value:null;
    }
    private static String text(String value) { return value.length()>256?value.substring(0,256):value; }
    private static List<String> strings(List<String> values) { return values.stream().limit(64).map(HostRuntimeService::text).toList(); }
    private static Map<String,Object> hardware(HostInfo h,long now) {
        var result=new LinkedHashMap<String,Object>();
        result.put("cpu_model",text(h.getCpuModel()));
        result.put("logical_cpus",h.getLogicalCpus()>0 && h.getLogicalCpus()<=65536?h.getLogicalCpus():null);
        result.put("physical_cores",h.getPhysicalCores()>0 && h.getPhysicalCores()<=65536?h.getPhysicalCores():null);
        result.put("memory_total_bytes",h.getMemoryTotalBytes()>0?h.getMemoryTotalBytes():null);
        result.put("boot_time_sec",h.getBootTimeSec()>0 && h.getBootTimeSec()<=now/1000+300?h.getBootTimeSec():null);
        result.put("platform_family",text(h.getPlatformFamily()));
        result.put("virtualization_system",text(h.getVirtualizationSystem()));result.put("virtualization_role",text(h.getVirtualizationRole()));
        result.put("timezone",text(h.getTimezone()));result.put("ip_list",strings(h.getIpListList()));result.put("mac_list",strings(h.getMacListList()));
        return result;
    }
}
