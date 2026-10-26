package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.service.heartbeat.HostRuntimeService;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.alert.SecurityEventService;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/** Actual migration/storage tests, including legacy Agents and offline retention. */
class HostRuntimeIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource source;
    JdbcTemplate jdbc;
    long now=Instant.parse("2026-10-26T00:00:00Z").toEpochMilli();
    @BeforeEach void setup() throws Exception {
        source=new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:"+root.resolve("host.db")),true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(source,"dataSource");
        jdbc=new JdbcTemplate(source);
        for(String id:List.of("host-a","host-b")) jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type) VALUES(?,?,1)",id,id);
    }
    @AfterEach void close() { source.destroy(); }
    HostRuntimeService service(long millis) { return new HostRuntimeService(jdbc,Clock.fixed(Instant.ofEpochMilli(millis),ZoneOffset.UTC)); }
    RptHeartbeat measured() {
        return RptHeartbeat.newBuilder().setCpuUsage(0).setCpuUsageValid(true).setMemUsage(37.5f).setMemUsageValid(true).setUptimeSec(4321)
                .setHost(HostInfo.newBuilder().setHostname("real-host").setKernel("6.8.0-test").setCpuModel("Measured CPU")
                    .setLogicalCpus(4).setPhysicalCores(2).setMemoryTotalBytes(8L<<30).setBootTimeSec(now/1000-4321)
                    .addIpList("192.0.2.10").addMacList("02:00:00:00:00:01")).build();
    }
    @SuppressWarnings("unchecked")
    @Test void measuredIdleAndHardwareSurviveStorageAndRefreshIdentity() {
        service(now).heartbeat("host-a",measured());
        var snapshot=service(now).snapshot("host-a");
        var latest=(Map<String,Object>)snapshot.get("latest");
        assertEquals(0,((Number)latest.get("cpu_percent")).doubleValue());
        assertEquals(37.5,((Number)latest.get("memory_percent")).doubleValue());
        assertEquals(4321,((Number)latest.get("uptime_sec")).longValue());
        assertEquals("Measured CPU",((JsonNode)latest.get("host")).path("cpu_model").asText());
        assertEquals("6.8.0-test",jdbc.queryForObject("SELECT kernel FROM t_agent WHERE agent_id='host-a'",String.class));
        assertEquals("real-host",jdbc.queryForObject("SELECT hostname FROM t_agent WHERE agent_id='host-a'",String.class));
        assertEquals(1,((List<?>)snapshot.get("samples")).size());
        assertTrue(((List<?>)service(now).snapshot("host-b").get("samples")).isEmpty());
    }
    @Test void unknownAndInvalidValuesNeverBecomeIdleOrEraseKnownHardware() {
        service(now).heartbeat("host-a",measured());
        service(now+10000).heartbeat("host-a",RptHeartbeat.getDefaultInstance());
        var row=jdbc.queryForMap("SELECT * FROM t_host_runtime WHERE agent_id='host-a'");
        assertNull(row.get("cpu_percent"));assertNull(row.get("memory_percent"));
        assertTrue(row.get("host_info").toString().contains("Measured CPU"));
        service(now+20000).heartbeat("host-a",measured().toBuilder().setCpuUsage(Float.NaN).setMemUsage(101).build());
        row=jdbc.queryForMap("SELECT * FROM t_host_runtime WHERE agent_id='host-a'");
        assertNull(row.get("cpu_percent"));assertNull(row.get("memory_percent"));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM t_host_metric",Integer.class));
    }
    @Test void minuteBucketsAreBoundedAndOfflineHostsArePruned() {
        for(int n=0;n<6;n++) service(now+n*1000).heartbeat("host-a",measured());
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM t_host_metric",Integer.class));
        service(now+120*60000).heartbeat("host-b",measured());
        service(now+120*60000).prune();
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM t_host_metric WHERE agent_id='host-a'",Integer.class));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM t_host_metric WHERE agent_id='host-b'",Integer.class));
        assertEquals(2,jdbc.queryForObject("SELECT COUNT(*) FROM t_host_runtime",Integer.class));
    }
    @Test void targetedDiskSnapshotsPreserveOtherAssetsAndAreExposedInHostDetails() {
        var assets=new AssetService(jdbc,mock(VulnMatchService.class),mock(SecurityEventService.class));
        var disk=DiskInfo.newBuilder().setMount("/").setFsType("ext4").setTotalBytes(1000).setUsedBytes(400);
        assets.replaceSnapshot("host-a",RptAssetSnapshot.newBuilder().addCollected("disks").addDisks(disk).build());
        assets.replaceSnapshot("host-a",RptAssetSnapshot.newBuilder().addCollected("ports").addPorts(PortInfo.newBuilder().setPort(443)).build());
        var detail=new com.alinksec.service.query.HostQueryService(jdbc).detail("host-a");
        assertEquals(1,((List<?>)detail.get("disks")).size());
        assets.replaceSnapshot("host-a",RptAssetSnapshot.newBuilder().addCollected("disks").addDisks(disk.setUsedBytes(600)).build());
        assertEquals(600,jdbc.queryForObject("SELECT used_bytes FROM t_asset_disk",Long.class));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM t_asset_port",Integer.class));
        assets.replaceSnapshot("host-a",RptAssetSnapshot.newBuilder().addCollected("disks").build());
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM t_asset_disk",Integer.class));
    }
}
