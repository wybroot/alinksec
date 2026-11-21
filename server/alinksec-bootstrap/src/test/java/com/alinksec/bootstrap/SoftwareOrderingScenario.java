package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.config.*;
import com.alinksec.service.library.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import java.util.*;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

/** Shared ordinary/cluster acceptance input; all inventory and matching use production services. */
final class SoftwareOrderingScenario {
    static void verify(JdbcTemplate jdbc,PlatformTransactionManager manager,AlinkSecProperties app,
                       LibraryProperties libraries,String agent,long actor,Consumer<RptAssetSnapshot> receive) {
        String pkg="ordering-"+UUID.randomUUID(),cve="CVE-2099-"+String.format(Locale.ROOT,"%019d",UUID.randomUUID().getMostSignificantBits()>>>1);
        var catalog=new LibraryCatalog(jdbc,libraries,new LibraryFiles(libraries,app),new DatabaseDialect(app),manager);
        var rule=new LinkedHashMap<String,Object>(Map.of("name",pkg,"match","exact","source","dpkg","version_scheme","dpkg",
                "distro_id","ubuntu","distro_version","24.04","architecture","amd64","vrange","<2.0","fixed_version","2.0"));
        rule.put("evidence",Map.of("basis","manual_analysis","assessment","affected","package_scope","binary","notes","Isolated ordering fixture"));
        try {
            catalog.cves("manual",List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id",cve,"severity",3,"affected",List.of(rule))))),actor);
            // B is vulnerable; old A would incorrectly erase its finding if applied.
            receive.accept(snapshot(pkg,20,"1.5",1000));
            assertEquals("1.5",jdbc.queryForObject("SELECT version FROM t_asset_software WHERE agent_id=?",String.class,agent));
            assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND cve_id=? AND current_match=true AND installed_version='1.5'",Integer.class,agent,cve));
            var vulnerable=state(jdbc,agent);
            receive.accept(snapshot(pkg,10,"3.0",2000));receive.accept(snapshot(pkg,20,"1.5",1000));
            assertEquals(vulnerable,state(jdbc,agent));
            // A later category must not block a valid software sequence below its watermark.
            receive.accept(RptAssetSnapshot.newBuilder().setSequence(100).addCollected("processes")
                    .addCollections(AssetCollection.newBuilder().setCategory("processes").setStatus(AssetCollection.Status.COMPLETE).setCollectedAt(3000))
                    .addProcesses(ProcessInfo.newBuilder().setPid(4242).setName("ordering-process")).build());
            // Now B is safe, with its clock moving backwards. Old A must not revive a finding.
            receive.accept(snapshot(pkg,40,"3.0",500));
            assertEquals("3.0",jdbc.queryForObject("SELECT version FROM t_asset_software WHERE agent_id=?",String.class,agent));
            assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND cve_id=? AND current_match=true",Integer.class,agent,cve));
            var safe=state(jdbc,agent);
            receive.accept(snapshot(pkg,30,"1.0",4000));receive.accept(snapshot(pkg,40,"3.0",500));
            assertEquals(safe,state(jdbc,agent));
            assertEquals(40L,jdbc.queryForObject("SELECT sequence FROM t_asset_collection_state WHERE agent_id=? AND category='software'",Long.class,agent));
            assertEquals(500L,jdbc.queryForObject("SELECT collected_at FROM t_asset_collection_state WHERE agent_id=? AND category='software'",Long.class,agent));
            assertEquals(4242,jdbc.queryForObject("SELECT pid FROM t_asset_process WHERE agent_id=?",Integer.class,agent));
        }finally {
            for(String table:List.of("t_asset_software","t_asset_process","t_asset_collection_state"))jdbc.update("DELETE FROM "+table+" WHERE agent_id=?",agent);
            jdbc.update("DELETE FROM t_vuln_package_assessment WHERE agent_id=?",agent);
            jdbc.update("DELETE FROM t_vuln_coverage WHERE agent_id=?",agent);
            jdbc.update("DELETE FROM t_vuln_finding WHERE agent_id=? AND cve_id=?",agent,cve);
            jdbc.update("DELETE FROM t_security_cve WHERE cve_id=?",cve);jdbc.update("DELETE FROM t_cve_db WHERE cve_id=?",cve);
        }
    }
    private static RptAssetSnapshot snapshot(String pkg,long sequence,String version,long collectedAt) {
        return RptAssetSnapshot.newBuilder().setSequence(sequence).addCollected("software")
                .addCollections(AssetCollection.newBuilder().setCategory("software").setStatus(AssetCollection.Status.COMPLETE).setCollectedAt(collectedAt))
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE).setSource("dpkg").setDistroId("ubuntu").setDistroVersion("24.04").setPackageRepairContract(2))
                .addSoftware(SoftwareInfo.newBuilder().setName(pkg).setVersion(version).setSource("dpkg").setArchitecture("amd64")).build();
    }
    private static Map<String,Object> state(JdbcTemplate jdbc,String agent) {
        return Map.of("software",jdbc.queryForList("SELECT name,version,source,architecture FROM t_asset_software WHERE agent_id=?",agent),
                "host",jdbc.queryForMap("SELECT software_revision,software_collection_status,software_attempted_at,software_succeeded_at FROM t_agent WHERE agent_id=?",agent),
                "findings",jdbc.queryForList("SELECT id,status,current_match,installed_version,inventory_revision FROM t_vuln_finding WHERE agent_id=? ORDER BY id",agent),
                "coverage",jdbc.queryForList("SELECT * FROM t_vuln_coverage WHERE agent_id=?",agent),
                "assessment",jdbc.queryForList("SELECT * FROM t_vuln_package_assessment WHERE agent_id=? ORDER BY software,source,architecture",agent));
    }
}
