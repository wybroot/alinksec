package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.library.*;
import com.alinksec.service.scan.VulnerabilityEvidence;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** The same authority, rollback and concurrent-client scenarios run on SQLite and PostgreSQL. */
class SourceTrustIntegrationTest {
    @TempDir Path root;
    LibraryGovernanceIntegrationTest f;
    String a,z,hash,rule;
    @BeforeEach void setup() throws Exception {
        f=new LibraryGovernanceIntegrationTest();f.root=root;f.setup();
        a=f.source("trust-a");z=f.source("trust-z");
        hash=VulnerabilityEvidence.sha256(UUID.randomUUID().toString());rule="Trust."+UUID.randomUUID();
    }
    @AfterEach void close() {
        if(f!=null && f.jdbc!=null) {
            for(String key:List.of(f.cve,hash,rule)) {
                f.jdbc.update("DELETE FROM t_security_selection_event WHERE item_key=?",key);
                f.jdbc.update("DELETE FROM t_security_item_decision WHERE item_key=?",key);
            }
            for(String source:f.sources) {
                f.jdbc.update("DELETE FROM t_security_source_policy WHERE source_id=?",source);
                f.jdbc.update("DELETE FROM t_security_selection_event WHERE kind='source' AND item_key=?",source);
            }
            f.close();
        }
    }
    JsonNode cve(String version) {
        return JsonUtils.read(JsonUtils.write(Map.of("cve_id",f.cve,"severity",3,"title","Declaration "+version,
                "affected",List.of(Map.of("name","trust-fixture","source","registry","os","windows","match","exact","vrange",version)))));
    }
    Map<String,Object> detail(String kind,String key) {return f.catalog.selectionDetail(kind,key);}
    Map<String,Object> current() {return f.jdbc.queryForMap("SELECT rule_source_id,rule_status,CAST(affected AS TEXT) AS affected,rule_digest,provenance FROM t_cve_db WHERE cve_id=?",f.cve);}
    void policy(String source,String tier,int priority,boolean quarantine)throws Exception {
        long revision=((Number)f.catalog.sourcePolicy(source).get("revision")).longValue();
        f.catalog.setSourcePolicy(source,tier,priority,quarantine,revision,f.actor,"Independent source review");
    }
    void decide(String kind,String key,String action,String source)throws Exception {
        var value=detail(kind,key);var decision=(Map<?,?>)value.get("decision");
        f.catalog.decideSelection(kind,key,action,source,value.get("contextDigest").toString(),((Number)decision.get("revision")).longValue(),f.actor,"Independent item review");
    }
    void conflict() {f.catalog.cves(a,List.of(cve("<2")),f.actor);f.catalog.cves(z,List.of(cve("<3")),f.actor);}
    SignaturePackage signature(String name,int severity,JsonNode...rules) {
        return new SignaturePackage("",Map.of(hash,SignaturePackage.checkedHash(hash,name,severity)),List.of(rules));
    }
    @Test void equalRankApplicabilityConflictHoldsWholeCveAndLiveAuthorization() {
        conflict();assertEquals("conflict",current().get("rule_status"));assertEquals("[]",current().get("affected"));
        assertEquals("unresolved_conflict",detail("cve",f.cve).get("reason"));
        assertFalse(new LibrarySelection(f.jdbc).allowsCve(f.cve,a,VulnerabilityEvidence.ruleDigest(a,f.cve,cve("<2").path("affected"))));
        assertEquals(2,f.catalog.declarations(f.cve).size());
    }
    @Test void metadataDifferencesDoNotMergeOrHoldIdenticalApplicability() {
        var one=cve("<2");var two=one.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)two).put("title","Different publisher title").put("severity",1);
        f.catalog.cves(a,List.of(one),f.actor);f.catalog.cves(z,List.of(two),f.actor);
        assertEquals("active",current().get("rule_status"));assertEquals(a,current().get("rule_source_id"));
        assertEquals(true,detail("cve",f.cve).get("documentConflict"));assertEquals(false,detail("cve",f.cve).get("applicabilityConflict"));
    }
    @Test void tierOutranksPriorityAndPriorityOutranksSourceId() throws Exception {
        conflict();policy(z,"reviewed",0,false);assertEquals(z,current().get("rule_source_id"));assertEquals("active",current().get("rule_status"));
        policy(a,"unreviewed",100,false);assertEquals(z,current().get("rule_source_id"));
        policy(a,"reviewed",10,false);assertEquals(a,current().get("rule_source_id"));
        assertEquals("<2",JsonUtils.read(current().get("affected").toString()).get(0).path("vrange").asText());
    }
    @Test void citationTextAndRuleOrderDifferencesAreNotApplicabilityConflicts() {
        var one=(com.fasterxml.jackson.databind.node.ObjectNode)cve("<2");
        var original=(com.fasterxml.jackson.databind.node.ObjectNode)one.path("affected").get(0);
        original.set("evidence",JsonUtils.read("{\"basis\":\"manual_analysis\",\"assessment\":\"affected\",\"package_scope\":\"binary\",\"notes\":\"First analyst note\"}"));
        var additional=original.deepCopy();additional.put("name","another-fixture");((com.fasterxml.jackson.databind.node.ArrayNode)one.path("affected")).add(additional);
        var two=one.deepCopy();var reordered=JsonUtils.mapper().createArrayNode();
        for(int i=1;i>=0;i--) {var item=(com.fasterxml.jackson.databind.node.ObjectNode)two.path("affected").get(i);((com.fasterxml.jackson.databind.node.ObjectNode)item.path("evidence")).put("notes","Other analyst note");reordered.add(item);}
        two.set("affected",reordered);f.catalog.cves(a,List.of(one),f.actor);f.catalog.cves(z,List.of(two),f.actor);
        assertEquals("active",current().get("rule_status"));assertEquals(true,detail("cve",f.cve).get("documentConflict"));assertEquals(false,detail("cve",f.cve).get("applicabilityConflict"));
    }
    @Test void explicitSelectionSurvivesIdenticalRefreshButContentChangeRequiresReview() throws Exception {
        conflict();decide("cve",f.cve,"select",z);assertEquals(z,current().get("rule_source_id"));
        String context=detail("cve",f.cve).get("contextDigest").toString();
        f.catalog.cves(a,List.of(cve("<2")),f.actor);assertEquals(context,detail("cve",f.cve).get("contextDigest"));assertEquals("active",current().get("rule_status"));
        f.catalog.cves(a,List.of(cve("<4")),f.actor);assertEquals("stale_decision",detail("cve",f.cve).get("reason"));assertEquals("review_required",current().get("rule_status"));
        assertFalse((Boolean)detail("cve",f.cve).get("effective"));decide("cve",f.cve,"select",z);assertEquals("active",current().get("rule_status"));
    }
    @Test void suppressionAndResetUseMonotonicRevisionsAndRejectStaleDigest() throws Exception {
        conflict();var before=detail("cve",f.cve);decide("cve",f.cve,"suppress","");assertEquals("suppressed",current().get("rule_status"));
        decide("cve",f.cve,"automatic","");assertEquals("unresolved_conflict",detail("cve",f.cve).get("reason"));
        assertThrows(IllegalArgumentException.class,()->f.catalog.decideSelection("cve",f.cve,"select",z,before.get("contextDigest").toString(),0L,f.actor,"Stale before reset"));
        assertEquals(2L,((Number)((Map<?,?>)detail("cve",f.cve).get("decision")).get("revision")).longValue());
        var value=detail("cve",f.cve);f.catalog.cves(z,List.of(cve("<5")),f.actor);
        assertThrows(IllegalArgumentException.class,()->f.catalog.decideSelection("cve",f.cve,"select",z,value.get("contextDigest").toString(),2L,f.actor,"Stale candidates"));
    }
    @Test void policyRevisionInvalidatesItemDecisionEvenWhenRankingIsUnchanged() throws Exception {
        conflict();decide("cve",f.cve,"select",z);policy(a,"unreviewed",1,false);
        assertEquals("stale_decision",detail("cve",f.cve).get("reason"));assertEquals("review_required",current().get("rule_status"));
    }
    @Test void quarantineRetainsAndAcceptsDeclarationsButCannotBeSelected() throws Exception {
        conflict();policy(z,"preferred",0,true);assertEquals(a,current().get("rule_source_id"));
        assertThrows(IllegalArgumentException.class,()->decide("cve",f.cve,"select",z));
        f.catalog.cves(z,List.of(cve("<7")),f.actor);assertEquals(2,f.catalog.declarations(f.cve).size());assertEquals(a,current().get("rule_source_id"));
        policy(a,"unreviewed",0,true);assertEquals("quarantined",current().get("rule_status"));assertEquals("[]",current().get("affected"));
        policy(z,"preferred",0,false);assertEquals(z,current().get("rule_source_id"));
    }
    @Test void firstDeclarationFromQuarantinedSourceIsVisibleButNeverMatchable() throws Exception {
        var configured=new LibraryProperties.Source();configured.setId(a);f.props.setSources(List.of(configured));
        policy(a,"reviewed",0,true);f.catalog.cves(a,List.of(cve("<2")),f.actor);
        assertEquals("quarantined",current().get("rule_status"));assertEquals("[]",current().get("affected"));assertEquals(false,detail("cve",f.cve).get("effective"));
    }
    @Test void selectedWithdrawalIsATombstoneRatherThanFallbackAuthority() throws Exception {
        conflict();decide("cve",f.cve,"select",a);
        f.catalog.decideCve(a,f.cve,true,f.digest(a),f.actor,"Withdraw chosen applicability");
        assertEquals("review_required",current().get("rule_status")); // The binding changed and must be explicitly reviewed again.
        decide("cve",f.cve,"select",a);assertEquals("withdrawn",current().get("rule_status"));assertEquals(a,current().get("rule_source_id"));
        decide("cve",f.cve,"automatic","");assertEquals("withdrawn",current().get("rule_status"));
        f.catalog.retire(a,f.actor,"Retire withdrawn provider");assertEquals(z,current().get("rule_source_id"));assertEquals("active",current().get("rule_status"));
    }
    @Test void selectedSourceRetirementRequiresNewItemReview() throws Exception {
        conflict();decide("cve",f.cve,"select",a);f.catalog.retire(a,f.actor,"Retire explicitly chosen provider");
        assertEquals("stale_decision",detail("cve",f.cve).get("reason"));assertEquals("review_required",current().get("rule_status"));
        decide("cve",f.cve,"automatic","");assertEquals(z,current().get("rule_source_id"));assertEquals("active",current().get("rule_status"));
    }
    @Test void legacyEffectiveCveCannotBypassNewConflictPolicyBeforeItsNextImport() {
        conflict();var affected=cve("<2").path("affected");String old=VulnerabilityEvidence.ruleDigest(a,f.cve,affected);
        f.jdbc.update("UPDATE t_cve_db SET affected=?,rule_source_id=?,rule_digest=?,provenance='{}',rule_status='active' WHERE cve_id=?",JsonUtils.write(affected),a,old,f.cve);
        assertFalse(new LibrarySelection(f.jdbc).allowsCve(f.cve,a,old));
        f.jdbc.update("DELETE FROM t_security_cve WHERE cve_id=?",f.cve);assertTrue(new LibrarySelection(f.jdbc).allowsCve(f.cve,a,old));
    }
    @Test void excessLegacyCandidatesRemainHeldWhileRetirementCanReduceTheSet() throws Exception {
        String serialized=VulnerabilityEvidence.canonicalJson(cve("<2"));
        for(int i=0;i<129;i++) {
            String source=f.source("legacy-"+i);
            f.jdbc.update("INSERT INTO t_security_cve(source_id,cve_id,document,provenance) VALUES (?,?,?,'{}')",source,f.cve,serialized);
        }
        assertEquals(129,detail("cve",f.cve).get("candidateCount"));assertEquals(false,detail("cve",f.cve).get("contextComplete"));
        assertEquals("candidate_capacity",detail("cve",f.cve).get("reason"));assertThrows(IllegalArgumentException.class,()->decide("cve",f.cve,"suppress",""));
        assertThrows(IllegalArgumentException.class,()->f.catalog.cves(a,List.of(cve("<2")),f.actor));
        f.catalog.retire(f.sources.get(2),f.actor,"Reduce oversized legacy set");assertEquals(128,detail("cve",f.cve).get("candidateCount"));
        assertEquals(true,detail("cve",f.cve).get("contextComplete"));assertEquals("active",current().get("rule_status"));
    }
    @Test void feedMetadataCannotAssignItsOwnSourceTrust() {
        var declaration=(com.fasterxml.jackson.databind.node.ObjectNode)cve("<2");
        declaration.put("trust_tier","preferred").put("priority",100).put("administrator_approved",true);
        f.catalog.cves(a,List.of(declaration),f.actor);
        assertEquals("unreviewed",f.catalog.sourcePolicy(a).get("tier"));assertEquals(0,f.catalog.sourcePolicy(a).get("priority"));
        assertEquals(0L,((Number)f.catalog.sourcePolicy(a).get("revision")).longValue());
    }
    @Test void hashMetadataDifferencesRemainVisibleAndPolicyRepublishes() throws Exception {
        f.catalog.signatures(a,signature("One",2),true,f.actor);f.catalog.signatures(z,signature("Two",4),true,f.actor);
        assertEquals(true,detail("hash",hash).get("effective"));assertEquals(true,detail("hash",hash).get("documentConflict"));
        String before=f.latest().get("db_version").toString();policy(z,"preferred",0,false);
        assertEquals(z,detail("hash",hash).get("selectedSource"));assertNotEquals(before,f.latest().get("db_version"));
        assertEquals("Two",((Map<?,?>)f.catalog.selectionCandidate("hash",hash,z).get("declaration")).get("name"));
    }
    @Test void conflictingBuiltinRulesAreHeldAndCanBeReviewedWithoutDroppingRawRows() throws Exception {
        var one=JsonUtils.read(JsonUtils.write(Map.of("name",rule,"type","path","pattern","/tmp/first","severity",2)));
        var two=one.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)two).put("pattern","/tmp/second");
        f.catalog.signatures(a,signature("Hash",3,one),true,f.actor);f.catalog.signatures(z,signature("Hash",3,two),true,f.actor);
        assertEquals("unresolved_conflict",detail("rule",rule).get("reason"));assertEquals(0,((Number)f.latest().get("rule_count")).intValue());
        decide("rule",rule,"select",z);assertEquals(1,((Number)f.latest().get("rule_count")).intValue());
        f.catalog.signatures(a,signature("Changed",3,two),true,f.actor);assertEquals("stale_decision",detail("rule",rule).get("reason"));
        assertEquals(2,f.jdbc.queryForObject("SELECT count(*) FROM t_security_rule WHERE name=?",Integer.class,rule));
    }
    @Test void quarantinedHashRefreshCanPublishDeliberatelyEmptyEffectiveRelease() throws Exception {
        f.catalog.signatures(a,signature("One",3),true,f.actor);policy(a,"reviewed",0,true);
        assertEquals(0,((Number)f.latest().get("hash_count")).intValue());
        f.catalog.signatures(a,signature("New.Untrusted.Name",4),true,f.actor);
        assertEquals(0,((Number)f.latest().get("hash_count")).intValue());assertEquals(1,f.jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Integer.class,a));
        policy(a,"reviewed",0,false);assertEquals(1,((Number)f.latest().get("hash_count")).intValue());
    }
    @Test void publicationFailureRollsBackPolicyAuditAndEffectiveAuthority() throws Exception {
        f.catalog.signatures(a,signature("One",3),true,f.actor);String before=f.latest().get("db_version").toString();f.props.getStorage().setBackend("s3");
        assertThrows(java.io.IOException.class,()->policy(a,"preferred",0,true));
        assertEquals(0L,((Number)f.catalog.sourcePolicy(a).get("revision")).longValue());assertEquals(before,f.latest().get("db_version"));
        assertEquals(0L,f.catalog.selectionHistory("source",a,1,20).get("total"));assertEquals(true,detail("hash",hash).get("effective"));
    }
    @Test void outerRollbackRemovesDecisionAuditAndCandidateArtifacts() throws Exception {
        f.catalog.signatures(a,signature("One",3),true,f.actor);String before=f.latest().get("db_version").toString();
        f.tx.executeWithoutResult(s->{try{decide("hash",hash,"suppress","");}catch(Exception e){throw new RuntimeException(e);}s.setRollbackOnly();});
        assertEquals(before,f.latest().get("db_version"));assertEquals(true,detail("hash",hash).get("effective"));
        assertEquals(0L,f.catalog.selectionHistory("hash",hash,1,20).get("total"));
        try(var paths=Files.list(root.resolve("signatures"))) {assertEquals(1,paths.count());}
    }
    @Test void demotedDisabledAndMissingActorsCannotChangeAuthority() throws Exception {
        conflict();f.jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name='operator') WHERE id=?",f.actor);
        assertThrows(IllegalArgumentException.class,()->policy(a,"preferred",0,false));assertThrows(IllegalArgumentException.class,()->decide("cve",f.cve,"select",a));
        f.jdbc.update("UPDATE t_user SET role_id=1,status=0 WHERE id=?",f.actor);
        assertThrows(IllegalArgumentException.class,()->policy(a,"preferred",0,false));
        assertThrows(IllegalArgumentException.class,()->f.catalog.setSourcePolicy(a,"preferred",0,false,0L,null,"No authenticated actor"));
        assertEquals(0L,f.catalog.selectionHistory("source",a,1,20).get("total"));
    }
    @Test void unknownRetiredAndMalformedPolicyInputsAreRejected() throws Exception {
        conflict();assertThrows(IllegalArgumentException.class,()->policy("unknown-provider","preferred",0,false));
        assertThrows(IllegalArgumentException.class,()->f.catalog.setSourcePolicy(a,"feed-claimed",0,false,0L,f.actor,"Invalid tier"));
        assertThrows(IllegalArgumentException.class,()->f.catalog.setSourcePolicy(a,"preferred",101,false,0L,f.actor,"Invalid priority"));
        f.catalog.retire(a,f.actor,"Retire provider");assertThrows(IllegalArgumentException.class,()->policy(a,"preferred",0,false));
        assertThrows(IllegalArgumentException.class,()->detail("hash","' OR 1=1"));assertThrows(IllegalArgumentException.class,()->detail("arbitrary_table",f.cve));
    }
    @Test void competingPolicyClientsCommitExactlyOneRevision() throws Exception {
        conflict();var other=new LibraryCatalog(f.jdbc,f.props,f.files,f.dialect,f.manager);
        var workers=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try {
            Callable<Boolean> first=()->{start.await();try{f.catalog.setSourcePolicy(a,"reviewed",1,false,0L,f.actor,"Concurrent first review");return true;}catch(IllegalArgumentException expected){return false;}};
            Callable<Boolean> second=()->{start.await();try{other.setSourcePolicy(a,"preferred",2,false,0L,f.actor,"Concurrent second review");return true;}catch(IllegalArgumentException expected){return false;}};
            var x=workers.submit(first);var y=workers.submit(second);start.countDown();assertNotEquals(x.get(10,TimeUnit.SECONDS),y.get(10,TimeUnit.SECONDS));
            assertEquals(1L,((Number)f.catalog.sourcePolicy(a).get("revision")).longValue());assertEquals(1L,f.catalog.selectionHistory("source",a,1,20).get("total"));
        } finally {workers.shutdownNow();assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS));}
    }
    @Test void capturedDeliveryAcknowledgementCannotClearNewerCommittedWork() throws Exception {
        f.catalog.signatures(a,signature("One",3),true,f.actor);var old=f.catalog.selectionDelivery();
        f.catalog.signatures(a,signature("Two",4),true,f.actor);conflict();
        f.catalog.acknowledgeSelectionDelivery(((Number)old.get("signature_release_id")).longValue(),((Number)old.get("rule_revision")).longValue(),true,true);
        assertEquals(1,((Number)f.catalog.selectionDelivery().get("signature_pending")).intValue());assertEquals(1,((Number)f.catalog.selectionDelivery().get("match_pending")).intValue());
    }
    @Test void failedDeliveryRemainsDurableAndRetriesWithoutConfiguredFeeds() throws Exception {
        f.catalog.signatures(a,signature("One",3),true,f.actor);conflict();
        var virus=mock(com.alinksec.service.virus.VirusDbService.class);var matcher=mock(com.alinksec.service.scan.VulnMatchService.class);
        doThrow(new IllegalStateException("fixture")).doNothing().when(virus).pushToAllAgents();
        doThrow(new IllegalStateException("fixture")).doNothing().when(matcher).matchAllForSelection();
        var sync=new LibrarySyncService(f.props,f.catalog,virus,mock(FeedDownload.class),f.jdbc,matcher,new LibrarySchedule(f.props,f.jdbc));
        try {
            sync.retrySelectionDelivery();assertEquals(1,((Number)f.catalog.selectionDelivery().get("signature_pending")).intValue());
            assertEquals(1,((Number)f.catalog.selectionDelivery().get("match_pending")).intValue());sync.scheduled();
            verify(virus,timeout(5000).times(2)).pushToAllAgents();verify(matcher,timeout(5000).times(2)).matchAllForSelection();
            // Wait for the acknowledgement after the mocked method returned, not merely its invocation.
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
            while(((Number)f.catalog.selectionDelivery().get("match_pending")).intValue()!=0 && System.nanoTime()<deadline)Thread.sleep(10);
            assertEquals(0,((Number)f.catalog.selectionDelivery().get("signature_pending")).intValue());assertEquals(0,((Number)f.catalog.selectionDelivery().get("match_pending")).intValue());
        } finally {sync.close();}
    }
    @Test void auditRetentionIsBoundedWithoutDeletingDecisionRevision() throws Exception {
        conflict();for(int i=0;i<53;i++)decide("cve",f.cve,i%2==0?"suppress":"automatic","");
        assertEquals(50L,f.catalog.selectionHistory("cve",f.cve,1,20).get("total"));assertEquals(20,((List<?>)f.catalog.selectionHistory("cve",f.cve,2,20).get("list")).size());
        assertEquals(53L,((Number)((Map<?,?>)detail("cve",f.cve).get("decision")).get("revision")).longValue());
    }
    @Test void captureActualConsolePolicyConflictAndStaleDecisionResponses() throws Exception {
        conflict();var stages=new LinkedHashMap<String,Object>();stages.put("conflict",snapshot());
        decide("cve",f.cve,"select",z);stages.put("reviewed",snapshot());f.catalog.cves(a,List.of(cve("<8")),f.actor);stages.put("stale",snapshot());
        decide("cve",f.cve,"suppress","");stages.put("suppressed",snapshot());policy(z,"preferred",50,true);stages.put("quarantined",snapshot());
        String output=System.getenv("ALINKSEC_SOURCE_TRUST_FIXTURES");
        if(output!=null && !output.isBlank()) {
            Path directory=Path.of(output);Files.createDirectories(directory);
            String database="postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite";
            Files.writeString(directory.resolve("console-"+database+".json"),JsonUtils.write(Map.of("database",database,"cve",f.cve,"a",a,"z",z,"stages",stages)));
        }
        assertEquals(5,stages.size());
    }
    Map<String,Object> snapshot() {
        var status=new LinkedHashMap<String,Object>();status.put("sources",List.of());status.put("signature",Map.of());status.put("storage","local");status.put("running",false);
        status.put("governanceSources",f.catalog.governanceSources().stream().filter(row->Set.of(a,z).contains(row.get("id"))).toList());status.put("selectionDelivery",f.catalog.selectionDelivery());
        return Map.of("status",status,"list",f.catalog.selections("cve",f.cve,true,1,20),"detail",detail("cve",f.cve),
                "candidateA",f.catalog.selectionCandidate("cve",f.cve,a),"candidateZ",f.catalog.selectionCandidate("cve",f.cve,z),
                "policyA",f.catalog.sourcePolicy(a),"policyZ",f.catalog.sourcePolicy(z),"history",f.catalog.selectionHistory("cve",f.cve,1,20),
                "policyHistory",f.catalog.selectionHistory("source",z,1,20));
    }
}
