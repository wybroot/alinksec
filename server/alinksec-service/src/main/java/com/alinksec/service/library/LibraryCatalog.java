package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.scan.VulnerabilityScope;
import com.alinksec.service.scan.VulnerabilityEvidence;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.zip.*;

/** Source rows and the published version commit together; failed candidates keep the last good release. */
@Service
public class LibraryCatalog {
    private final JdbcTemplate jdbc;
    private final LibraryProperties props;
    private final LibraryFiles files;
    private final DatabaseDialect database;
    private final TransactionTemplate transaction;
    private final LibrarySelection selection;
    public LibraryCatalog(JdbcTemplate jdbc, LibraryProperties props, LibraryFiles files,
                          DatabaseDialect database, PlatformTransactionManager manager) {
        this.jdbc = jdbc; this.props = props; this.files = files; this.database = database;
        transaction = new TransactionTemplate(manager);
        selection = new LibrarySelection(jdbc);
    }
    public synchronized Map<String, Object> signatures(String source, SignaturePackage pkg, boolean replace, Long actor) throws IOException {
        return storeSignatures(source,pkg,replace,actor,false);
    }
    /** Only the native complete-collection/known-expiry path may publish an empty effective snapshot. */
    synchronized Map<String,Object> nativeSignatures(String source,SignaturePackage pkg)throws IOException {
        return storeSignatures(source,pkg,true,null,true);
    }
    private Map<String,Object> storeSignatures(String source,SignaturePackage pkg,boolean replace,Long actor,boolean allowEmpty)throws IOException {
        if(!allowEmpty && pkg.hashes().isEmpty() && pkg.rules().isEmpty())throw new IllegalArgumentException("拒绝导入空特征库");
        try {
            return transaction.execute(status -> {
                try {
                    lockActiveSource(source);
                    lockSignatureRelease();
                    adoptLegacySignature("manual".equals(source) && replace);
                    if (replace) {
                        jdbc.update("DELETE FROM t_security_hash WHERE source_id = ?", source);
                        jdbc.update("DELETE FROM t_security_rule WHERE source_id = ?", source);
                    }
                    jdbc.batchUpdate("""
                            INSERT INTO t_security_hash(source_id,sha256,name,severity) VALUES (?,?,?,?)
                            ON CONFLICT(source_id,sha256) DO UPDATE SET name=EXCLUDED.name,severity=EXCLUDED.severity
                            """, pkg.hashes().values(), 500, (stmt, hash) -> {
                        stmt.setString(1, source); stmt.setString(2, hash.sha256()); stmt.setString(3, hash.name()); stmt.setInt(4, hash.severity());
                    });
                    for (JsonNode rule : pkg.rules()) jdbc.update("""
                            INSERT INTO t_security_rule(source_id,name,document) VALUES (?,?,?)
                            ON CONFLICT(source_id,name) DO UPDATE SET document=EXCLUDED.document
                            """, source, rule.path("name").asText(), JsonUtils.write(rule));
                    return publishSignatures(actor, "manual".equals(source) ? pkg.version() : "", allowEmpty,true);
                } catch (IOException e) { throw new UncheckedIOException(e); }
            });
        } catch (UncheckedIOException e) { throw e.getCause(); }
    }
    private void adoptLegacySignature(boolean replacingManual) throws IOException {
        if (jdbc.queryForObject("SELECT count(*) FROM t_security_feed_state WHERE source_id = '_legacy-signature'", Integer.class) > 0) return;
        var latest = jdbc.queryForList("SELECT package_key FROM t_virus_db ORDER BY id DESC LIMIT 1");
        if (!replacingManual && !latest.isEmpty()) {
            Path tmp = files.temporary(".zip");
            try {
                files.copyTo("signature", (String) latest.get(0).get("package_key"), tmp);
                SignaturePackage old = SignaturePackage.read(tmp, props);
                // Existing imported data becomes the manual source, so remote updates cannot erase it.
                jdbc.batchUpdate("INSERT INTO t_security_hash(source_id,sha256,name,severity) VALUES ('manual',?,?,?) ON CONFLICT DO NOTHING",
                        old.hashes().values(), 500, (stmt, hash) -> { stmt.setString(1, hash.sha256()); stmt.setString(2, hash.name()); stmt.setInt(3, hash.severity()); });
                for (JsonNode rule : old.rules()) jdbc.update("INSERT INTO t_security_rule(source_id,name,document) VALUES ('manual',?,?) ON CONFLICT DO NOTHING", rule.path("name").asText(), JsonUtils.write(rule));
            } finally { Files.deleteIfExists(tmp); }
        }
        jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,status) VALUES ('_legacy-signature','internal','success')");
    }
    private Map<String, Object> publishSignatures(Long actor, String proposedVersion, boolean allowEmpty) throws IOException {
        return publishSignatures(actor,proposedVersion,allowEmpty,false);
    }
    private Map<String, Object> publishSignatures(Long actor, String proposedVersion, boolean allowEmpty,boolean rejectExcessCandidates) throws IOException {
        Path hashes = files.temporary(".txt"), rules = files.temporary(".json"), zip = files.temporary(".zip");
        try {
            int[] selectedHashes={0},candidateGroups={0};
            try (BufferedWriter writer = Files.newBufferedWriter(hashes, StandardCharsets.UTF_8)) {
                selection.each("hash",choice -> {
                    if(rejectExcessCandidates && !choice.contextComplete())throw new IllegalArgumentException("单条情报当前来源超过128个，请先退役多余来源");
                    candidateGroups[0]++;
                    if(!choice.effective())return;
                    if(++selectedHashes[0]>props.getMaxHashes())throw new IllegalArgumentException("合并哈希库超过容量上限，已有库保留");
                    var row=choice.proposed();
                    try { writer.write(row.get("sha256")+" "+row.get("name")+" "+row.get("severity")+"\n"); }
                    catch (IOException e) { throw new UncheckedIOException(e); }
                });
            }
            int hashCount=selectedHashes[0];
            var ruleRows=new ArrayList<JsonNode>();long[] ruleBytes={0};
            selection.each("rule",choice -> {
                if(rejectExcessCandidates && !choice.contextComplete())throw new IllegalArgumentException("单条情报当前来源超过128个，请先退役多余来源");
                candidateGroups[0]++;
                if(!choice.effective())return;
                String document=choice.proposed().get("document").toString();
                ruleBytes[0]+=document.getBytes(StandardCharsets.UTF_8).length;
                if(ruleRows.size()>=2000 || ruleBytes[0]>2L<<20)throw new IllegalArgumentException("合并规则数量或内容超过上限");
                ruleRows.add(JsonUtils.read(document));
            });
            ruleRows.sort(Comparator.comparing(node->node.path("name").asText()));
            Files.writeString(rules, JsonUtils.write(Map.of("rules",ruleRows)));
            if(Files.size(rules)>2L<<20 || Files.size(hashes)+Files.size(rules)>(64L<<20)-(64L<<10)) throw new IllegalArgumentException("合并特征超过Agent规则或解压容量，保留原版本");
            if (!allowEmpty && candidateGroups[0]==0) throw new IllegalArgumentException("拒绝发布空特征库");
            String fingerprint = SignaturePackage.sha256(hashes) + SignaturePackage.sha256(rules);
            var state = jdbc.queryForList("SELECT cursor,version FROM t_security_feed_state WHERE source_id = '_signature-release'");
            if (!state.isEmpty() && fingerprint.equals(state.get(0).get("cursor"))) {
                return Map.of("dbVersion", state.get(0).get("version"), "hashCount", hashCount, "ruleCount", ruleRows.size(), "changed", false);
            }
            String version = proposedVersion;
            if (version.isBlank() || jdbc.queryForObject("SELECT count(*) FROM t_virus_db WHERE db_version=?", Integer.class, version) > 0) {
                version = "lib-" + Long.toString(System.currentTimeMillis(), 36) + "-" + UUID.randomUUID().toString().substring(0, 8);
            }
            try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(zip))) {
                out.putNextEntry(new ZipEntry("manifest.json"));
                out.write(JsonUtils.write(Map.of("db_version", version, "hash_count", hashCount, "rule_count", ruleRows.size())).getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
                for (var entry : Map.of("hashes.txt", hashes, "rules.json", rules).entrySet()) {
                    out.putNextEntry(new ZipEntry(entry.getKey())); Files.copy(entry.getValue(), out); out.closeEntry();
                }
            }
            if (Files.size(zip)>(20L<<20)) throw new IllegalArgumentException("压缩特征包超过Agent的20MiB上限，保留原版本");
            String content=SignatureDelta.identity(zip).digest();
            var previous=jdbc.queryForList("SELECT db_version,package_key,sha256 FROM t_virus_db ORDER BY id DESC LIMIT 1");
            String key = version + ".zip";
            files.put("signature", key, zip);
            List<String> publishedKeys=new ArrayList<>(); publishedKeys.add(key);
            org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        @Override public void afterCompletion(int status) {
                            if (status!=STATUS_COMMITTED) for (String candidate:publishedKeys) try { files.delete("signature",candidate); }
                            catch (IOException e) { org.slf4j.LoggerFactory.getLogger(LibraryCatalog.class).warn("Unreferenced signature candidate cleanup deferred"); }
                        }
                    });
            DeltaPublication delta=prepareDelta(previous,zip,version);
            if (!delta.key().isEmpty()) publishedKeys.add(delta.key());
            jdbc.update("""
                    INSERT INTO t_virus_db(db_version,package_key,sha256,size,hash_count,rule_count,imported_by,
                      content_sha256,delta_base_version,delta_base_content_sha256,delta_key,delta_sha256,delta_size)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, version, key, SignaturePackage.sha256(zip), Files.size(zip), hashCount, ruleRows.size(), actor,
                    content,delta.baseVersion(),delta.baseContent(),delta.key(),delta.sha256(),delta.size());
            jdbc.update("""
                    INSERT INTO t_security_feed_state(source_id,kind,status,cursor,version,entry_count,success_at)
                    VALUES ('_signature-release','internal','success',?,?,?,?)
                    ON CONFLICT(source_id) DO UPDATE SET cursor=EXCLUDED.cursor,version=EXCLUDED.version,
                    entry_count=EXCLUDED.entry_count,success_at=EXCLUDED.success_at
                    """, fingerprint, version, hashCount, Instant.now().toString());
            jdbc.update("UPDATE t_security_selection_delivery SET signature_release_id=(SELECT MAX(id) FROM t_virus_db),signature_pending=1 WHERE id=1");
            return Map.of("dbVersion", version, "hashCount", hashCount, "ruleCount", ruleRows.size(), "changed", true);
        } finally { Files.deleteIfExists(hashes); Files.deleteIfExists(rules); Files.deleteIfExists(zip); }
    }
    private record DeltaPublication(String baseVersion,String baseContent,String key,String sha256,long size) {
        static DeltaPublication none() { return new DeltaPublication("","","","",0); }
    }
    private DeltaPublication prepareDelta(List<Map<String,Object>> previous,Path target,String version) {
        if (previous.isEmpty()) return DeltaPublication.none();
        Path base=null,patch=null;
        try {
            base=files.temporary(".zip"); patch=files.temporary(".zip");
            var row=previous.get(0);
            var download=files.download("signature",String.valueOf(row.get("package_key")));
            if (download==null) return DeltaPublication.none();
            try (var in=download.resource().getInputStream(); var out=Files.newOutputStream(base)) {
                if (download.size()>(20L<<20)) return DeltaPublication.none();
                byte[] buffer=new byte[8192]; long count=0; int n;
                while ((n=in.read(buffer))!=-1) { count+=n; if (count>(20L<<20)) throw new IOException("Base exceeds limits"); out.write(buffer,0,n); }
            }
            if (!SignaturePackage.sha256(base).equals(row.get("sha256"))) throw new IOException("Base package digest mismatch");
            var difference=SignatureDelta.build(base,target,patch,props.getMaxHashes());
            if (!difference.base().version().equals(row.get("db_version"))) throw new IOException("Base package version mismatch");
            long size=Files.size(patch),full=Files.size(target);
            if (size*5>=full*4 || full-size<256) return DeltaPublication.none();
            String key=version+".delta.zip";
            String digest=SignaturePackage.sha256(patch);
            files.put("signature",key,patch);
            return new DeltaPublication(difference.base().version(),difference.base().digest(),key,digest,size);
        } catch (IOException | IllegalArgumentException e) {
            org.slf4j.LoggerFactory.getLogger(LibraryCatalog.class).warn("Optional signature delta unavailable; publishing complete release: {}",e.getClass().getSimpleName());
            return DeltaPublication.none();
        } finally {
            for (Path path:new Path[]{base,patch}) if (path!=null) try { Files.deleteIfExists(path); }
            catch (IOException e) { org.slf4j.LoggerFactory.getLogger(LibraryCatalog.class).warn("Signature delta temporary cleanup deferred"); }
        }
    }
    public synchronized int cves(String source, List<JsonNode> documents) {
        return cves(source, documents, null);
    }
    public synchronized int cves(String source, List<JsonNode> documents, Long actor) {
        return storeCves(source, documents, actor, Map.of());
    }
    /** Native transport facts are server-generated and cannot be supplied by a manual import. */
    synchronized int nativeCves(String source, List<JsonNode> documents, Map<String,Object> nativeProvenance) {
        return storeCves(source, documents, null, nativeProvenance);
    }
    synchronized <T> T nativeTransaction(String source, java.util.function.Supplier<T> action) {
        return transaction.execute(status -> { lockActiveSource(source); return action.get(); });
    }
    void nativeIndicatorEvent(String source,String operation,Map<String,Object> snapshot) {
        if(!Set.of("opencti_snapshot","opencti_expiry").contains(operation))throw new IllegalArgumentException("原生指标审计类型非法");
        String document=JsonUtils.write(snapshot);
        if(document.getBytes(StandardCharsets.UTF_8).length>64*1024)throw new IllegalArgumentException("原生指标审计超过边界");
        event(source,"",operation,null,"",document,snapshot);
        jdbc.update("""
                DELETE FROM t_security_governance_event WHERE source_id=? AND operation IN ('opencti_snapshot','opencti_expiry')
                AND id NOT IN (SELECT id FROM t_security_governance_event WHERE source_id=?
                    AND operation IN ('opencti_snapshot','opencti_expiry') ORDER BY recorded_at DESC,id DESC LIMIT 50)
                """,source,source);
    }
    private int storeCves(String source, List<JsonNode> documents, Long actor, Map<String,Object> nativeProvenance) {
        if (source == null || !source.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("规则导入来源非法");
        if (documents.size() > props.getMaxCvesPerImport()) throw new IllegalArgumentException("漏洞数据超过单次导入上限");
        var ids = new HashSet<String>();
        for (JsonNode document : documents) {
            validateCve(document);
            if (!ids.add(document.path("cve_id").asText())) throw new IllegalArgumentException("同一导入批次不能重复 CVE");
        }
        return transaction.execute(status -> {
            lockActiveSource(source);
            for (JsonNode document : documents) {
                String id = document.path("cve_id").asText();
                for (JsonNode rule : document.path("affected")) {
                    if (!rule.has("match")) ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("match", "exact");
                }
                String serialized = VulnerabilityEvidence.canonicalJson(document);
                if (serialized.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256 * 1024)
                    throw new IllegalArgumentException("单条公告原文超过 256 KiB 上限");
                Map<String, Object> provenance = new LinkedHashMap<>();
                provenance.put("source_id", source);
                provenance.put("ingestion", "manual".equals(source) ? "manual_import" : "configured_import");
                provenance.put("document_sha256", VulnerabilityEvidence.sha256(serialized));
                provenance.put("recorded_at", Instant.now().toString());
                provenance.put("imported_by", actor);
                provenance.put("verification", "imported_declaration");
                if (!nativeProvenance.isEmpty()) {
                    provenance.putAll(nativeProvenance);
                    provenance.put("ingestion", "native_vendor_advisory");
                    provenance.put("verification", "parsed_transport_document");
                }
                var old = jdbc.queryForList("SELECT document,provenance FROM t_security_cve WHERE source_id=? AND cve_id=?", source, id);
                if (old.isEmpty() || !serialized.equals(old.get(0).get("document"))
                        || !nativeProvenance.isEmpty() && !JsonUtils.read(old.get(0).get("provenance").toString()).path("raw_documents")
                                .equals(JsonUtils.mapper().valueToTree(nativeProvenance.get("raw_documents"))))
                    event(source, id, "import", actor, document.path("withdrawal_reason").asText(""), serialized, provenance);
                jdbc.update("""
                        INSERT INTO t_security_cve(source_id,cve_id,document,matchable,provenance) VALUES (?,?,?,?,?)
                        ON CONFLICT(source_id,cve_id) DO UPDATE SET document=EXCLUDED.document,matchable=EXCLUDED.matchable,provenance=EXCLUDED.provenance
                        """, source, id, serialized, hasComparableRules(document) ? 1 : 0, JsonUtils.write(provenance));
                if(jdbc.queryForObject("SELECT count(*) FROM t_security_cve c LEFT JOIN t_security_source_lifecycle l ON l.source_id=c.source_id WHERE c.cve_id=? AND COALESCE(l.retired,0)=0",Long.class,id)>128)
                    throw new IllegalArgumentException("单条情报当前来源超过128个，请先退役多余来源");
                if ("withdrawn".equals(document.path("status").asText())) revokeReviews(source,id);
                rebuildCve(id);
            }
            if (!documents.isEmpty()) {
                jdbc.update("UPDATE t_vuln_rule_state SET revision=revision+1 WHERE id=1");
                markMatchingDelivery();
            }
            return documents.size();
        });
    }
    /** A source row is the shared database lock for import, retirement and window commit. */
    private void lockActiveSource(String source) {
        if (source==null || !source.matches("[A-Za-z0-9_-]{1,64}") || source.startsWith("_"))
            throw new IllegalArgumentException("来源标识非法");
        // Serialize effective source selection even across separate service/catalog instances.
        lockAuthority();
        jdbc.update("INSERT INTO t_security_source_lifecycle(source_id) VALUES (?) ON CONFLICT(source_id) DO UPDATE SET source_id=EXCLUDED.source_id",source);
        if (isRetired(source)) throw new IllegalArgumentException("来源已退役，请使用新的来源标识");
    }
    private void lockAuthority() {
        if(jdbc.update("UPDATE t_vuln_rule_state SET revision=revision WHERE id=1")!=1)
            throw new IllegalStateException("来源治理状态缺失");
    }
    private void lockSignatureRelease() {
        jdbc.update("""
                INSERT INTO t_security_feed_state(source_id,kind,status) VALUES ('_signature-release','internal','never')
                ON CONFLICT(source_id) DO UPDATE SET cursor=t_security_feed_state.cursor
                """);
    }
    public boolean isRetired(String source) {
        return jdbc.queryForObject("SELECT count(*) FROM t_security_source_lifecycle WHERE source_id=? AND retired=1",Integer.class,source)>0;
    }
    private void event(String source,String cve,String operation,Long actor,String note,String document,Map<String,Object> provenance) {
        jdbc.update("INSERT INTO t_security_governance_event(id,source_id,cve_id,operation,actor,recorded_at,note,document_sha256,snapshot) VALUES (?,?,?,?,?,?,?,?,?)",
                UUID.randomUUID().toString(),source,cve,operation,actor,Instant.now().toString(),note,
                document.isEmpty()?"":VulnerabilityEvidence.sha256(document),
                JsonUtils.write(Map.of("document",document.isEmpty()?Map.of():JsonUtils.read(document),"provenance",provenance)));
    }
    /** Whole-CVE priority stays explicit. A selected withdrawn declaration is a tombstone, not fallback authority. */
    private void rebuildCve(String id) {
        var choice=selection.item("cve",id);
        var previous=jdbc.queryForList("SELECT rule_source_id,rule_digest,rule_status,provenance FROM t_cve_db WHERE cve_id=?",id);
        if (choice.proposed()==null) {
            String state=choice.candidates().isEmpty()?"retired":"quarantined";
            if (!previous.isEmpty()) {
                String source=String.valueOf(previous.get(0).get("rule_source_id"));
                var provenance=(com.fasterxml.jackson.databind.node.ObjectNode)JsonUtils.read(previous.get(0).get("provenance").toString());
                provenance.set("selection",JsonUtils.mapper().valueToTree(choice.summary()));provenance.put("lifecycle",state);
                jdbc.update("UPDATE t_cve_db SET affected=?,rule_status=?,rule_digest=?,provenance=? WHERE cve_id=?",
                        "[]",state,VulnerabilityEvidence.ruleDigest(source,id,JsonUtils.read("[]")),JsonUtils.write(provenance),id);
                revokeReviews(source,id);
                invalidateCve(id);
            }
            return;
        }
        var selected=choice.proposed();
        JsonNode document=JsonUtils.read((String)selected.get("document"));
        String source=(String)selected.get("source_id");
        boolean withdrawn=((Number)selected.get("locally_withdrawn")).intValue()==1 || "withdrawn".equals(document.path("status").asText());
        JsonNode affected=withdrawn || !choice.effective()?JsonUtils.read("[]"):document.path("affected");
        String state=!choice.effective()?("suppressed".equals(choice.reason())?"suppressed":"stale_decision".equals(choice.reason())?"review_required":"no_eligible_source".equals(choice.reason())?"quarantined":"conflict"):withdrawn?"withdrawn":"active";
        String digest=VulnerabilityEvidence.ruleDigest(source,id,affected);
        var provenance=(com.fasterxml.jackson.databind.node.ObjectNode)JsonUtils.read((String)selected.get("provenance"));
        provenance.put("lifecycle",state); provenance.put("locally_withdrawn",((Number)selected.get("locally_withdrawn")).intValue()==1);
        provenance.set("selection",JsonUtils.mapper().valueToTree(choice.summary()));
        jdbc.update("""
                INSERT INTO t_cve_db(cve_id,title,severity,cvss,affected,description,published_at,rule_source_id,rule_digest,provenance,rule_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET title=EXCLUDED.title,
                severity=EXCLUDED.severity,cvss=EXCLUDED.cvss,affected=EXCLUDED.affected,
                description=EXCLUDED.description,published_at=EXCLUDED.published_at,imported_at=CURRENT_TIMESTAMP,
                rule_source_id=EXCLUDED.rule_source_id,rule_digest=EXCLUDED.rule_digest,provenance=EXCLUDED.provenance,rule_status=EXCLUDED.rule_status
                """,id,document.path("title").asText(id),document.path("severity").asInt(),
                document.hasNonNull("cvss")?document.path("cvss").asDouble():null,JsonUtils.write(affected),document.path("description").asText(""),
                document.hasNonNull("published_at")?database.timestamp(Instant.parse(document.path("published_at").asText())):null,
                source,digest,JsonUtils.write(provenance),state);
        if (previous.isEmpty() || !source.equals(previous.get(0).get("rule_source_id")) || !digest.equals(previous.get(0).get("rule_digest"))
                || !state.equals(previous.get(0).get("rule_status"))
                || !choice.contextDigest().equals(JsonUtils.read(previous.get(0).get("provenance").toString()).path("selection").path("contextDigest").asText())
                || ((Number)choice.decision().get("revision")).longValue()!=JsonUtils.read(previous.get(0).get("provenance").toString()).path("selection").path("decision").path("revision").asLong()) {
            if(!previous.isEmpty())revokeReviews(previous.get(0).get("rule_source_id").toString(),id);
            invalidateCve(id);
        }
    }
    private void revokeReviews(String source,String id) {
        jdbc.update("UPDATE t_patch_review SET revoked_at=?,revocation_note='来源声明、选择依据或治理策略已变化，请重新审核' WHERE rule_source_id=? AND cve_id=? AND revoked_at IS NULL",
                Instant.now().toString(),source,id);
    }
    private void invalidateCve(String id) {
        jdbc.update("UPDATE t_vuln_rule_state SET revision=revision+1 WHERE id=1");
        jdbc.update("UPDATE t_vuln_finding SET current_match=false WHERE cve_id=?",id);
        markMatchingDelivery();
    }
    private void markMatchingDelivery() {
        jdbc.update("UPDATE t_security_selection_delivery SET rule_revision=(SELECT revision FROM t_vuln_rule_state WHERE id=1),match_pending=1 WHERE id=1");
    }
    public synchronized void cveWindow(String source,List<JsonNode> documents,Instant end) {
        transaction.executeWithoutResult(status -> {
            cves(source,documents);
            jdbc.update("UPDATE t_security_feed_state SET cursor=? WHERE source_id=?",end.toString(),source);
        });
    }
    private static String decisionNote(Long actor,String note) {
        if (actor==null || actor<=0 || note==null || note.isBlank() || note.trim().length()>2000)
            throw new IllegalArgumentException("治理操作须有已登录账号和 1 至 2000 字原因");
        return note.trim();
    }
    private void requireAdministrator(Long actor) {
        // Lock the current account so disable/role changes cannot race this decision.
        if (jdbc.update("UPDATE t_user SET status=status WHERE id=? AND status=1",actor)!=1
                || jdbc.queryForObject("SELECT count(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND r.name='admin'",Integer.class,actor)!=1)
            throw new IllegalArgumentException("治理操作须由当前有效管理员执行");
    }
    public synchronized Map<String,Object> decideCve(String source,String id,boolean withdraw,String expectedDigest,Long actor,String note) {
        String reason=decisionNote(actor,note);
        return transaction.execute(status -> {
            requireAdministrator(actor);
            lockActiveSource(source);
            var rows=jdbc.queryForList("SELECT document,provenance,locally_withdrawn FROM t_security_cve WHERE source_id=? AND cve_id=?",source,id);
            if (rows.size()!=1) throw new IllegalArgumentException("本来源公告不存在");
            var row=rows.get(0); String document=(String)row.get("document");
            if (!VulnerabilityEvidence.sha256(document).equals(expectedDigest)) throw new IllegalArgumentException("公告已变化，请刷新后重新确认");
            if ((((Number)row.get("locally_withdrawn")).intValue()==1)==withdraw) throw new IllegalArgumentException("公告已处于该状态");
            if (!withdraw && "withdrawn".equals(JsonUtils.read(document).path("status").asText())) throw new IllegalArgumentException("上游公告仍已撤销，不能恢复当前声明");
            jdbc.update("UPDATE t_security_cve SET locally_withdrawn=? WHERE source_id=? AND cve_id=?",withdraw?1:0,source,id);
            event(source,id,withdraw?"withdraw":"reinstate",actor,reason,document,JsonUtils.read((String)row.get("provenance"),Map.class));
            if (withdraw) revokeReviews(source,id);
            rebuildCve(id);
            return Map.of("sourceId",source,"cveId",id,"locallyWithdrawn",withdraw);
        });
    }
    public synchronized Map<String,Object> retire(String source,Long actor,String note) throws IOException {
        String reason=decisionNote(actor,note);
        if ("manual".equals(source)) throw new IllegalArgumentException("人工来源请逐条撤销或重新导入，不支持整源退役");
        try {
            return transaction.execute(status -> {
                requireAdministrator(actor);
                lockActiveSource(source);
                var counts=sourceCounts(source);
                if (((Number)counts.get("cves")).intValue()+((Number)counts.get("hashes")).intValue()+((Number)counts.get("rules")).intValue()==0
                        && props.getSources().stream().noneMatch(s -> s.getId().equals(source))) throw new IllegalArgumentException("来源不存在");
                try {
                    // Adopt once before publishing even a deliberate empty retirement release.
                    if (((Number)counts.get("hashes")).intValue()+((Number)counts.get("rules")).intValue()>0) {
                        lockSignatureRelease(); adoptLegacySignature(false);
                    }
                    jdbc.update("UPDATE t_security_source_lifecycle SET retired=1,retired_at=?,retired_by=?,retirement_note=? WHERE source_id=?",
                            Instant.now().toString(),actor,reason,source);
                    for (String id:jdbc.queryForList("SELECT cve_id FROM t_security_cve WHERE source_id=?",String.class,source)) {
                        revokeReviews(source,id); rebuildCve(id);
                    }
                    event(source,"","retire",actor,reason,"",counts);
                    if (((Number)counts.get("hashes")).intValue()+((Number)counts.get("rules")).intValue()>0) {
                        var release=publishSignatures(actor,"",true);
                        var result=new LinkedHashMap<String,Object>(counts); result.putAll(release); return result;
                    }
                    return counts;
                } catch (IOException e) { throw new UncheckedIOException(e); }
            });
        } catch (UncheckedIOException e) { throw e.getCause(); }
    }
    private Map<String,Object> sourceCounts(String source) {
        return jdbc.queryForMap("SELECT (SELECT count(*) FROM t_security_cve WHERE source_id=?) AS cves, (SELECT count(*) FROM t_security_hash WHERE source_id=?) AS hashes, (SELECT count(*) FROM t_security_rule WHERE source_id=?) AS rules",source,source,source);
    }
    public List<Map<String,Object>> governanceSources() {
        var ids=new TreeSet<String>();
        for (var source:props.getSources()) ids.add(source.getId());
        ids.addAll(jdbc.queryForList("SELECT source_id FROM t_security_source_lifecycle UNION SELECT source_id FROM t_security_cve UNION SELECT source_id FROM t_security_hash UNION SELECT source_id FROM t_security_rule",String.class));
        ids.removeIf(id -> id.startsWith("_"));
        var result=new ArrayList<Map<String,Object>>();
        for (String id:ids) {
            var row=new LinkedHashMap<String,Object>(sourceCounts(id)); row.put("id",id); row.put("retired",isRetired(id));
            row.put("policy",selection.policy(id));
            row.put("configured",props.getSources().stream().anyMatch(s -> s.getId().equals(id)));
            var lifecycle=jdbc.queryForList("SELECT retired_at,retired_by,retirement_note FROM t_security_source_lifecycle WHERE source_id=?",id);
            if (!lifecycle.isEmpty()) row.putAll(lifecycle.get(0)); result.add(row);
        }
        return result;
    }
    public List<Map<String,Object>> declarations(String id) {
        var rows=jdbc.queryForList("SELECT source_id,cve_id,document,provenance,locally_withdrawn FROM t_security_cve WHERE cve_id=? ORDER BY source_id",id);
        for (var row:rows) {
            String document=(String)row.get("document"); row.put("documentDigest",VulnerabilityEvidence.sha256(document));
            row.put("document",JsonUtils.read(document)); row.put("provenance",JsonUtils.read((String)row.get("provenance")));
            row.put("retired",isRetired((String)row.get("source_id")));
        }
        return rows;
    }
    public Map<String,Object> governanceHistory(String source,int page,int size) {
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Long.class,source);
        var rows=jdbc.queryForList("SELECT * FROM t_security_governance_event WHERE source_id=? ORDER BY recorded_at DESC,id DESC LIMIT ? OFFSET ?",source,size,(long)(page-1)*size);
        for (var row:rows) row.put("snapshot",JsonUtils.read((String)row.get("snapshot")));
        return Map.of("list",rows,"total",total==null?0:total);
    }

    public Map<String,Object> sourcePolicy(String source) { return selection.policy(source); }
    public synchronized Map<String,Object> setSourcePolicy(String source,String tier,Integer priority,Boolean quarantined,
                                                          Long expectedRevision,Long actor,String note) throws IOException {
        LibrarySelection.sourceId(source); String reason=decisionNote(actor,note);
        if(tier==null || !LibrarySelection.TIERS.contains(tier) || priority==null || priority<0 || priority>100
                || quarantined==null || expectedRevision==null || expectedRevision<0)
            throw new IllegalArgumentException("须明确来源信任等级、0至100优先级、隔离状态及当前修订号");
        try {
            return transaction.execute(status -> {
                requireAdministrator(actor); lockActiveSource(source);
                var counts=sourceCounts(source);
                boolean known="manual".equals(source) || props.getSources().stream().anyMatch(s->source.equals(s.getId()))
                        || counts.values().stream().anyMatch(n->((Number)n).longValue()>0);
                if(!known)throw new IllegalArgumentException("来源不存在");
                var before=selection.policy(source);
                long revision=((Number)before.get("revision")).longValue();
                if(revision!=expectedRevision)throw new IllegalArgumentException("来源策略已变化，请刷新后重新确认");
                if(tier.equals(before.get("tier")) && priority.equals(before.get("priority")) && quarantined.equals(before.get("quarantined")))
                    throw new IllegalArgumentException("来源策略没有变化");
                if(revision==0 && jdbc.queryForObject("SELECT count(*) FROM t_security_source_policy",Long.class)>=128)
                    throw new IllegalArgumentException("来源策略超过128个上限");
                var ids=jdbc.queryForList("SELECT cve_id FROM t_security_cve WHERE source_id=? ORDER BY cve_id LIMIT 50001",String.class,source);
                if(ids.size()>50000)throw new IllegalArgumentException("来源包含超过50000条CVE，请缩小治理范围后再操作");
                try {
                    boolean signatures="manual".equals(source) || ((Number)counts.get("hashes")).longValue()+((Number)counts.get("rules")).longValue()>0;
                    if(signatures) { lockSignatureRelease(); adoptLegacySignature(false); }
                    jdbc.update("""
                            INSERT INTO t_security_source_policy(source_id,tier,priority,quarantined,revision,actor,updated_at,note)
                            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET tier=EXCLUDED.tier,
                            priority=EXCLUDED.priority,quarantined=EXCLUDED.quarantined,revision=EXCLUDED.revision,
                            actor=EXCLUDED.actor,updated_at=EXCLUDED.updated_at,note=EXCLUDED.note
                            """,source,LibrarySelection.TIERS.indexOf(tier),priority,quarantined?1:0,revision+1,actor,Instant.now().toString(),reason);
                    for(String id:ids)rebuildCve(id);
                    Map<String,Object> release=signatures?publishSignatures(actor,"",true):Map.of("changed",false);
                    var after=selection.policy(source);
                    selectionEvent("source",source,"policy",actor,reason,Map.of("before",before,"after",after,"declarations",counts,"recheckedCves",ids.size(),"publication",release));
                    return Map.of("sourceId",source,"policy",after,"recheckedCves",ids.size(),"publication",release,"delivery",selectionDelivery());
                } catch(IOException e) { throw new UncheckedIOException(e); }
            });
        } catch(UncheckedIOException e) { throw e.getCause(); }
    }
    public Map<String,Object> selections(String kind,String keyword,boolean multiple,int page,int size) {
        if(page<1 || size<1 || size>100)throw new IllegalArgumentException("分页范围非法");
        return selection.keys(kind,keyword,multiple,page,size);
    }
    public Map<String,Object> selectionDetail(String kind,String key) {
        var choice=selection.item(kind,key); var result=new LinkedHashMap<>(choice.summary());
        result.put("candidates",choice.candidates()); return result;
    }
    public Map<String,Object> selectionCandidate(String kind,String key,String source) {
        return transaction.execute(status -> {lockAuthority();return candidateSnapshot(kind,key,source);});
    }
    private Map<String,Object> candidateSnapshot(String kind,String key,String source) {
        var choice=selection.item(kind,key);LibrarySelection.sourceId(source);
        var candidate=choice.candidates().stream().filter(c->source.equals(c.get("sourceId"))).findFirst()
                .orElseThrow(()->new IllegalArgumentException("当前候选来源不存在，请刷新列表"));
        var result=new LinkedHashMap<String,Object>();result.put("candidate",candidate);result.put("contextDigest",choice.contextDigest());
        // Fixed table names only; all caller-provided identifiers remain bound parameters.
        var rows=switch(kind) {
            case "hash" -> jdbc.queryForList("SELECT sha256,name,severity FROM t_security_hash WHERE source_id=? AND sha256=?",source,key);
            case "rule" -> jdbc.queryForList("SELECT document FROM t_security_rule WHERE source_id=? AND name=?",source,key);
            case "cve" -> jdbc.queryForList("SELECT document,provenance,locally_withdrawn FROM t_security_cve WHERE source_id=? AND cve_id=?",source,key);
            default -> throw new IllegalArgumentException("来源选择类型非法");
        };
        if(rows.size()!=1)throw new IllegalArgumentException("候选内容已变化，请刷新");
        var row=rows.get(0);
        if(row.containsKey("document"))row.put("document",JsonUtils.read(row.get("document").toString()));
        if(row.containsKey("provenance"))row.put("provenance",JsonUtils.read(row.get("provenance").toString()));
        result.put("declaration",row); return result;
    }
    public synchronized Map<String,Object> decideSelection(String kind,String key,String action,String source,
                                                           String context,Long expectedRevision,Long actor,String note) throws IOException {
        LibrarySelection.validate(kind,key);String reason=decisionNote(actor,note);
        if(action==null || !Set.of("automatic","select","suppress").contains(action) || context==null || !context.matches("[a-f0-9]{64}")
                || expectedRevision==null || expectedRevision<0)throw new IllegalArgumentException("处理方式、候选摘要或修订号非法");
        if("select".equals(action))LibrarySelection.sourceId(source);
        else if(source!=null && !source.isBlank())throw new IllegalArgumentException("仅指定来源操作可以提供来源标识");
        try {
            return transaction.execute(status -> {
                requireAdministrator(actor);lockAuthority();
                try {if(!"cve".equals(kind)) {lockSignatureRelease();adoptLegacySignature(false);}}
                catch(IOException e) {throw new UncheckedIOException(e);}
                var before=selection.item(kind,key);
                if(!before.contextComplete())throw new IllegalArgumentException("单条情报当前来源超过128个，请先退役多余来源再复核");
                if(!context.equals(before.contextDigest()) || ((Number)before.decision().get("revision")).longValue()!=expectedRevision)
                    throw new IllegalArgumentException("候选内容、策略或处理决定已变化，请刷新后重新确认");
                if(before.candidates().isEmpty() && (!"automatic".equals(action) || expectedRevision==0))throw new IllegalArgumentException("当前条目没有候选来源");
                if("select".equals(action) && before.candidates().stream().noneMatch(c->source.equals(c.get("sourceId")) && !Boolean.TRUE.equals(c.get("quarantined"))))
                    throw new IllegalArgumentException("指定来源不存在、已隔离或已退役");
                if(expectedRevision==0 && jdbc.queryForObject("SELECT count(*) FROM t_security_item_decision",Long.class)>=10000)
                    throw new IllegalArgumentException("条目处理记录超过10000条上限");
                try {
                    // Reset retains a monotonic revision tombstone, preventing stale clients from passing an ABA check.
                    jdbc.update("""
                            INSERT INTO t_security_item_decision(kind,item_key,action,selected_source,context_digest,revision,actor,decided_at,note)
                            VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,item_key) DO UPDATE SET action=EXCLUDED.action,
                            selected_source=EXCLUDED.selected_source,context_digest=EXCLUDED.context_digest,revision=EXCLUDED.revision,
                            actor=EXCLUDED.actor,decided_at=EXCLUDED.decided_at,note=EXCLUDED.note
                            """,kind,key,action,"select".equals(action)?source:"",context,expectedRevision+1,actor,Instant.now().toString(),reason);
                    Map<String,Object> release=Map.of("changed",false);
                    if("cve".equals(kind))rebuildCve(key); else release=publishSignatures(actor,"",true);
                    var after=selection.item(kind,key);
                    selectionEvent(kind,key,action,actor,reason,Map.of("before",before.summary(),"after",after.summary(),"candidates",after.candidates(),"publication",release));
                    var result=new LinkedHashMap<>(after.summary());result.put("candidates",after.candidates());result.put("publication",release);result.put("delivery",selectionDelivery());return result;
                } catch(IOException e) {throw new UncheckedIOException(e);}
            });
        } catch(UncheckedIOException e) {throw e.getCause();}
    }
    private void selectionEvent(String kind,String key,String operation,Long actor,String note,Map<String,Object> snapshot) {
        String serialized=JsonUtils.write(snapshot);
        if(serialized.getBytes(StandardCharsets.UTF_8).length>64*1024)throw new IllegalArgumentException("治理审计快照超过64KiB上限");
        jdbc.update("INSERT INTO t_security_selection_event(id,kind,item_key,operation,actor,recorded_at,note,snapshot) VALUES (?,?,?,?,?,?,?,?)",
                UUID.randomUUID().toString(),kind,key,operation,actor,Instant.now().toString(),note,serialized);
        jdbc.update("""
                DELETE FROM t_security_selection_event WHERE kind=? AND item_key=? AND id NOT IN
                (SELECT id FROM t_security_selection_event WHERE kind=? AND item_key=? ORDER BY recorded_at DESC,id DESC LIMIT 50)
                """,kind,key,kind,key);
    }
    public Map<String,Object> selectionHistory(String kind,String key,int page,int size) {
        if("source".equals(kind))LibrarySelection.sourceId(key);else LibrarySelection.validate(kind,key);
        if(page<1 || size<1 || size>50)throw new IllegalArgumentException("分页范围非法");
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_security_selection_event WHERE kind=? AND item_key=?",Long.class,kind,key);
        var rows=jdbc.queryForList("SELECT * FROM t_security_selection_event WHERE kind=? AND item_key=? ORDER BY recorded_at DESC,id DESC LIMIT ? OFFSET ?",kind,key,size,(long)(page-1)*size);
        for(var row:rows)row.put("snapshot",JsonUtils.read(row.get("snapshot").toString()));
        return Map.of("list",rows,"total",total==null?0:total);
    }
    public Map<String,Object> selectionDelivery() {
        return jdbc.queryForMap("SELECT signature_release_id,signature_pending,rule_revision,match_pending FROM t_security_selection_delivery WHERE id=1");
    }
    public void acknowledgeSelectionDelivery(long signatureRelease,long ruleRevision,boolean signatures,boolean matching) {
        // One statement, no lost update when another catalog instance commits newer work during delivery.
        jdbc.update("""
                UPDATE t_security_selection_delivery SET
                  signature_pending=CASE WHEN ?=1 AND signature_release_id<=? THEN 0 ELSE signature_pending END,
                  match_pending=CASE WHEN ?=1 AND rule_revision<=? THEN 0 ELSE match_pending END WHERE id=1
                """,signatures?1:0,signatureRelease,matching?1:0,ruleRevision);
    }

    /** Retain current/recent releases and every artifact referenced by pending delivery or valid tokens. */
    public synchronized int pruneSignatures() throws IOException {
        if (props.getRetainVersions() < 2 || props.getRetainDays() < 1) throw new IllegalArgumentException("至少保留两个版本和一天历史");
        // A queued command can still contain an old package URL. Conservatively defer cleanup.
        if (jdbc.queryForObject("SELECT count(*) FROM t_command WHERE type='signature_update' AND status IN (0,1,2,3)", Integer.class) > 0) return 0;
        var protectedIds = jdbc.queryForList("SELECT id FROM t_virus_db ORDER BY id DESC LIMIT ?", Long.class, props.getRetainVersions());
        if (protectedIds.isEmpty()) return 0;
        var candidates = jdbc.queryForList("""
                SELECT id,package_key,delta_key FROM t_virus_db WHERE id < ? AND imported_at < ?
                  AND NOT EXISTS (SELECT 1 FROM t_agent_download_token t
                    WHERE t.resource_type='virus-db' AND (t.resource_key=t_virus_db.package_key OR t.resource_key=t_virus_db.delta_key) AND t.expire_at > ?)
                ORDER BY id LIMIT 100
                """, protectedIds.get(protectedIds.size() - 1), database.timestampBefore(java.time.Duration.ofDays(props.getRetainDays())), database.timestamp(Instant.now()));
        int removed = 0;
        for (var row : candidates) {
            files.delete("signature", (String) row.get("package_key"));
            if (!String.valueOf(row.get("delta_key")).isEmpty()) files.delete("signature",String.valueOf(row.get("delta_key")));
            removed += jdbc.update("DELETE FROM t_virus_db WHERE id=?", row.get("id"));
        }
        return removed;
    }
    public static void validateCve(JsonNode document) {
        if (document.has("provenance")) throw new IllegalArgumentException("导入来源和真实性记录由平台生成");
        String id = document.path("cve_id").asText("");
        int severity = document.path("severity").asInt(0);
        if (!document.isObject() || !document.path("cve_id").isTextual() || !document.path("severity").isIntegralNumber()
                || !id.matches("CVE-[0-9]{4}-[0-9]{4,19}") || severity < 1 || severity > 4 || !document.path("affected").isArray()
                || document.path("affected").size() > 200 || document.path("title").asText("").length() > 512
                || (document.has("title") && !document.path("title").isTextual())
                || (document.has("description") && (!document.path("description").isTextual() || document.path("description").asText().length()>65536))
                || (document.hasNonNull("cvss") && (!document.path("cvss").isNumber() || document.path("cvss").asDouble(-1) < 0 || document.path("cvss").asDouble() > 10))) throw new IllegalArgumentException("漏洞数据格式非法");
        if (document.hasNonNull("published_at")) {
            if (!document.path("published_at").isTextual()) throw new IllegalArgumentException("漏洞发布时间格式非法");
            try { Instant.parse(document.path("published_at").asText()); }
            catch (java.time.DateTimeException e) { throw new IllegalArgumentException("漏洞发布时间必须是带时区的 ISO 日期"); }
        }
        if (document.has("status") && (!document.path("status").isTextual() || !Set.of("active", "withdrawn").contains(document.path("status").asText())))
            throw new IllegalArgumentException("公告状态必须为 active 或 withdrawn");
        if (document.has("withdrawal_reason") && (!document.path("withdrawal_reason").isTextual() || document.path("withdrawal_reason").asText().length()>2000))
            throw new IllegalArgumentException("撤销说明非法");
        if ("withdrawn".equals(document.path("status").asText()) && (document.path("withdrawal_reason").asText().isBlank() || !document.path("affected").isEmpty()))
            throw new IllegalArgumentException("撤销公告须说明原因并清空当前适用规则");
        if (VulnerabilityEvidence.canonicalJson(document).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256 * 1024)
            throw new IllegalArgumentException("单条公告原文超过 256 KiB 上限");
        for (JsonNode rule : document.path("affected")) {
            VulnerabilityEvidence.validate(rule);
            String name = rule.path("name").asText("");
            if (!rule.isObject() || !rule.path("name").isTextual() || name.isBlank() || name.length() > 255
                    || rule.has("vrange") == rule.has("ranges")) throw new IllegalArgumentException("漏洞缺少软件及唯一版本条件");
            for (String field : List.of("os", "source", "fixed_version", "match", "version_scheme", "distro_id", "distro_version", "architecture")) {
                if (rule.has(field) && (!rule.path(field).isTextual() || rule.path(field).asText().length() > 255)) throw new IllegalArgumentException("漏洞规则字段类型非法");
            }
            if (rule.has("match") && !Set.of("exact", "contains").contains(rule.path("match").asText())) throw new IllegalArgumentException("软件名匹配方式非法");
            if (rule.has("distro_id") && !VulnerabilityScope.distributionId(rule.path("distro_id").asText())) throw new IllegalArgumentException("发行版 ID 必须明确且格式有效");
            if (rule.has("distro_version") && !VulnerabilityScope.distributionVersion(rule.path("distro_version").asText())) throw new IllegalArgumentException("发行版版本必须明确且格式有效");
            if (rule.has("architecture") && !"*".equals(rule.path("architecture").asText())
                    && !VulnerabilityScope.architecture(rule.path("architecture").asText())) throw new IllegalArgumentException("包架构必须明确或显式声明通配");
            if (VulnerabilityScope.nativeSource(rule.path("source").asText()) && "contains".equals(rule.path("match").asText())) throw new IllegalArgumentException("原生软件包规则必须精确匹配包名");
            if (rule.has("version_scheme") && (!Set.of("rpm", "dpkg", "upstream").contains(rule.path("version_scheme").asText())
                    || (!"upstream".equals(rule.path("version_scheme").asText())
                    && !rule.path("version_scheme").asText().equals(rule.path("source").asText())))) throw new IllegalArgumentException("版本比较语义与软件来源不一致");
            if (rule.has("vrange") && (!rule.path("vrange").isTextual()
                    || !rule.path("vrange").asText().matches("(?:\\*|(?:>=|<=|>|<|=)?[A-Za-z0-9][A-Za-z0-9._:+~%^-]{0,254})"))) throw new IllegalArgumentException("漏洞版本条件非法");
            if (rule.has("ranges") && (!rule.path("ranges").isArray() || rule.path("ranges").isEmpty() || rule.path("ranges").size() > 8)) throw new IllegalArgumentException("漏洞版本范围非法");
            if (rule.has("ranges")) for (JsonNode range : rule.path("ranges")) {
                if (!range.isTextual() || !range.asText().matches("(?:>=|<=|>|<|=)[A-Za-z0-9][A-Za-z0-9._:+~%^-]{0,254}")) throw new IllegalArgumentException("漏洞版本范围非法");
            }
            String source = rule.path("source").asText("");
            if (Set.of("rpm", "dpkg").contains(source) && !"upstream".equals(rule.path("version_scheme").asText())) {
                if (rule.has("ranges")) {
                    for (JsonNode range : rule.path("ranges")) validatePackageBound(source, range.asText());
                } else validatePackageBound(source, rule.path("vrange").asText());
                String fixed = rule.path("fixed_version").asText("");
                if (!fixed.isEmpty()) com.alinksec.service.scan.PackageVersions.compare(source, fixed, fixed);
            }
        }
    }

    private static void validatePackageBound(String source, String range) {
        if ("*".equals(range)) return;
        String bound = range.replaceFirst("^(?:>=|<=|>|<|=)", "");
        com.alinksec.service.scan.PackageVersions.compare(source, bound, bound);
    }

    static boolean hasComparableRules(JsonNode document) {
        for (JsonNode rule : document.path("affected")) {
            if (VulnerabilityScope.nativeSource(rule.path("source").asText())) {
                if (VulnerabilityScope.nativeRule(rule) && VulnerabilityEvidence.comparable(rule)) return true;
            } else if (VulnerabilityEvidence.comparable(rule)) return true;
        }
        return false;
    }

    public Map<String, Object> cveRules(String keyword, int page, int size) {
        String where = keyword == null || keyword.isBlank() ? "" : " WHERE LOWER(cve_id) LIKE LOWER(?) OR LOWER(title) LIKE LOWER(?)";
        var args = new ArrayList<Object>();
        if (!where.isEmpty()) { args.add("%" + keyword.trim() + "%"); args.add(args.get(0)); }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_cve_db" + where, Long.class, args.toArray());
        var pageArgs = new ArrayList<>(args); pageArgs.add(size); pageArgs.add((page - 1) * size);
        var rows = jdbc.queryForList("SELECT cve_id,title,rule_source_id,rule_digest,rule_status,provenance,CAST(affected AS TEXT) AS affected FROM t_cve_db"
                + where + " ORDER BY cve_id LIMIT ? OFFSET ?", pageArgs.toArray());
        for (var row : rows) {
            row.put("provenance", JsonUtils.read((String) row.get("provenance")));
            JsonNode affected = JsonUtils.read((String) row.get("affected"));
            row.put("affected", affected);
            var choice=selection.item("cve",String.valueOf(row.get("cve_id")));
            if(!choice.candidates().isEmpty())row.put("selection",choice.summary());
            boolean declared = !String.valueOf(row.get("rule_source_id")).isEmpty()
                    && row.get("rule_digest").equals(VulnerabilityEvidence.ruleDigest(String.valueOf(row.get("rule_source_id")), String.valueOf(row.get("cve_id")), affected));
            boolean supported = false;
            if (declared) for (var rule : affected) {
                if (rule.path("evidence").isObject() && VulnerabilityEvidence.comparable(rule)) { supported = true; break; }
            }
            row.put("evaluation",!choice.candidates().isEmpty() && !choice.effective()?"source_held":supported ? "declared" : "metadata_only");
        }
        return Map.of("list", rows, "total", total == null ? 0 : total);
    }
}
