package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.virus.VirusDbService;
import com.alinksec.service.scan.VulnMatchService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.JsonToken;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Serial sync jobs preserve local data and never expose credentials in status or errors. */
@Service
public class LibrarySyncService {
    private static final Logger log = LoggerFactory.getLogger(LibrarySyncService.class);
    private final LibraryProperties props;
    private final LibraryCatalog catalog;
    private final VirusDbService virus;
    private final FeedDownload download;
    private final JdbcTemplate jdbc;
    private final VulnMatchService matcher;
    private final LibrarySchedule schedules;
    private final AtomicBoolean busy = new AtomicBoolean();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "library-sync"); t.setDaemon(true); return t; });
    public LibrarySyncService(LibraryProperties props, LibraryCatalog catalog, VirusDbService virus, FeedDownload download, JdbcTemplate jdbc, VulnMatchService matcher, LibrarySchedule schedules) {
        this.props = props; this.catalog = catalog; this.virus = virus; this.download = download; this.jdbc = jdbc;
        this.matcher = matcher; this.schedules = schedules;
    }
    public void recheckAssets() { worker.execute(() -> matcher.matchAll(0)); }
    @Scheduled(fixedDelay = 86_400_000, initialDelay = 86_400_000)
    public void cleanupVersions() {
        if (busy.get()) return;
        try { catalog.pruneSignatures(); }
        catch (Exception e) { log.warn("Library history cleanup deferred: {}", e.getClass().getSimpleName()); }
    }
    @PostConstruct public void validate() {
        Set<String> ids = new HashSet<>();
        if (props.getSources().size() > 16 || props.getMaxDownloadBytes() < 1024 || props.getMaxHashes() < 1
                || props.getMaxCvesPerImport() < 1 || props.getRetainVersions() < 2 || props.getRetainDays() < 1) throw new IllegalArgumentException("安全库容量或保留配置非法");
        for (var source : props.getSources()) {
            if (!source.getId().matches("[A-Za-z0-9-]{1,64}") || "manual".equals(source.getId()) || !ids.add(source.getId())
                    || !Set.of("hashes", "signature-zip", "malwarebazaar", "misp", "cve-json", "nvd").contains(source.getType())
                    || source.getIntervalMs() < 300_000 || source.getInitialDays() < 1 || source.getInitialDays() > 120) throw new IllegalArgumentException("安全库数据源配置非法");
            LibrarySchedule.validateInterval(source.getType(), source.getIntervalMs());
            for (var product : source.getProducts()) {
                if (!product.getCpePrefix().matches("cpe:2\\.3:a:[^:]+:[^:]+:") || product.getName().isBlank() || product.getOs().isBlank()
                        || product.getAssetSource().isBlank() || Set.of("rpm", "dpkg").contains(product.getAssetSource())) throw new IllegalArgumentException("NVD 应用映射需明确软件名、系统和非发行版软件来源");
            }
        }
        recoverInterruptedRuns();
    }
    public void recoverInterruptedRuns() {
        String message = "服务重启中断了上次同步，将按计划重试";
        jdbc.update("UPDATE t_security_feed_run SET status='interrupted',finished_at=?,error=? WHERE status='running'", Instant.now().toString(), message);
        jdbc.update("UPDATE t_security_feed_state SET status='failed',failure_count=failure_count+1,error=? WHERE status='running'", message);
    }
    public boolean trigger(String id) { return trigger(id, "manual"); }
    private boolean trigger(String id, String triggerType) {
        var source = schedules.source(id);
        if (!schedules.effective(source).enabled()) throw new IllegalArgumentException("该远端数据源未启用");
        if (!busy.compareAndSet(false, true)) return false;
        try {
            worker.execute(() -> { try { sync(source, triggerType); } finally { busy.set(false); } });
            return true;
        } catch (RuntimeException e) { busy.set(false); throw e; }
    }
    @Scheduled(fixedDelay = 60_000, initialDelay = 60_000)
    public void scheduled() {
        if (busy.get()) return;
        LibraryProperties.Source due = null;
        Instant earliest = Instant.now();
        for (var source : props.getSources()) {
            var plan = schedules.effective(source);
            if (!plan.enabled()) continue;
            var rows = jdbc.queryForList("SELECT checked_at,failure_count FROM t_security_feed_state WHERE source_id=?", source.getId());
            Instant next = LibrarySchedule.nextCheck(plan, rows.isEmpty() ? Map.of() : rows.get(0));
            if (next.isBefore(earliest)) { due = source; earliest = next; }
        }
        if (due != null) {
            try { trigger(due.getId(), "scheduled"); }
            catch (IllegalArgumentException ignored) { /* An administrator may have paused it since selection. */ }
        }
    }
    public void sync(LibraryProperties.Source source) { sync(source, "manual"); }
    private void sync(LibraryProperties.Source source, String triggerType) {
        String id = source.getId();
        jdbc.update("""
                INSERT INTO t_security_feed_state(source_id,kind,checked_at,status) VALUES (?,?,?,'running')
                ON CONFLICT(source_id) DO UPDATE SET kind=EXCLUDED.kind,checked_at=EXCLUDED.checked_at,status='running',error=''
                """, id, source.getType(), Instant.now().toString());
        String runId = UUID.randomUUID().toString();
        jdbc.update("INSERT INTO t_security_feed_run(id,source_id,trigger_type,started_at,status) VALUES (?,?,?,?,'running')",
                runId, id, triggerType, Instant.now().toString());
        try {
            if ("nvd".equals(source.getType())) { syncNvd(source); return; }
            if ("misp".equals(source.getType())) {
                var result = catalog.signatures(id, MispAdapter.fetch(source, download, props), true, null);
                if (Boolean.TRUE.equals(result.get("changed"))) virus.pushToAllAgents();
                int count = jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?", Integer.class, id);
                success(id, count, "", "", "");
                return;
            }
            var state = jdbc.queryForMap("SELECT * FROM t_security_feed_state WHERE source_id=?", id);
            Map<String, String> headers = new HashMap<>();
            String form = null;
            if ("malwarebazaar".equals(source.getType())) {
                if (source.getApiKey().isBlank()) throw new IllegalArgumentException("数据源认证未配置");
                headers.put("Auth-Key", source.getApiKey()); form = "query=get_recent&selector=time";
            } else {
                String etag = (String) state.get("etag"), modified = (String) state.get("last_modified");
                if (!etag.isBlank()) headers.put("If-None-Match", etag);
                if (!modified.isBlank()) headers.put("If-Modified-Since", modified);
            }
            String address = source.getUrl().isBlank() && "malwarebazaar".equals(source.getType()) ? "https://mb-api.abuse.ch/api/v1/" : source.getUrl();
            try (var fetched = download.fetch(address, headers, form)) {
                int count = 0;
                if (fetched.status() == 200) {
                    if ("cve-json".equals(source.getType())) {
                        count = catalog.cves(id, readCves(Files.newInputStream(fetched.file())));
                        matcher.matchAll(0);
                    }
                    else {
                        SignaturePackage pkg;
                        boolean replace = false;
                        if ("signature-zip".equals(source.getType())) { pkg = SignaturePackage.read(fetched.file(), props); replace = true; }
                        else if ("malwarebazaar".equals(source.getType())) pkg = malwareBazaar(fetched.file());
                        else { try (var in = Files.newInputStream(fetched.file())) { pkg = new SignaturePackage("", SignaturePackage.readHashes(in, props.getMaxHashes()), List.of()); } }
                        if (!pkg.hashes().isEmpty() || !pkg.rules().isEmpty()) {
                            var result = catalog.signatures(id, pkg, replace, null);
                            if (Boolean.TRUE.equals(result.get("changed"))) virus.pushToAllAgents();
                        } else if (!"malwarebazaar".equals(source.getType())) throw new IllegalArgumentException("远端返回空特征数据，已有库保留");
                    }
                } else if (state.get("success_at") == null) throw new IllegalArgumentException("数据源首次同步不能返回 304");
                if (!"cve-json".equals(source.getType())) count = jdbc.queryForObject("SELECT (SELECT count(*) FROM t_security_hash WHERE source_id=?) + (SELECT count(*) FROM t_security_rule WHERE source_id=?)", Integer.class, id, id);
                else count = jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?", Integer.class, id);
                String etag = fetched.etag(), modified = fetched.modified();
                if (fetched.status() == 304) {
                    if (etag.isBlank()) etag = (String) state.get("etag");
                    if (modified.isBlank()) modified = (String) state.get("last_modified");
                }
                success(id, count, "", etag, modified);
            }
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            // Messages from parsers/HTTP libraries may contain a URL, API key or response body.
            String message = e instanceof IllegalArgumentException ? "数据格式、认证或容量校验失败，已有库保留" : "远端访问或发布失败，已有库保留";
            jdbc.update("UPDATE t_security_feed_state SET status='failed',failure_count=CASE WHEN failure_count<1000 THEN failure_count+1 ELSE 1000 END,error=? WHERE source_id=?", message, id);
            log.warn("Library sync failed: source={} type={}", id, e.getClass().getSimpleName());
        } finally {
            var state = jdbc.queryForMap("SELECT status,entry_count,error FROM t_security_feed_state WHERE source_id=?", id);
            jdbc.update("UPDATE t_security_feed_run SET finished_at=?,status=?,entry_count=?,error=? WHERE id=?",
                    Instant.now().toString(), state.get("status"), state.get("entry_count"), state.get("error"), runId);
            jdbc.update("DELETE FROM t_security_feed_run WHERE source_id=? AND id NOT IN (SELECT id FROM t_security_feed_run WHERE source_id=? ORDER BY started_at DESC,id DESC LIMIT 50)", id, id);
        }
    }
    private SignaturePackage malwareBazaar(java.nio.file.Path file) throws IOException {
        JsonNode root = JsonUtils.mapper().readTree(file.toFile());
        if ("no_results".equals(root.path("query_status").asText())) return new SignaturePackage("", Map.of(), List.of());
        if (!"ok".equals(root.path("query_status").asText()) || !root.path("data").isArray()) throw new IllegalArgumentException("数据源响应非法");
        Map<String, SignaturePackage.Hash> hashes = new TreeMap<>();
        for (JsonNode item : root.path("data")) {
            String family = item.path("signature").asText("KnownHash").replaceAll("[^A-Za-z0-9._-]", "_");
            if (family.isEmpty()) family = "KnownHash";
            var hash = SignaturePackage.checkedHash(item.path("sha256_hash").asText(), "MalwareBazaar." + family.substring(0, Math.min(200, family.length())), 4);
            hashes.put(hash.sha256(), hash);
            if (hashes.size() > props.getMaxHashes()) throw new IllegalArgumentException("哈希数超过上限");
        }
        return new SignaturePackage("", hashes, List.of());
    }
    public List<JsonNode> readCves(InputStream input) throws IOException {
        List<JsonNode> documents = new ArrayList<>();
        try (input; var parser = JsonUtils.mapper().getFactory().createParser(input)) {
            if (parser.nextToken() != JsonToken.START_ARRAY) throw new IllegalArgumentException("漏洞文件必须是 JSON 数组");
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (parser.currentToken() != JsonToken.START_OBJECT || documents.size() >= props.getMaxCvesPerImport()) throw new IllegalArgumentException("漏洞文件格式或数量非法");
                JsonNode document = JsonUtils.mapper().readTree(parser);
                LibraryCatalog.validateCve(document); documents.add(document);
            }
            if (parser.nextToken() != null || documents.isEmpty()) throw new IllegalArgumentException("拒绝空或非法漏洞文件");
        }
        return documents;
    }
    private void syncNvd(LibraryProperties.Source source) throws Exception {
        var state = jdbc.queryForMap("SELECT * FROM t_security_feed_state WHERE source_id=?", source.getId());
        String cursor = (String) state.get("cursor");
        Instant end = Instant.now();
        Instant start = cursor.isBlank() ? end.minus(Duration.ofDays(source.getInitialDays())) : Instant.parse(cursor).minusSeconds(120);
        // Catch up in bounded windows; checkpoint each completed window, never skip an outage.
        if (Duration.between(start, end).toDays() > 119) end = start.plus(Duration.ofDays(119));
        String endpoint = source.getUrl().isBlank() ? "https://services.nvd.nist.gov/rest/json/cves/2.0/" : source.getUrl();
        String filter = "lastModStartDate=" + encode(start.toString()) + "&lastModEndDate=" + encode(end.toString());
        Map<String, String> headers = source.getApiKey().isBlank() ? Map.of() : Map.of("apiKey", source.getApiKey());
        List<JsonNode> documents = new ArrayList<>();
        int index = 0, total;
        long downloaded = 0;
        do {
            try (var fetched = download.fetch(endpoint + (endpoint.contains("?") ? "&" : "?") + filter + "&resultsPerPage=200&startIndex=" + index, headers, null)) {
                downloaded += Files.size(fetched.file());
                if (downloaded > props.getMaxDownloadBytes()) throw new IllegalArgumentException("NVD 分页累计大小超过同步上限");
                JsonNode root = JsonUtils.mapper().readTree(fetched.file().toFile());
                if (fetched.status() != 200 || !root.path("vulnerabilities").isArray() || !root.has("totalResults") || root.path("startIndex").asInt(-1) != index) throw new IllegalArgumentException("NVD 分页响应非法");
                total = root.path("totalResults").asInt(-1);
                if (total < 0 || total > props.getMaxCvesPerImport()) throw new IllegalArgumentException("NVD 数据量超过单次同步上限，请缩小初始日期范围");
                JsonNode page = root.path("vulnerabilities");
                if ((page.isEmpty() && index < total) || index + page.size() > total) throw new IllegalArgumentException("NVD 分页不完整");
                for (JsonNode item : page) documents.add(NvdAdapter.normalize(item.path("cve"), source.getProducts()));
                index += page.size();
            }
            if (index < total) Thread.sleep(source.getApiKey().isBlank() ? 6000 : 700);
        } while (index < total);
        catalog.cves(source.getId(), documents);
        if (!documents.isEmpty()) matcher.matchAll(0);
        int count = jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?", Integer.class, source.getId());
        success(source.getId(), count, end.toString(), "", "");
    }
    private static String encode(String text) { return URLEncoder.encode(text, StandardCharsets.UTF_8); }
    private void success(String id, int count, String cursor, String etag, String modified) {
        jdbc.update("""
                UPDATE t_security_feed_state SET status='success',failure_count=0,error='',success_at=?,entry_count=?,
                cursor=?,etag=?,last_modified=? WHERE source_id=?
                """, Instant.now().toString(), count, cursor, etag, modified, id);
    }
    public Map<String, Object> status() {
        List<Map<String, Object>> sources = new ArrayList<>();
        for (var source : props.getSources()) {
            Map<String, Object> row = new LinkedHashMap<>();
            var plan = schedules.effective(source);
            row.put("id", source.getId()); row.put("type", source.getType()); row.put("enabled", plan.enabled()); row.put("intervalMs", plan.intervalMs());
            row.put("scheduleOverridden", plan.overridden()); row.put("minIntervalMs", LibrarySchedule.minimumInterval(source.getType()));
            row.put("configurationIssue", LibrarySchedule.configurationIssue(source));
            var states = jdbc.queryForList("SELECT checked_at,success_at,status,error,entry_count,cursor,failure_count FROM t_security_feed_state WHERE source_id=?", source.getId());
            if (!states.isEmpty()) row.putAll(states.get(0)); else row.put("status", "never");
            Object last = row.get("success_at");
            row.put("stale", last == null || Instant.parse((String) last).plusMillis(plan.intervalMs() * 2).isBefore(Instant.now()));
            row.put("nextCheckAt", plan.enabled() ? LibrarySchedule.nextCheck(plan, row).toString() : null);
            row.put("retryDelayMs", LibrarySchedule.delay(plan, row.get("failure_count") instanceof Number count ? count.intValue() : 0));
            row.put("coverage", "malwarebazaar".equals(source.getType()) ? "recent-60m" : "nvd".equals(source.getType()) ? "modified-window" : "misp".equals(source.getType()) ? "curated-snapshot" : "configured-feed");
            sources.add(row);
        }
        var virusRows = jdbc.queryForList("SELECT db_version,hash_count,rule_count,imported_at FROM t_virus_db ORDER BY id DESC LIMIT 1");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sources", sources); result.put("running", busy.get()); result.put("storage", props.getStorage().getBackend());
        result.put("signature", virusRows.isEmpty() ? Map.of() : virusRows.get(0));
        result.put("cveCount", jdbc.queryForObject("SELECT count(*) FROM t_cve_db", Integer.class));
        String effective = "SELECT cve_id,matchable,ROW_NUMBER() OVER(PARTITION BY cve_id ORDER BY CASE WHEN source_id='manual' THEN 0 ELSE 1 END,source_id) AS priority FROM t_security_cve";
        var counts = jdbc.queryForMap("SELECT count(*) AS total,COALESCE(SUM(matchable),0) AS matchable FROM (" + effective + ") v WHERE priority=1");
        result.put("managedCveCount", counts.get("total")); result.put("matchableCveCount", counts.get("matchable"));
        result.put("manualSignature", jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id='manual'", Integer.class));
        return result;
    }
    public List<Map<String, Object>> history(String id) {
        schedules.source(id);
        return jdbc.queryForList("SELECT id,trigger_type,started_at,finished_at,status,entry_count,error FROM t_security_feed_run WHERE source_id=? ORDER BY started_at DESC,id DESC LIMIT 50", id);
    }
    @PreDestroy public void close() { worker.shutdownNow(); }
}
