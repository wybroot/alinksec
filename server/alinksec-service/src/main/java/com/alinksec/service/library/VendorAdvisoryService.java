package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.scan.VulnerabilityEvidence;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.jdbc.core.JdbcTemplate;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Bounded native discovery and per-document atomic imports; current publisher contributions remain distinct. */
public final class VendorAdvisoryService {
    private final LibraryCatalog catalog;
    private final FeedDownload download;
    private final JdbcTemplate jdbc;
    private final VendorAdvisoryProperties limits;
    public VendorAdvisoryService(LibraryCatalog catalog, FeedDownload download, JdbcTemplate jdbc, VendorAdvisoryProperties limits) {
        this.catalog=catalog; this.download=download; this.jdbc=jdbc; this.limits=limits;
    }
    public void validate(LibraryProperties.Source source) { limits.validate(); VendorAdvisoryIndex.validate(source); }
    private static final String META = "id,source_id,document_id,format,publisher,title,vendor_version,vendor_updated_at,origin,origin_kind,sha256,size_bytes,current_version,cve_count,rule_count,imported_at,checked_at,CASE WHEN raw_base64 IS NULL THEN 0 ELSE 1 END AS raw_available";
    private static final class Budget {
        int requests; long bytes;
        final long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(180);
        int timeout() {
            long remaining=TimeUnit.NANOSECONDS.toMillis(end-System.nanoTime());
            if (++requests>16 || remaining<100) throw VendorAdvisoryIndex.invalid();
            return (int)Math.min(30_000,remaining);
        }
        void add(long size) { if ((bytes+=size)>(64L<<20)) throw VendorAdvisoryIndex.invalid(); }
    }
    private record Response(int status, byte[] raw, String etag, String modified) {}
    private Response fetch(String address, Map<String,String> conditional, int cap, Budget budget) throws IOException {
        Map<String,String> headers=new HashMap<>(conditional);
        headers.put("Accept", "application/json");
        headers.putIfAbsent("Accept-Encoding", "identity");
        try (var fetched=download.fetchBounded(address,headers,cap,budget.timeout())) {
            byte[] raw=Files.readAllBytes(fetched.file()); budget.add(raw.length);
            return new Response(fetched.status(),raw,fetched.etag(),fetched.modified());
        }
    }
    private static Map<String,String> conditional(Map<String,Object> previous) {
        Map<String,String> headers=new HashMap<>();
        for (var pair:Map.of("etag","If-None-Match","last_modified","If-Modified-Since").entrySet()) {
            String value=Objects.toString(previous.get(pair.getKey()),"");
            if (!value.isBlank()) headers.put(pair.getValue(),value);
        }
        return headers;
    }
    private void pin(LibraryProperties.Source source) {
        String fingerprint=VendorAdvisoryIndex.fingerprint(source);
        catalog.nativeTransaction(source.getId(),()-> {
            jdbc.update("INSERT INTO t_vendor_sync_state(source_id,configuration_sha256,updated_at) VALUES (?,?,?) ON CONFLICT(source_id) DO NOTHING",
                    source.getId(),fingerprint,Instant.now().toString());
            String pinned=jdbc.queryForObject("SELECT configuration_sha256 FROM t_vendor_sync_state WHERE source_id=?",String.class,source.getId());
            if (!fingerprint.equals(pinned)) throw new IllegalArgumentException("厂商来源身份或范围已变更，请退役旧来源并使用新来源标识");
            return null;
        });
    }
    public int sync(LibraryProperties.Source source) throws IOException {
        validate(source); pin(source);
        Budget budget=new Budget();
        VendorAdvisoryIndex.Candidate direct=VendorAdvisoryIndex.direct(source);
        List<VendorAdvisoryIndex.Candidate> candidates=direct==null?discover(source,budget):List.of(direct);
        Map<String,Map<String,Object>> current=new HashMap<>();
        for (var row:jdbc.queryForList("SELECT document_id,vendor_updated_at,checked_at,origin,etag,last_modified FROM t_vendor_document WHERE source_id=? AND current_version=1",source.getId()))
            current.put(row.get("document_id").toString(),row);
        var pending=new ArrayList<VendorAdvisoryIndex.Candidate>();
        Set<String> discovered=new HashSet<>();
        for (var item:candidates) {
            discovered.add(item.id());
            if (direct!=null || needsCheck(item,current.get(item.id()))) pending.add(item);
        }
        // A recent discovery window does not erase documents already accepted from an older window.
        for (var row:current.values()) {
            String id=row.get("document_id").toString();
            if (!discovered.contains(id)) {
                var item=new VendorAdvisoryIndex.Candidate(id,row.get("origin").toString(),Instant.EPOCH);
                if (needsCheck(item,row)) pending.add(item);
            }
        }
        pending.sort(Comparator.comparing(VendorAdvisoryIndex.Candidate::updated).reversed().thenComparing(VendorAdvisoryIndex.Candidate::id));
        progress(source.getId(),candidates.size(),pending.size(),0);
        int checked=0;
        for (var item:pending) {
            if (checked>=limits.getDocumentsPerSync()) break;
            Map<String,Object> old=current.getOrDefault(item.id(),Map.of());
            Map<String,String> headers=conditional(old);
            if ("debian-tracker".equals(source.getType())) headers.put("Accept-Encoding","gzip");
            Response response=fetch(item.address(),headers,limits.getMaxDocumentBytes(),budget);
            if (response.status()==304) {
                if (old.isEmpty()) throw VendorAdvisoryIndex.invalid();
                catalog.nativeTransaction(source.getId(),()-> {
                    jdbc.update("UPDATE t_vendor_document SET checked_at=? WHERE source_id=? AND document_id=? AND current_version=1",Instant.now().toString(),source.getId(),item.id());
                    return null;
                });
            } else {
                var parsed=VendorAdvisoryAdapter.parse(source,response.raw());
                if (!parsed.id().equals(item.id())) throw VendorAdvisoryIndex.invalid();
                store(source,item.address(),response,parsed);
            }
            checked++;
            progress(source.getId(),candidates.size(),pending.size()-checked,checked);
        }
        return jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?",Integer.class,source.getId());
    }
    private static boolean needsCheck(VendorAdvisoryIndex.Candidate item, Map<String,Object> old) {
        return old==null || item.updated().isAfter(Instant.parse(old.get("vendor_updated_at").toString()))
                || Instant.parse(old.get("checked_at").toString()).isBefore(Instant.now().minusSeconds(86_400));
    }
    private void progress(String source,int discovered,int pending,int checked) {
        jdbc.update("UPDATE t_vendor_sync_state SET discovered_count=?,pending_count=?,checked_count=?,updated_at=? WHERE source_id=?",
                discovered,pending,checked,Instant.now().toString(),source);
    }
    private List<VendorAdvisoryIndex.Candidate> discover(LibraryProperties.Source source,Budget budget) throws IOException {
        Map<String,Object> state=jdbc.queryForMap("SELECT * FROM t_vendor_sync_state WHERE source_id=?",source.getId());
        if (((Number)state.get("pending_count")).intValue()>0 && !state.get("index_base64").toString().isBlank())
            return decodePlan(state.get("index_base64").toString(),state.get("index_sha256").toString());
        String base=VendorAdvisoryIndex.address(source);
        Instant cutoff=Instant.now().minus(Duration.ofDays(source.getInitialDays()));
        List<VendorAdvisoryIndex.Candidate> candidates;
        String etag="",modified="";
        if ("ubuntu-usn".equals(source.getType())) {
            var result=new LinkedHashMap<String,VendorAdvisoryIndex.Candidate>();
            for (int page=0;page<source.getVendorPages();page++) {
                Response response=fetch(base+"/notices.json?limit=20&offset="+(page*20),Map.of(),4<<20,budget);
                if (response.status()!=200) throw VendorAdvisoryIndex.invalid();
                JsonNode rows=VendorAdvisoryIndex.json(response.raw()).path("notices");
                if (!rows.isArray() || rows.size()>20) throw VendorAdvisoryIndex.invalid();
                boolean older=false;
                for (var row:rows) {
                    String id=row.path("id").asText();
                    if (!id.matches("USN-[0-9]{1,8}-[0-9]{1,4}")) throw VendorAdvisoryIndex.invalid();
                    Instant published=VendorAdvisoryAdapter.timestamp(row.path("published").asText());
                    if (published.isBefore(cutoff)) { older=true; continue; }
                    VendorAdvisoryIndex.add(result,new VendorAdvisoryIndex.Candidate(id,base+"/notices/"+id+".json",published));
                }
                if (older || rows.size()<20) break;
            }
            candidates=List.copyOf(result.values());
        } else {
            String suffix="redhat-csaf".equals(source.getType())?"/changes.csv":"/updates";
            Response response=fetch(base+suffix,conditional(state),4<<20,budget);
            if (response.status()==304) {
                if (state.get("index_base64").toString().isBlank()) throw VendorAdvisoryIndex.invalid();
                return decodePlan(state.get("index_base64").toString(),state.get("index_sha256").toString());
            }
            candidates="redhat-csaf".equals(source.getType())?VendorAdvisoryIndex.redhat(response.raw(),base,cutoff)
                    :VendorAdvisoryIndex.microsoft(response.raw(),base,cutoff);
            etag=response.etag(); modified=response.modified();
        }
        var rows=JsonUtils.mapper().createArrayNode();
        for (var item:candidates) rows.addObject().put("id",item.id()).put("address",item.address()).put("updated",item.updated().toString());
        byte[] bytes=JsonUtils.write(Map.of("candidates",rows)).getBytes(StandardCharsets.UTF_8);
        if (bytes.length>(4<<20)) throw VendorAdvisoryIndex.invalid();
        jdbc.update("UPDATE t_vendor_sync_state SET index_base64=?,index_sha256=?,etag=?,last_modified=? WHERE source_id=?",
                Base64.getEncoder().encodeToString(bytes),sha(bytes),etag,modified,source.getId());
        return candidates;
    }
    private List<VendorAdvisoryIndex.Candidate> decodePlan(String encoded,String expected) throws IOException {
        byte[] bytes=Base64.getDecoder().decode(encoded);
        if (bytes.length>(4<<20) || !sha(bytes).equals(expected)) throw VendorAdvisoryIndex.invalid();
        JsonNode rows=VendorAdvisoryIndex.json(bytes).path("candidates");
        if (!rows.isArray() || rows.size()>4096) throw VendorAdvisoryIndex.invalid();
        var result=new ArrayList<VendorAdvisoryIndex.Candidate>();
        for (var row:rows) result.add(new VendorAdvisoryIndex.Candidate(row.path("id").asText(),row.path("address").asText(),Instant.parse(row.path("updated").asText())));
        return result;
    }
    private void store(LibraryProperties.Source source,String origin,Response response,VendorAdvisoryAdapter.Document document) {
        String sourceId=source.getId(),digest=sha(response.raw()),fingerprint=VendorAdvisoryIndex.fingerprint(source);
        catalog.nativeTransaction(sourceId,()-> {
            var old=jdbc.queryForList("SELECT id,sha256,vendor_updated_at FROM t_vendor_document WHERE source_id=? AND document_id=? AND current_version=1",sourceId,document.id());
            if (!old.isEmpty() && digest.equals(old.get(0).get("sha256"))) {
                jdbc.update("UPDATE t_vendor_document SET checked_at=?,etag=?,last_modified=? WHERE id=?",Instant.now().toString(),response.etag(),response.modified(),old.get(0).get("id"));
                return null;
            }
            if (!old.isEmpty() && !document.updated().equals(Instant.EPOCH)
                    && document.updated().isBefore(Instant.parse(old.get(0).get("vendor_updated_at").toString()))) throw VendorAdvisoryIndex.invalid();
            var affected=new TreeSet<>(jdbc.queryForList("SELECT cve_id FROM t_vendor_contribution WHERE source_id=? AND document_id=?",String.class,sourceId,document.id()));
            for (var cve:document.cves()) affected.add(cve.path("cve_id").asText());
            jdbc.update("UPDATE t_vendor_document SET current_version=0 WHERE source_id=? AND document_id=? AND current_version=1",sourceId,document.id());
            var known=jdbc.queryForList("SELECT id FROM t_vendor_document WHERE source_id=? AND document_id=? AND configuration_sha256=? AND sha256=?",sourceId,document.id(),fingerprint,digest);
            String archive=known.isEmpty()?UUID.randomUUID().toString():known.get(0).get("id").toString();
            String now=Instant.now().toString();
            int ruleCount=document.cves().stream().mapToInt(c->c.path("affected").size()).sum();
            if (known.isEmpty()) {
                if (jdbc.queryForObject("SELECT count(*) FROM t_vendor_document",Integer.class)>=50_000) throw VendorAdvisoryIndex.invalid();
                jdbc.update("""
                        INSERT INTO t_vendor_document(id,source_id,document_id,format,publisher,title,vendor_version,vendor_updated_at,configuration_sha256,
                        origin,origin_kind,sha256,size_bytes,raw_base64,current_version,cve_count,rule_count,imported_at,checked_at,etag,last_modified)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)
                        """,archive,sourceId,document.id(),source.getType(),document.publisher(),document.title(),document.version(),document.updated().toString(),fingerprint,
                        origin,originKind(source,origin),digest,response.raw().length,Base64.getEncoder().encodeToString(response.raw()),document.cves().size(),ruleCount,now,now,response.etag(),response.modified());
            } else jdbc.update("UPDATE t_vendor_document SET current_version=1,raw_base64=?,checked_at=?,etag=?,last_modified=? WHERE id=?",
                    Base64.getEncoder().encodeToString(response.raw()),now,response.etag(),response.modified(),archive);
            pruneRaw(sourceId,document.id());
            Long bytes=jdbc.queryForObject("SELECT COALESCE(sum(size_bytes),0) FROM t_vendor_document WHERE raw_base64 IS NOT NULL",Long.class);
            if (bytes>limits.getMaxArchiveBytes()) throw new IllegalArgumentException("厂商公告原件容量已满，已有文档保留");
            jdbc.update("DELETE FROM t_vendor_contribution WHERE source_id=? AND document_id=?",sourceId,document.id());
            for (var cve:document.cves()) jdbc.update("INSERT INTO t_vendor_contribution(source_id,document_id,cve_id,raw_document_id,document) VALUES (?,?,?,?,?)",
                    sourceId,document.id(),cve.path("cve_id").asText(),archive,VulnerabilityEvidence.canonicalJson(cve));
            if (jdbc.queryForObject("SELECT count(*) FROM t_vendor_contribution WHERE source_id=?",Integer.class,sourceId)>100_000) throw VendorAdvisoryIndex.invalid();
            for (String cve:affected) aggregate(sourceId,cve,source.getType(),document.publisher(),archive);
            return null;
        });
    }
    private void pruneRaw(String source,String document) {
        var versions=jdbc.queryForList("SELECT id FROM t_vendor_document WHERE source_id=? AND document_id=? AND raw_base64 IS NOT NULL ORDER BY current_version DESC,imported_at DESC,id DESC",String.class,source,document);
        for (int i=limits.getRetainRawVersions();i<versions.size();i++) jdbc.update("UPDATE t_vendor_document SET raw_base64=NULL WHERE id=?",versions.get(i));
    }
    private void aggregate(String source,String cve,String format,String publisher,String changedArchive) {
        var rows=jdbc.queryForList("""
                SELECT c.document,d.id,d.sha256,d.document_id,d.origin_kind FROM t_vendor_contribution c JOIN t_vendor_document d ON d.id=c.raw_document_id
                WHERE c.source_id=? AND c.cve_id=? ORDER BY d.vendor_updated_at DESC,d.document_id LIMIT 65
                """,source,cve);
        if (rows.size()>64) throw VendorAdvisoryIndex.invalid();
        ObjectNode merged;
        var refs=new ArrayList<Map<String,Object>>();
        if (rows.isEmpty()) {
            merged=JsonUtils.mapper().createObjectNode().put("cve_id",cve).put("title",cve).put("severity",1).put("cvss",0)
                    .put("description","No current document in this publisher source reaffirms this CVE; no fixed or withdrawn state is inferred.")
                    .put("native_presence","not_reaffirmed").put("score_status","not_provided");
            merged.putArray("affected"); merged.putArray("vendor_advisories");
            refs.add(Map.of("id",changedArchive,"role","document_omission"));
        } else {
            merged=((ObjectNode)JsonUtils.read(rows.get(0).get("document").toString())).deepCopy();
            var rules=merged.putArray("affected"); var facts=merged.putArray("vendor_advisories");
            Set<String> unique=new HashSet<>(); double score=0;
            for (var row:rows) {
                JsonNode node=JsonUtils.read(row.get("document").toString()); score=Math.max(score,node.path("cvss").asDouble());
                for (var rule:node.path("affected")) if (unique.add(VulnerabilityEvidence.canonicalJson(rule))) rules.add(rule);
                for (var fact:node.path("vendor_advisories")) facts.add(fact);
                refs.add(Map.of("id",row.get("id"),"sha256",row.get("sha256"),"document_id",row.get("document_id"),"origin_kind",row.get("origin_kind")));
                if (rules.size()>200 || facts.size()>1000) throw VendorAdvisoryIndex.invalid();
            }
            merged.put("cvss",score).put("severity",score>=9?4:score>=7?3:score>=4?2:1);
        }
        catalog.nativeCves(source,List.of(merged),Map.of("native_format",format,"publisher",publisher,"raw_documents",refs,
                "signature_verified",false,"verification_note","Parsed native document and recorded transport origin; no publisher signature or live-host applicability verification."));
    }
    private static String originKind(LibraryProperties.Source source,String origin) {
        URIIdentity actual=new URIIdentity(origin),official=new URIIdentity(VendorAdvisoryIndex.DEFAULTS.get(source.getType()));
        return actual.equals(official)?"official_https":"configured_mirror";
    }
    private record URIIdentity(String scheme,String host,int port) {
        URIIdentity(String value) { this(java.net.URI.create(value).getScheme(),java.net.URI.create(value).getHost(),java.net.URI.create(value).getPort()); }
    }
    static String sha(byte[] raw) {
        try { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    public String configurationIssue(LibraryProperties.Source source) {
        try { validate(source); }
        catch (IllegalArgumentException e) { return "请检查厂商公告地址、包范围及显式产品映射"; }
        var pinned=jdbc.queryForList("SELECT configuration_sha256 FROM t_vendor_sync_state WHERE source_id=?",String.class,source.getId());
        return !pinned.isEmpty() && !pinned.get(0).equals(VendorAdvisoryIndex.fingerprint(source))
                ? "厂商来源身份或范围已变更，请退役旧来源并使用新来源标识" : "";
    }
    public Map<String,Object> state(String source) {
        var rows=jdbc.queryForList("SELECT discovered_count,pending_count,checked_count,updated_at FROM t_vendor_sync_state WHERE source_id=?",source);
        var result=new LinkedHashMap<String,Object>(rows.isEmpty()?Map.of():rows.get(0));
        result.put("archive_documents",jdbc.queryForObject("SELECT count(*) FROM t_vendor_document WHERE source_id=? AND current_version=1",Integer.class,source));
        result.put("scope","bounded_recent_discovery_and_previously_imported_documents");
        return result;
    }
    public Map<String,Object> documents(String source,int page,int size) {
        if (page<1 || page>100_000 || size<1 || size>100) throw VendorAdvisoryIndex.invalid();
        return Map.of("total",jdbc.queryForObject("SELECT count(*) FROM t_vendor_document WHERE source_id=?",Integer.class,source),
                "items",jdbc.queryForList("SELECT "+META+" FROM t_vendor_document WHERE source_id=? ORDER BY imported_at DESC,id DESC LIMIT ? OFFSET ?",source,size,(page-1)*size),"state",state(source));
    }
    public Map<String,Object> detail(String source,String id) {
        var rows=jdbc.queryForList("SELECT "+META+" FROM t_vendor_document WHERE source_id=? AND id=?",source,id);
        if (rows.isEmpty()) throw new IllegalArgumentException("公告原件不存在");
        var result=new LinkedHashMap<>(rows.get(0));
        result.put("contributions",jdbc.queryForList("SELECT cve_id FROM t_vendor_contribution WHERE source_id=? AND raw_document_id=? ORDER BY cve_id LIMIT 200",String.class,source,id));
        result.put("verification","原生格式已解析并记录传输来源；未验证厂商签名，也不代表当前主机补丁适用性");
        return result;
    }
    public byte[] raw(String source,String id) {
        var rows=jdbc.queryForList("SELECT raw_base64,sha256 FROM t_vendor_document WHERE source_id=? AND id=?",source,id);
        if (rows.isEmpty() || rows.get(0).get("raw_base64")==null) throw new IllegalArgumentException("原件不存在或已按保留策略清理，摘要记录仍保留");
        byte[] bytes=Base64.getDecoder().decode(rows.get(0).get("raw_base64").toString());
        if (!sha(bytes).equals(rows.get(0).get("sha256"))) throw new IllegalStateException("公告原件摘要校验失败");
        return bytes;
    }
}
