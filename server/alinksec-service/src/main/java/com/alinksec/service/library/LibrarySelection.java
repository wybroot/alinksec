package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.scan.VulnerabilityEvidence;
import org.springframework.jdbc.core.JdbcTemplate;
import java.sql.*;
import java.util.*;
import java.util.function.Consumer;

/** Source authority is an administrator decision, never a claim taken from a feed. */
public final class LibrarySelection {
    public static final int MAX_CANDIDATES=128;
    public static final List<String> TIERS=List.of("unreviewed","reviewed","preferred");
    private final JdbcTemplate jdbc;
    public LibrarySelection(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    public static void validate(String kind,String key) {
        if (kind==null || !Set.of("hash","rule","cve").contains(kind) || key==null || key.isBlank() || key.length()>255
                || key.codePoints().anyMatch(Character::isISOControl)
                || "hash".equals(kind) && !key.matches("[a-f0-9]{64}")
                || "cve".equals(kind) && !key.matches("CVE-[0-9]{4}-[0-9]{4,19}"))
            throw new IllegalArgumentException("来源选择条目非法");
    }
    public static void sourceId(String id) {
        if (id==null || !id.matches("[A-Za-z0-9_-]{1,64}") || id.startsWith("_"))
            throw new IllegalArgumentException("来源标识非法");
    }
    static String digest(Object value) {
        return VulnerabilityEvidence.sha256(VulnerabilityEvidence.canonicalJson(JsonUtils.mapper().valueToTree(value)));
    }
    private static Object applicability(com.fasterxml.jackson.databind.JsonNode affected) {
        var rules=new TreeMap<String,com.fasterxml.jackson.databind.JsonNode>();
        for(var original:affected) {
            var rule=JsonUtils.mapper().createObjectNode();
            for(String field:List.of("name","source","os","match","vrange","ranges","version_scheme","distro_id","distro_version","architecture","fixed_version"))
                if(original.has(field))rule.set(field,original.get(field));
            if(original.path("evidence").isObject()) {
                var evidence=JsonUtils.mapper().createObjectNode();
                for(String field:List.of("basis","assessment","package_scope"))evidence.set(field,original.path("evidence").path(field));
                rule.set("evidence",evidence);
            }
            rule.put("comparable",VulnerabilityEvidence.comparable(original));
            rules.put(VulnerabilityEvidence.canonicalJson(rule),rule);
        }
        return rules.values();
    }
    private static String table(String kind) {
        return switch(kind) { case "hash" -> "t_security_hash"; case "rule" -> "t_security_rule";
            case "cve" -> "t_security_cve"; default -> throw new IllegalArgumentException("来源选择类型非法"); };
    }
    private static String keyColumn(String kind) {
        return switch(kind) { case "hash" -> "sha256"; case "rule" -> "name"; case "cve" -> "cve_id";
            default -> throw new IllegalArgumentException("来源选择类型非法"); };
    }
    private static String query(String kind,boolean single) {
        String key=keyColumn(kind);
        String fields="hash".equals(kind)?"c.name,c.severity": "c.document"+("cve".equals(kind)?",c.provenance,c.locally_withdrawn":"");
        return "SELECT c.source_id,c."+key+" AS item_key,"+fields+",COALESCE(p.tier,0) AS trust_tier,"
                +"COALESCE(p.priority,CASE WHEN c.source_id='manual' THEN 100 ELSE 0 END) AS source_priority,"
                +"COALESCE(p.quarantined,0) AS quarantined,COALESCE(p.revision,0) AS policy_revision,"
                +"d.action,d.selected_source,d.context_digest,d.revision AS decision_revision,d.actor AS decision_actor,"
                +"d.decided_at,d.note AS decision_note FROM "+table(kind)+" c "
                +"LEFT JOIN t_security_source_policy p ON p.source_id=c.source_id "
                +"LEFT JOIN t_security_source_lifecycle l ON l.source_id=c.source_id "
                +"LEFT JOIN t_security_item_decision d ON d.kind='"+kind+"' AND d.item_key=c."+key+" "
                +"WHERE COALESCE(l.retired,0)=0"+(single?" AND c."+key+"=?":"")
                +" ORDER BY c."+key+",trust_tier DESC,source_priority DESC,CASE WHEN c.source_id='manual' THEN 0 ELSE 1 END,c.source_id";
    }
    public record Choice(String kind,String key,Map<String,Object> proposed,boolean effective,String reason,
                         String contextDigest,List<Map<String,Object>> candidates,Map<String,Object> decision,
                         boolean documentConflict,boolean applicabilityConflict,int candidateCount,boolean contextComplete) {
        public Map<String,Object> summary() {
            Map<String,Object> value=new LinkedHashMap<>();
            value.put("kind",kind); value.put("key",key); value.put("effective",effective); value.put("reason",reason);
            value.put("contextDigest",contextDigest); value.put("candidateCount",candidateCount);value.put("contextComplete",contextComplete);
            value.put("selectedSource",effective?proposed.get("source_id"):"");
            value.put("proposedSource",proposed==null?"":proposed.get("source_id"));
            value.put("documentConflict",documentConflict); value.put("applicabilityConflict",applicabilityConflict);
            value.put("decision",decision); return value;
        }
    }
    /** The caller holds the catalog transaction lock when using a choice for publication or governance. */
    public Choice item(String kind,String key) {
        validate(kind,key); Group group=new Group(kind,key);
        jdbc.query(query(kind,true),(org.springframework.jdbc.core.RowCallbackHandler) rs -> group.add(rs),key);
        return group.finish();
    }
    /** PostgreSQL uses a cursor inside the catalog transaction; memory holds only one candidate group. */
    public void each(String kind,Consumer<Choice> consumer) {
        table(kind);
        jdbc.query(connection -> { var statement=connection.prepareStatement(query(kind,false)); statement.setFetchSize(256); return statement; },rs -> {
            Group group=null;
            while(rs.next()) {
                String key=rs.getString("item_key");
                if(group==null || !group.key.equals(key)) { if(group!=null)consumer.accept(group.finish()); group=new Group(kind,key); }
                group.add(rs);
            }
            if(group!=null)consumer.accept(group.finish()); return null;
        });
    }
    public Map<String,Object> keys(String kind,String keyword,boolean multiple,int page,int size) {
        String key=keyColumn(kind),where=" WHERE NOT EXISTS (SELECT 1 FROM t_security_source_lifecycle l WHERE l.source_id=c.source_id AND l.retired=1)";
        List<Object> args=new ArrayList<>();
        if(keyword!=null && !keyword.isBlank()) { if(keyword.length()>255)throw new IllegalArgumentException("查询过长"); where+=" AND LOWER(c."+key+") LIKE LOWER(?)";args.add("%"+keyword.trim()+"%"); }
        String groups="SELECT c."+key+" AS item_key FROM "+table(kind)+" c"+where+" GROUP BY c."+key+(multiple?" HAVING count(*)>1":"");
        Long total=jdbc.queryForObject("SELECT count(*) FROM ("+groups+") selection_keys",Long.class,args.toArray());
        args.add(size);args.add((long)(page-1)*size);
        var keys=jdbc.queryForList(groups+" ORDER BY item_key LIMIT ? OFFSET ?",String.class,args.toArray());
        return Map.of("list",keys.stream().map(k -> item(kind,k).summary()).toList(),"total",total==null?0:total);
    }
    public Map<String,Object> policy(String id) {
        sourceId(id);var rows=jdbc.queryForList("SELECT tier,priority,quarantined,revision,actor,updated_at,note FROM t_security_source_policy WHERE source_id=?",id);
        if(rows.isEmpty())return Map.of("tier","unreviewed","priority","manual".equals(id)?100:0,"quarantined",false,"revision",0L,"note","");
        Map<String,Object> result=new LinkedHashMap<>(rows.get(0));
        result.put("tier",TIERS.get(((Number)result.get("tier")).intValue()));
        result.put("quarantined",((Number)result.get("quarantined")).intValue()==1);return result;
    }
    /** Authorization-time guard also covers pre-migration effective CVEs that have not been rebuilt yet. */
    public boolean allowsCve(String id,String source,String ruleDigest) {
        var choice=item("cve",id);
        if(choice.candidates().isEmpty()) {
            // Historical direct t_cve_db rows retain their existing, limited semantics. Retired declarations do not.
            return ((Number)choice.decision().get("revision")).longValue()==0
                    && jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE cve_id=?",Long.class,id)==0;
        }
        if(!choice.effective() || choice.proposed()==null || !source.equals(choice.proposed().get("source_id")))return false;
        var row=choice.proposed();var document=JsonUtils.read(row.get("document").toString());
        return number(row,"locally_withdrawn")==0 && !"withdrawn".equals(document.path("status").asText())
                && ruleDigest.equals(VulnerabilityEvidence.ruleDigest(source,id,document.path("affected")));
    }
    private static long number(Map<String,Object> row,String field) { return row.get(field) instanceof Number n?n.longValue():0; }
    private static String text(Map<String,Object> row,String field) { return row.get(field)==null?"":row.get(field).toString(); }
    private final class Group {
        final String kind,key;
        final List<Map<String,Object>> candidates=new ArrayList<>();
        final Set<String> contentDigests=new HashSet<>(),topSemantics=new HashSet<>();
        Map<String,Object> best,chosen,representative,decision=new LinkedHashMap<>();
        int topTier=-1,topPriority=-1;
        int candidateCount;
        Group(String kind,String key) { this.kind=kind;this.key=key; }
        void add(ResultSet rs)throws SQLException {
            candidateCount++;
            // Old installations may already exceed the current bound. Hold them safely while allowing retirement to reduce the set.
            if(candidates.size()>=MAX_CANDIDATES)return;
            String source=rs.getString("source_id");int tier=rs.getInt("trust_tier"),priority=rs.getInt("source_priority");
            boolean eligible=rs.getInt("quarantined")==0;
            Map<String,Object> row=new LinkedHashMap<>();row.put("source_id",source);
            Object content,semantics;
            boolean withdrawn=false;
            if("hash".equals(kind)) {
                row.put("sha256",key);row.put("name",rs.getString("name"));row.put("severity",rs.getInt("severity"));
                content=Map.of("sha256",key,"name",row.get("name"),"severity",row.get("severity"));semantics=key;
            } else {
                String document=rs.getString("document");var node=JsonUtils.read(document);content=node;row.put("document",document);
                if("cve".equals(kind)) {
                    row.put("provenance",rs.getString("provenance"));row.put("locally_withdrawn",rs.getInt("locally_withdrawn"));
                    withdrawn=rs.getInt("locally_withdrawn")==1 || "withdrawn".equals(node.path("status").asText());
                    semantics=Map.of("withdrawn",withdrawn,"affected",applicability(node.path("affected")));
                } else semantics=node;
            }
            String contentDigest=digest(content),semanticDigest=digest(semantics);
            Map<String,Object> candidate=new LinkedHashMap<>();candidate.put("sourceId",source);candidate.put("documentDigest",contentDigest);
            candidate.put("applicabilityDigest",semanticDigest);candidate.put("tier",TIERS.get(tier));candidate.put("priority",priority);
            candidate.put("policyRevision",rs.getLong("policy_revision"));candidate.put("quarantined",!eligible);candidate.put("withdrawn",withdrawn);
            candidates.add(candidate);
            if(representative==null)representative=row;
            if(decision.isEmpty()) {
                decision.put("action",rs.getString("action")==null?"automatic":rs.getString("action"));
                decision.put("selectedSource",rs.getString("selected_source")==null?"":rs.getString("selected_source"));
                decision.put("contextDigest",rs.getString("context_digest")==null?"":rs.getString("context_digest"));
                decision.put("revision",rs.getLong("decision_revision"));decision.put("actor",rs.getObject("decision_actor"));
                decision.put("decidedAt",rs.getString("decided_at"));decision.put("note",rs.getString("decision_note"));
            }
            if(!eligible)return;
            contentDigests.add(contentDigest);
            if(best==null || tier>topTier || tier==topTier && priority>topPriority) {
                best=row;topTier=tier;topPriority=priority;topSemantics.clear();
            }
            if(tier==topTier && priority==topPriority) {
                topSemantics.add(semanticDigest);
                String current=text(best,"source_id");
                if("manual".equals(source) || !"manual".equals(current) && source.compareTo(current)<0)best=row;
            }
            if(source.equals(text(decision,"selectedSource")))chosen=row;
        }
        Choice finish() {
            candidates.sort(Comparator.comparing(c -> c.get("sourceId").toString()));
            String context=digest(Map.of("contract",1,"kind",kind,"key",key,"candidates",candidates,"candidateCount",candidateCount));
            if(decision.isEmpty()) {
                // A decision may outlive its last current source; keep revision/ABA protection visible.
                var rows=jdbc.queryForList("SELECT action,selected_source,context_digest,revision,actor,decided_at,note FROM t_security_item_decision WHERE kind=? AND item_key=?",kind,key);
                if(!rows.isEmpty()) {var d=rows.get(0);decision.put("action",d.get("action"));decision.put("selectedSource",d.get("selected_source"));decision.put("contextDigest",d.get("context_digest"));decision.put("revision",d.get("revision"));decision.put("actor",d.get("actor"));decision.put("decidedAt",d.get("decided_at"));decision.put("note",d.get("note"));}
                else decision.putAll(Map.of("action","automatic","selectedSource","","contextDigest","","revision",0L));
            }
            String action=text(decision,"action"),reason=best==null?"no_eligible_source":candidates.size()==1?"single_source":"ranked";
            boolean effective=best!=null;
            if(!"automatic".equals(action)) {
                if(!context.equals(text(decision,"contextDigest"))) {effective=false;reason="stale_decision";}
                else if("suppress".equals(action)) {effective=false;reason="suppressed";}
                else if(chosen==null) {effective=false;reason="source_unavailable";}
                else {best=chosen;reason="reviewed";}
            } else if(effective && topSemantics.size()>1 && !"hash".equals(kind)) {
                // Preserve a selected withdrawal tombstone; it must never activate a lower declaration.
                boolean tombstone="cve".equals(kind) && (number(best,"locally_withdrawn")==1 || "withdrawn".equals(JsonUtils.read(text(best,"document")).path("status").asText()));
                if(!tombstone) {effective=false;reason="unresolved_conflict";}
            }
            boolean complete=candidateCount<=MAX_CANDIDATES;
            if(!complete) {effective=false;reason="candidate_capacity";}
            if(best==null)best=representative; // Reporting metadata for a wholly quarantined item never becomes effective authority.
            return new Choice(kind,key,best,effective,reason,context,List.copyOf(candidates),Collections.unmodifiableMap(new LinkedHashMap<>(decision)),contentDigests.size()>1,topSemantics.size()>1,candidateCount,complete);
        }
    }
}
