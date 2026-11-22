package review.console;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.AppenderBase;
import com.alinksec.bootstrap.BootstrapApplication;
import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.LoggerFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

/** Explicit test-classpath executable. Requests use the real HTTP/filter/controller/service path. */
public final class ConsoleAcceptance {
    private final Path control, output;
    private final Set<String> secrets = new LinkedHashSet<>();
    private final List<Map<String,Object>> observations = new ArrayList<>();
    private final Map<String,Object> cases = new LinkedHashMap<>();
    private final JdbcTemplate jdbc;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String base, initialPassword;
    private String admin, viewer, operator, agent;

    private ConsoleAcceptance(ServletWebServerApplicationContext app, Path control) throws Exception {
        this.control=control;output=control.resolve("public");Files.createDirectory(output);
        jdbc=app.getBean(JdbcTemplate.class);base="http://127.0.0.1:"+app.getWebServer().getPort();
        initialPassword=Objects.requireNonNull(System.getenv("ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD"));secrets.add(initialPassword);
    }
    public static void main(String[] args) {
        int exit=1;
        try (var app=(ServletWebServerApplicationContext)new SpringApplicationBuilder(BootstrapApplication.class).run(args)) {
            var check=new ConsoleAcceptance(app,Path.of(Objects.requireNonNull(System.getenv("ALINKSEC_CONSOLE_CONTROL_DIR"))));
            try { check.run();exit=0; }
            finally {
                Path privateFile=check.control.resolve("secrets.json");
                Files.writeString(privateFile,JsonUtils.write(check.secrets));
                Files.setPosixFilePermissions(privateFile,PosixFilePermissions.fromString("rw-------"));
                check.http.close();
            }
        } catch(Throwable failure) { failure.printStackTrace(); }
        System.exit(exit);
    }
    private static void require(boolean condition,String message) {if(!condition)throw new IllegalStateException(message);}
    private String secret() {String value="Console-"+UUID.randomUUID();secrets.add(value);return value;}
    private static String sha(String value) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
    private JsonNode safe(Object value) {
        String text=JsonUtils.write(value);
        for(String secret:secrets)text=text.replace(secret,"[removed]");
        return JsonUtils.read(text);
    }
    private record Reply(int status,JsonNode body,int index) {JsonNode data(){return body.path("data");}}
    private Reply request(String name,String role,String token,String method,String path,Object body,int status,int code) throws Exception {
        if(body instanceof Map<?,?> map)map.forEach((key,value)->{if(key.toString().toLowerCase(Locale.ROOT).contains("password") && value instanceof String text)secrets.add(text);});
        var builder=HttpRequest.newBuilder(URI.create(base+path)).timeout(Duration.ofSeconds(8)).header("Content-Type","application/json");
        if(token!=null)builder.header("Authorization","Bearer "+token);
        var response=http.send(builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(JsonUtils.write(body))).build(),HttpResponse.BodyHandlers.ofString());
        require(response.body().getBytes(StandardCharsets.UTF_8).length<=1024*1024,"HTTP response exceeds fixed 1 MiB acceptance bound: "+name);
        JsonNode document=JsonUtils.read(response.body());
        if(path.equals("/api/auth/login") && document.path("code").asInt(-1)==0)secrets.add(document.path("data").path("token").asText());
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("role",role);row.put("method",method);row.put("path",path);
        row.put("status",response.statusCode());row.put("response",safe(document));row.put("tokenSHA256",token==null?"":sha(token));
        if(body instanceof Map<?,?> map) {
            Map<String,Object> metadata=new LinkedHashMap<>();
            map.forEach((key,value)->metadata.put(key.toString(),key.toString().toLowerCase(Locale.ROOT).contains("password")?"[submitted]":value));row.put("request",metadata);
        }
        observations.add(row);
        require(response.statusCode()==status && document.path("code").asInt(-1)==code,"Unexpected HTTP/application response: "+name+" status="+response.statusCode()+" code="+document.path("code").asInt(-1));
        return new Reply(response.statusCode(),document,observations.size()-1);
    }
    private Reply get(String name,String role,String token,String path) throws Exception {return request(name,role,token,"GET",path,null,200,0);}
    private String login(String name,String password,String label) throws Exception {return request(label,"login",null,"POST","/api/auth/login",Map.of("username",name,"password",password),200,0).data().path("token").asText();}
    private Reply action(String name,String token,String method,String path,Object body) throws Exception {return request(name,"admin",token,method,path,body,200,0);}
    private void capture(String name,Reply reply) {cases.put(name,observations.get(reply.index()));}
    private void users(String name) throws Exception {capture(name,get(name,"admin",admin,"/api/users?page=1&size=100"));rememberHashes();}
    private void rememberHashes(){secrets.addAll(jdbc.queryForList("SELECT password_hash FROM t_user",String.class));}
    private long userId(String name){return jdbc.queryForObject("SELECT id FROM t_user WHERE username=?",Long.class,name);}
    private JsonNode userState(long id){return JsonUtils.read(JsonUtils.write(jdbc.queryForMap("SELECT id,role_id,status,auth_version,password_hash FROM t_user WHERE id=?",id)));}
    private Reply create(String name,String password,String role,String label) throws Exception {return action(label,admin,"POST","/api/users",Map.of("username",name,"realName","console fixture","password",password,"role",role));}

    private void accounts() throws Exception {
        admin=login("admin",initialPassword,"bootstrap-login");String second=login("admin",initialPassword,"second-bootstrap-session");rememberHashes();
        String changed=secret();users("users-before-create");
        capture("password-rejected",request("password-rejected","admin",admin,"POST","/api/auth/password",Map.of("oldPassword","incorrect-fixture-password","password",changed),400,10001));
        get("failed-change-keeps-session","admin",admin,"/api/users");
        capture("password-changed",action("password-changed",admin,"POST","/api/auth/password",Map.of("oldPassword",initialPassword,"password",changed)));rememberHashes();
        capture("old-admin-session-denied",request("old-admin-session-denied","admin",admin,"GET","/api/users",null,401,40100));
        request("second-admin-session-denied","admin",second,"GET","/api/users",null,401,40100);
        capture("old-password-login-denied",request("old-password-login-denied","login",null,"POST","/api/auth/login",Map.of("username","admin","password",initialPassword),200,40101));
        admin=login("admin",changed,"new-password-login");capture("new-password-login",new Reply(200,null,observations.size()-1));
        String managedPassword=secret();capture("user-created",create("console-managed",managedPassword,"viewer","user-created"));users("users-created");
        long managed=userId("console-managed");String managedSession=login("console-managed",managedPassword,"managed-session");
        capture("user-promoted",action("user-promoted",admin,"PUT","/api/users/"+managed,Map.of("role","operator","status","1","version","0")));users("users-promoted");
        request("role-change-revokes-session","viewer",managedSession,"GET","/api/alerts",null,401,40100);
        String promoted=login("console-managed",managedPassword,"promoted-login");
        capture("user-disabled",action("user-disabled",admin,"PUT","/api/users/"+managed,Map.of("role","operator","status","0","version","1")));users("users-disabled");
        request("disable-revokes-session","operator",promoted,"GET","/api/alerts",null,401,40100);
        request("disabled-login-denied","login",null,"POST","/api/auth/login",Map.of("username","console-managed","password",managedPassword),200,40101);
        String reset=secret();capture("user-reset",action("user-reset",admin,"PUT","/api/users/"+managed,Map.of("role","viewer","status","1","version","2","password",reset)));users("users-reset");
        request("reset-old-password-denied","login",null,"POST","/api/auth/login",Map.of("username","console-managed","password",managedPassword),200,40101);
        String own=login("console-managed",reset,"reset-new-password-login"),ownSecond=login("console-managed",reset,"reset-second-session");
        JsonNode before=userState(userId("admin"));long count=jdbc.queryForObject("SELECT count(*) FROM t_user",Long.class);
        capture("viewer-user-create-denied",request("viewer-user-create-denied","viewer",own,"POST","/api/users",Map.of("username","forbidden","password",secret(),"role","admin"),403,40301));
        request("viewer-user-edit-denied","viewer",own,"PUT","/api/users/"+userId("admin"),Map.of("role","viewer","status","0","version","1"),403,40301);
        require(count==jdbc.queryForObject("SELECT count(*) FROM t_user",Long.class) && before.equals(userState(userId("admin"))),"denied account mutation changed database");
        String self=secret();capture("viewer-password-changed",request("viewer-password-changed","viewer",own,"POST","/api/auth/password",Map.of("oldPassword",reset,"password",self,"uid",userId("admin")),200,0));rememberHashes();
        request("self-change-revokes-first-session","viewer",own,"GET","/api/alerts",null,401,40100);
        request("self-change-revokes-second-session","viewer",ownSecond,"GET","/api/alerts",null,401,40100);
        request("self-old-password-denied","login",null,"POST","/api/auth/login",Map.of("username","console-managed","password",reset),200,40101);
        String fresh=login("console-managed",self,"self-new-password-login");capture("viewer-new-password-login",new Reply(200,null,observations.size()-1));
        get("fresh-self-session-readable","viewer",fresh,"/api/alerts");
        require(before.equals(userState(userId("admin"))),"self-service password changed another principal");
        String matrix=secret();create("console-viewer",matrix,"viewer","create-matrix-viewer");create("console-operator",matrix,"operator","create-matrix-operator");
        viewer=login("console-viewer",matrix,"viewer-login");operator=login("console-operator",matrix,"operator-login");
        capture("viewer-role-login",new Reply(200,null,observations.size()-2));capture("operator-role-login",new Reply(200,null,observations.size()-1));
        Map<String,Object> facts=new LinkedHashMap<>();facts.put("managedUserId",managed);facts.put("admin",jdbc.queryForMap("SELECT username,role_id,status,auth_version FROM t_user WHERE username='admin'"));
        facts.put("managed",jdbc.queryForMap("SELECT username,role_id,status,auth_version FROM t_user WHERE id=?",managed));
        facts.put("managedRemainingSessions",jdbc.queryForObject("SELECT count(*) FROM t_user_session WHERE user_id=?",Integer.class,managed));
        facts.put("deniedAccountMutationsUnchanged",true);facts.put("selfServiceCannotSelectAnotherUser",true);write("account-facts.json",facts);
    }
    private void seed() {
        agent="console-"+UUID.randomUUID();jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status,last_heartbeat,maintenance_until) VALUES(?,?,?,1,1,CURRENT_TIMESTAMP,?)",agent,"console-fixture","192.0.2.55",System.currentTimeMillis()/1000+3600);
        for(int i=0;i<105;i++)jdbc.update("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,severity_source,title,detail,status) VALUES(?,?,?,?,'agent_proto_v1',?,'{}',?)",UUID.randomUUID().toString(),agent,"process",i==0?5:2,"console-alert-"+i,i==0?0:2);
        for(int i=0;i<121;i++) {
            var time=java.sql.Timestamp.valueOf(java.time.LocalDateTime.of(2026,1,1,0,0).plusSeconds(i));
            jdbc.update("INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,severity,created_at) VALUES(0,?,?,?,3,?)",agent,"CVE-2099-"+(10000+i),"console-software-"+i,time);
            jdbc.update("INSERT INTO t_virus_finding(agent_id,path,name,sha256,engine,severity,created_at) VALUES(?,?,?,?,'hash',3,?)",agent,"/fixture/"+i,"console-harmless-"+i,"a".repeat(64),time);
            jdbc.update("INSERT INTO t_audit_log(username,method,path,status) VALUES('console-fixture','GET','/fixture',200)");
        }
        for(int i=0;i<521;i++)jdbc.update("INSERT INTO t_asset_software(agent_id,name,version,source) VALUES(?,?,?,'dpkg')",agent,"console-software-"+String.format("%04d",i),"1");
    }
    private void alerts() throws Exception {
        capture("alerts-page-one",get("alerts-page-one","admin",admin,"/api/alerts?page=1&size=100"));
        capture("alerts-page-two",get("alerts-page-two","admin",admin,"/api/alerts?page=2&size=100"));
        Reply open=get("alerts-open","admin",admin,"/api/alerts?page=1&size=100&status=-1");capture("alerts-open",open);
        capture("alerts-critical",get("alerts-critical","admin",admin,"/api/alerts?page=1&size=100&severity=4&maxSeverity=4"));
        Reply empty=get("alerts-empty","admin",admin,"/api/alerts?page=1&size=100&severity=3&maxSeverity=3");capture("alerts-empty",empty);
        require(empty.data().path("total").asInt()==0 && empty.data().path("list").isEmpty(),"expected actual empty alert filter");
        long id=jdbc.queryForObject("SELECT id FROM t_alert WHERE agent_id=? AND status=0",Long.class,agent);
        capture("alert-target",new Reply(200,null,open.index()));
        var commandBefore=jdbc.queryForList("SELECT cmd_id,status,type FROM t_command ORDER BY cmd_id");
        capture("viewer-handle-denied",request("viewer-handle-denied","viewer",viewer,"POST","/api/alerts/"+id+"/handle",Map.of("remark","标记已处理"),403,40301));
        require(jdbc.queryForObject("SELECT status FROM t_alert WHERE id=?",Integer.class,id)==0,"viewer changed alert");
        capture("alert-handled",action("alert-handled",admin,"POST","/api/alerts/"+id+"/handle",Map.of("remark","标记已处理")));
        var first=jdbc.queryForMap("SELECT status,handled_by,handle_remark,handled_at FROM t_alert WHERE id=?",id);
        capture("alert-duplicate-denied",request("alert-duplicate-denied","admin",admin,"POST","/api/alerts/"+id+"/handle",Map.of("remark","overwrite attempt"),200,30001));
        capture("alert-missing-denied",request("alert-missing-denied","admin",admin,"POST","/api/alerts/9223372036854775807/handle",Map.of("remark","标记已处理"),200,30001));
        require(first.equals(jdbc.queryForMap("SELECT status,handled_by,handle_remark,handled_at FROM t_alert WHERE id=?",id)),"duplicate marking overwrote terminal metadata");
        require(commandBefore.equals(jdbc.queryForList("SELECT cmd_id,status,type FROM t_command ORDER BY cmd_id")),"manual marking issued an Agent command");
        capture("alerts-open-after-handle",get("alerts-open-after-handle","admin",admin,"/api/alerts?page=1&size=100&status=-1"));
        capture("alerts-all-after-handle",get("alerts-all-after-handle","admin",admin,"/api/alerts?page=1&size=100"));
        write("alert-facts.json",Map.of("targetId",id,"firstTerminalState",first,"duplicatePreservesTerminalState",true,"commandRowsBefore",commandBefore,"commandRowsAfter",jdbc.queryForList("SELECT cmd_id,status,type FROM t_command ORDER BY cmd_id"),"actualSecurityActionsSupportedByThisMarkingOperation",false));
    }
    private record Endpoint(String name,String path,String table,String condition,int cap,boolean array,boolean adminOnly) {}
    private JsonNode rows(Reply reply,Endpoint endpoint){return endpoint.array()?reply.data():reply.data().path("list");}
    private void pagination() throws Exception {
        List<Endpoint> endpoints=List.of(new Endpoint("alerts","/api/alerts","t_alert","status<>9",100,false,false),
                new Endpoint("vulnerabilities","/api/vuln/findings","t_vuln_finding","status IN(0,1)",100,false,false),
                new Endpoint("viruses","/api/virus/findings","t_virus_finding","1=1",100,false,false),
                new Endpoint("audit","/api/audit/logs","t_audit_log","1=1",100,false,true),
                new Endpoint("software","/api/hosts/"+agent+"/software","t_asset_software","agent_id='"+agent+"'",500,true,false));
        List<Map<String,Object>> facts=new ArrayList<>();
        var invalid=List.of("page=-1&size=7","page=0&size=7","page=-2147483648&size=7","page=2147483648&size=7",
                "page=9223372036854775807&size=7","page=999999999999999999999&size=7","page=2147483647&size=2",
                "page=1073741825&size=2","page=1&size=-1","page=1&size=0","page=1&size=-2147483648",
                "page=1&size=2147483648","page=1&size=9223372036854775807","page=1&size=999999999999999999999",
                "page=1&size=7&pageSize=-1","page=1&size=7&pageSize=0","page=1&size=7&limit=-1","page=1&size=7&limit=2147483648");
        for(var endpoint:endpoints) {
            long expected=jdbc.queryForObject("SELECT count(*) FROM "+endpoint.table()+" WHERE "+endpoint.condition(),Long.class);
            for(var principal:Map.of("admin",admin,"operator",operator,"viewer",viewer).entrySet()) {
                String role=principal.getKey(),token=principal.getValue(),prefix="page-"+endpoint.name()+"-"+role+"-";
                boolean forbidden=endpoint.adminOnly() && !role.equals("admin");
                for(int i=0;i<invalid.size();i++)request(prefix+"invalid-"+i,role,token,"GET",endpoint.path()+"?"+invalid.get(i),null,forbidden?403:400,forbidden?40301:10001);
                if(forbidden) {request(prefix+"normal",role,token,"GET",endpoint.path()+"?page=1&size=7",null,403,40301);continue;}
                for(String query:List.of("page=1&size=7","page=2&size=7","page=1&size="+(endpoint.cap()+1),"page=1&size=2147483647","page=2147483647&size=1","page=1073741824&size=2")) {
                    Reply reply=get(prefix+query,role,token,endpoint.path()+"?"+query);
                    int cap=Math.min(Integer.parseInt(query.substring(query.indexOf("size=")+5)),endpoint.cap());
                    require(rows(reply,endpoint).isArray() && rows(reply,endpoint).size()<=cap,"unbounded list: "+prefix+query);
                    if(!endpoint.array())require(reply.data().path("total").asLong(-1)==expected,"incorrect independent SQL count: "+prefix);
                    if(query.startsWith("page=1&size="))require(rows(reply,endpoint).size()==Math.min(expected,cap),"normalized size differs: "+prefix);
                    if(query.startsWith("page=2147483647") || query.startsWith("page=1073741824"))require(rows(reply,endpoint).isEmpty(),"large safe offset returned data");
                }
                facts.add(Map.of("endpoint",endpoint.name(),"role",role,"independentSqlCount",expected,"cap",endpoint.cap(),"responseHasTotal",!endpoint.array(),"invalidQueries",invalid.size()));
            }
            Set<String> seen=new LinkedHashSet<>();int pages=0;
            for(int page=1;;page++) {
                Reply reply=get("traverse-"+endpoint.name()+"-"+page,"admin",admin,endpoint.path()+"?page="+page+"&size=20");JsonNode rows=rows(reply,endpoint);pages++;
                for(JsonNode row:rows)require(seen.add(endpoint.array()?row.path("name").asText():row.path("id").asText()),"normal pages repeat an item: "+endpoint.name());
                if(rows.size()<20)break;require(page<100,"bounded fixture traversal exceeded 100 pages");
            }
            String column=endpoint.array()?"name":"CAST(id AS TEXT)";
            require(seen.equals(new HashSet<>(jdbc.queryForList("SELECT "+column+" FROM "+endpoint.table()+" WHERE "+endpoint.condition(),String.class))),"normal pages omitted SQL facts: "+endpoint.name());
            facts.add(Map.of("endpoint",endpoint.name(),"traversedPages",pages,"uniqueRows",seen.size(),"matchesIndependentSql",true));
        }
        write("pagination-facts.json",Map.of("invalidQueries",invalid,"endpoints",facts,"auditLowPrivilegeResponse",403));
    }
    private static final class Capture extends AppenderBase<ILoggingEvent> {
        final StringBuilder text=new StringBuilder();boolean exceeded;
        @Override protected synchronized void append(ILoggingEvent event) {
            String line=event.getLoggerName()+" "+event.getFormattedMessage()+"\n"+(event.getThrowableProxy()==null?"":ThrowableProxyUtil.asString(event.getThrowableProxy()));
            if(text.length()+line.length()>2*1024*1024){exceeded=true;return;}text.append(line);
        }
        synchronized String snapshot(){require(!exceeded,"application event capture exceeded 2 MiB");return text.toString();}
    }
    private void write(String name,Object value) throws Exception {Files.writeString(output.resolve(name),JsonUtils.write(value)+"\n");}
    private void run() throws Exception {
        Logger logger=(Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);var capture=new Capture();capture.setContext(logger.getLoggerContext());capture.start();logger.addAppender(capture);
        try {
            LoggerFactory.getLogger(ConsoleAcceptance.class).info("review_console_actual_http_started");
            accounts();seed();alerts();pagination();
            for(String path:List.of("/api/upgrade/packages","/api/upgrade/versions","/api/notify/channels","/api/audit/logs?page=1&size=20"))capture("ancillary:"+path,get("ancillary:"+path,"admin",admin,path));
            rememberHashes();
            var audits=jdbc.queryForList("SELECT * FROM t_audit_log ORDER BY id");String rawAudit=JsonUtils.write(audits),events=capture.snapshot();
            require(audits.size()>121 && events.contains("review_console_actual_http_started"),"missing actual audit/log observations");
            for(String secret:secrets)require(!rawAudit.contains(secret) && !events.contains(secret),"submitted credential material entered application logging or audit");
            require(jdbc.queryForObject("SELECT count(*) FROM t_audit_log WHERE method='password_changed' AND path='/api/auth/password' AND body_digest IS NULL",Integer.class)>=2,"missing safe account audit facts");
            write("audit-rows.json",audits);Files.writeString(output.resolve("application-events.log"),events);
            write("log-checks.json",Map.of("applicationLogSHA256",sha(events),"applicationLogBytes",events.getBytes(StandardCharsets.UTF_8).length,"auditSHA256",sha(rawAudit+"\n"),"auditRows",audits.size(),"credentialValuesChecked",secrets.size(),"credentialLeakDetected",false,"scope","Actual logging events and complete database audit rows during these HTTP operations"));
            write("cases.json",cases);write("observations.json",observations);write("accepted.json",Map.of("accepted",true,"actualHttp",true,"database",System.getenv("SPRING_PROFILES_ACTIVE"),"requests",observations.size(),"cases",cases.size(),"syntheticDatabaseFixtures",true,"releaseOrDeployment",false));
            System.out.println("Console acceptance passed; requests="+observations.size());
        } finally {logger.detachAppender(capture);capture.stop();}
    }
}
