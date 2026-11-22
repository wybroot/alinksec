package review.runtime;

import com.alinksec.bootstrap.BootstrapApplication;
import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.metrics.MetricsForwarder;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

/** Test-classpath-only launcher. No fault-control classes enter the production jar. */
public final class RuntimeFixtureServer {
    static Path directory;
    public static void main(String[] args) {
        directory=Path.of(Objects.requireNonNull(System.getenv("ALINKSEC_REVIEW_CONTROL_DIR"))).toAbsolutePath();
        if(!Files.isDirectory(directory))throw new IllegalArgumentException("isolated control directory required");
        var context=new SpringApplicationBuilder(BootstrapApplication.class,Fixture.class).run(args);
        var metrics=context.getBean(MetricsForwarder.class);
        var sampler=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"review-metrics-observer");t.setDaemon(true);return t;});
        sampler.scheduleWithFixedDelay(()->{
            try {Files.writeString(directory.resolve("metrics.jsonl"),JsonUtils.write(Map.of("at",System.currentTimeMillis(),"statistics",metrics.statistics()))+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);}
            catch(Exception e){throw new IllegalStateException(e);}
        },0,50,TimeUnit.MILLISECONDS);
        context.addApplicationListener(event->{if(event instanceof org.springframework.context.event.ContextClosedEvent)sampler.shutdownNow();});
        try {Files.writeString(directory.resolve("ready.json"),JsonUtils.write(Map.of("pid",ProcessHandle.current().pid(),"started",true))+"\n");}
        catch(Exception e){throw new IllegalStateException(e);}
    }
    @Configuration(proxyBeanMethods=false)
    static class Fixture {
        @Bean static BeanPostProcessor commitGate(BeanFactory factory) {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean,String name) {
                    if(!(bean instanceof PlatformTransactionManager delegate))return bean;
                    return new PlatformTransactionManager() {
                        public TransactionStatus getTransaction(TransactionDefinition definition){return delegate.getTransaction(definition);}
                        public void rollback(TransactionStatus status){delegate.rollback(status);}
                        public void commit(TransactionStatus status) {
                            Path armed=directory.resolve("armed.json");
                            if(!status.isNewTransaction() || !Files.isRegularFile(armed)){delegate.commit(status);return;}
                            try {
                                var input=JsonUtils.read(Files.readString(armed));
                                var jdbc=factory.getBean(JdbcTemplate.class);
                                String source=input.path("source").asText(),agent=input.path("agentId").asText(),report=input.path("reportId").asText();
                                if(jdbc.queryForObject("SELECT count(*) FROM t_agent_log WHERE agent_id=? AND source=?",Integer.class,agent,source)!=1){delegate.commit(status);return;}
                                int dedup=jdbc.queryForObject("SELECT count(*) FROM t_report_dedup WHERE report_id=?",Integer.class,key(agent,report));
                                if(dedup!=1 || !TransactionSynchronizationManager.isActualTransactionActive())throw new IllegalStateException("gate outside atomic report transaction");
                                String phase=input.path("phase").asText();
                                if(!Set.of("precommit","postcommit").contains(phase))throw new IllegalArgumentException("unknown gate");
                                if(phase.equals("postcommit"))delegate.commit(status);
                                var marker=Map.of("phase",phase,"agentId",agent,"reportId",report,"source",source,"businessRowsInside",1,"dedupRowsInside",dedup,
                                        "transactionActive",TransactionSynchronizationManager.isActualTransactionActive(),"pid",ProcessHandle.current().pid());
                                Path temporary=directory.resolve("reached.tmp");Files.writeString(temporary,JsonUtils.write(marker)+"\n");
                                Files.move(temporary,directory.resolve("reached.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
                                // The parent must kill this JVM. Never complete a blocked commit or send its receipt.
                                new CountDownLatch(1).await();
                                throw new IllegalStateException("unreachable gate release");
                            }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
                            catch(Exception e){throw new IllegalStateException("test commit gate failed",e);}
                        }
                    };
                }
            };
        }
        @Bean Probe runtimeProbe(JdbcTemplate jdbc,MetricsForwarder metrics){return new Probe(jdbc,metrics);}
    }
    static String key(String agent,String report) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((agent+"\0"+report).getBytes(StandardCharsets.UTF_8)));
    }
    @RestController
    static class Probe {
        private final JdbcTemplate jdbc;private final MetricsForwarder metrics;
        Probe(JdbcTemplate jdbc,MetricsForwarder metrics){this.jdbc=jdbc;this.metrics=metrics;}
        @GetMapping("/api/review-runtime/probe") public Map<String,Object> probe(@RequestParam String agent,@RequestParam(defaultValue="") String report,@RequestParam(defaultValue="") String source)throws Exception {
            return Map.of("business",jdbc.queryForObject("SELECT count(*) FROM t_agent_log WHERE agent_id=? AND source=?",Integer.class,agent,source),
                    "dedup",jdbc.queryForObject("SELECT count(*) FROM t_report_dedup WHERE report_id=?",Integer.class,key(agent,report)),
                    "heartbeat",Objects.toString(jdbc.queryForObject("SELECT CAST(last_heartbeat AS TEXT) FROM t_agent WHERE agent_id=?",String.class,agent),""),
                    "metrics",metrics.statistics(),"commands",jdbc.queryForList("SELECT cmd_id,status FROM t_command WHERE agent_id=? AND type='collect_now' ORDER BY created_at",agent));
        }
    }
}
