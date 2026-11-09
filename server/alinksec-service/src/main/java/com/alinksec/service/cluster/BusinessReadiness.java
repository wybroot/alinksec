package com.alinksec.service.cluster;

import org.springframework.stereotype.Service;
import javax.sql.DataSource;
import java.util.concurrent.*;

/** One bounded probe worker: overload, dependency failures and timeouts fail closed. */
@Service
public class BusinessReadiness {
    private final DataSource source;
    private final ThreadPoolExecutor probes=new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(1),r->{var t=new Thread(r,"business-readiness");t.setDaemon(true);return t;});
    public BusinessReadiness(DataSource source){this.source=source;}
    public boolean ready(){
        Future<Boolean> check=null;
        try {
            check=probes.submit(()->{
                try(var connection=source.getConnection()) {
                    try {connection.setNetworkTimeout(Runnable::run,1000);}catch(java.sql.SQLFeatureNotSupportedException ignored){}
                    try(var statement=connection.createStatement()) {
                        statement.setQueryTimeout(1);
                        try(var rows=statement.executeQuery("SELECT (SELECT COUNT(*) FROM t_agent WHERE 1=0)+(SELECT COUNT(*) FROM t_user WHERE 1=0)+(SELECT COUNT(*) FROM t_user_session WHERE 1=0)+(SELECT COUNT(*) FROM t_command WHERE 1=0)+(SELECT COUNT(*) FROM t_report_dedup WHERE 1=0)")){if(!rows.next())return false;}
                        // One namespaced housekeeping row proves write access without touching business facts.
                        return statement.executeUpdate("INSERT INTO t_report_dedup(report_id,expire_at) VALUES ('business-readiness-probe',CURRENT_TIMESTAMP) ON CONFLICT(report_id) DO UPDATE SET expire_at=excluded.expire_at")==1;
                    }
                }
            });
            return check.get(1500,TimeUnit.MILLISECONDS);
        }catch(Exception failure){if(check!=null)check.cancel(true);probes.purge();if(failure instanceof InterruptedException)Thread.currentThread().interrupt();return false;}
    }
    @jakarta.annotation.PreDestroy public void close(){probes.shutdownNow();}
}
