package com.alinksec.service.cluster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/** Slow webhook retries must not delay ownership renewal. Existing jobs retain their serial scheduler. */
@Configuration(proxyBeanMethods=false)
public class ClusterScheduling {
    @Bean(name="taskScheduler")
    @ConditionalOnMissingBean(name="taskScheduler")
    ThreadPoolTaskScheduler ordinary() { return scheduler(1,"scheduled-"); }
    @Bean(name="clusterScheduler")
    ThreadPoolTaskScheduler coordination() { return scheduler(4,"cluster-coordination-"); }
    private static ThreadPoolTaskScheduler scheduler(int size,String prefix) {
        var scheduler=new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(size);scheduler.setThreadNamePrefix(prefix);scheduler.setDaemon(true);
        scheduler.setRemoveOnCancelPolicy(true);scheduler.setAwaitTerminationSeconds(2);
        return scheduler;
    }
}
