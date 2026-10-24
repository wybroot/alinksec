package com.alinksec.service.cluster;

import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Redis time and a bounded client index give replicas one shared login failure budget. */
@Component
public class ClusterLoginLimiter {
    static final String SCRIPT="""
            local time=redis.call('TIME'); local now=time[1]*1000+math.floor(time[2]/1000)
            redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now)
            if ARGV[2]=='success' then redis.call('DEL',KEYS[2]);redis.call('ZREM',KEYS[1],ARGV[1]);return 1 end
            local locked=tonumber(redis.call('HGET',KEYS[2],'locked') or '0')
            if ARGV[2]=='check' then
              if locked>now then return 0 end
              if redis.call('EXISTS',KEYS[2])==0 and redis.call('ZCARD',KEYS[1])>=10000 then return 0 end
              return 1
            end
            if locked>now then return 0 end
            if redis.call('EXISTS',KEYS[2])==0 and redis.call('ZCARD',KEYS[1])>=10000 then return 0 end
            local started=tonumber(redis.call('HGET',KEYS[2],'started') or '0')
            local failures=tonumber(redis.call('HGET',KEYS[2],'failures') or '0')
            if now-started>=600000 then started=now;failures=0 end
            failures=failures+1
            if failures>=5 then locked=now+900000 else locked=0 end
            redis.call('HSET',KEYS[2],'started',started,'failures',failures,'locked',locked)
            redis.call('PEXPIRE',KEYS[2],1500000);redis.call('ZADD',KEYS[1],now+1500000,ARGV[1])
            redis.call('PEXPIRE',KEYS[1],1500000);return 1
            """;
    private final ClusterProperties properties;
    private final RedisLeases redis;
    public ClusterLoginLimiter(ClusterProperties properties,RedisLeases redis) {this.properties=properties;this.redis=redis;}
    public boolean enabled() {return properties.isEnabled();}
    public boolean apply(String address,String action) {
        if(!java.util.Set.of("check","failure","success").contains(action))throw new IllegalArgumentException();
        try {
            String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    (address==null || address.isBlank()?"unknown":address).getBytes(StandardCharsets.UTF_8)));
            return redis.loginLimit(hash,action);
        } catch(ClusterUnavailable failure) {throw failure;}
        catch(Exception failure) {throw new ClusterUnavailable("login_coordination_unavailable");}
    }
}
