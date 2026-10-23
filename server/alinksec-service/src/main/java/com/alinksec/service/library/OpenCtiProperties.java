package com.alinksec.service.library;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="alinksec.opencti")
public class OpenCtiProperties {
    private int maxIndicators=25_000, maxPages=128, requestTimeoutMs=10_000, roundTimeoutMs=180_000;
    private long maxSnapshotBytes=32L<<20;
    public int getMaxIndicators(){return maxIndicators;}
    public void setMaxIndicators(int v){maxIndicators=v;}
    public int getMaxPages(){return maxPages;}
    public void setMaxPages(int v){maxPages=v;}
    public int getRequestTimeoutMs(){return requestTimeoutMs;}
    public void setRequestTimeoutMs(int v){requestTimeoutMs=v;}
    public int getRoundTimeoutMs(){return roundTimeoutMs;}
    public void setRoundTimeoutMs(int v){roundTimeoutMs=v;}
    public long getMaxSnapshotBytes(){return maxSnapshotBytes;}
    public void setMaxSnapshotBytes(long v){maxSnapshotBytes=v;}
    public void validate(){
        if(maxIndicators<1||maxIndicators>25_000||maxPages<1||maxPages>128
                ||requestTimeoutMs<100||requestTimeoutMs>30_000||roundTimeoutMs<1000||roundTimeoutMs>180_000
                ||maxSnapshotBytes<1024||maxSnapshotBytes>32L<<20)
            throw new IllegalArgumentException("OpenCTI 抓取边界配置无效");
    }
}
