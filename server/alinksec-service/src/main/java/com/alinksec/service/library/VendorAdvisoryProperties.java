package com.alinksec.service.library;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Native documents are bounded independently of signature packages. */
@Component
@ConfigurationProperties(prefix = "alinksec.vendor-advisories")
public class VendorAdvisoryProperties {
    private long maxArchiveBytes = 256L << 20;
    private int maxDocumentBytes = 32 << 20;
    private int documentsPerSync = 2;
    private int retainRawVersions = 2;
    public long getMaxArchiveBytes() { return maxArchiveBytes; }
    public void setMaxArchiveBytes(long v) { maxArchiveBytes = v; }
    public int getMaxDocumentBytes() { return maxDocumentBytes; }
    public void setMaxDocumentBytes(int v) { maxDocumentBytes = v; }
    public int getDocumentsPerSync() { return documentsPerSync; }
    public void setDocumentsPerSync(int v) { documentsPerSync = v; }
    public int getRetainRawVersions() { return retainRawVersions; }
    public void setRetainRawVersions(int v) { retainRawVersions = v; }
    public void validate() {
        if (maxArchiveBytes < (32L << 20) || maxArchiveBytes > (1024L << 20)
                || maxDocumentBytes < 1024 || maxDocumentBytes > (32 << 20)
                || documentsPerSync < 1 || documentsPerSync > 4
                || retainRawVersions < 1 || retainRawVersions > 10)
            throw new IllegalArgumentException("厂商公告容量配置非法");
    }
}
