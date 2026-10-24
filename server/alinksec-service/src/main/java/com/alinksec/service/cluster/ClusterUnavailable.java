package com.alinksec.service.cluster;

/** Fixed error codes keep broker URIs, passwords and payloads out of public diagnostics. */
public final class ClusterUnavailable extends IllegalStateException {
    public ClusterUnavailable(String code) { super(code); }
}
