package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Full text export avoids confusing a filtered page or recent delta with a complete snapshot. */
public final class MispAdapter {
    private MispAdapter() {}
    public static SignaturePackage fetch(LibraryProperties.Source source, FeedDownload download, LibraryProperties props) throws IOException {
        String issue = LibrarySchedule.configurationIssue(source);
        if (!issue.isEmpty()) throw new IllegalArgumentException(issue);
        String query = JsonUtils.write(Map.of(
                "returnFormat", "text", "type", "sha256", "published", true,
                "to_ids", true, "deleted", false, "enforceWarninglist", true,
                "tags", List.of(source.getMispTag())));
        // URL is the complete /attributes/restSearch endpoint, including an optional MISP subpath.
        try (var fetched = download.postJson(source.getUrl(),
                Map.of("Authorization", source.getApiKey(), "Accept", "application/json"), query)) {
            if (fetched.status() != 200) throw new IllegalArgumentException("MISP 必须返回完整导出");
            Map<String, SignaturePackage.Hash> raw = SignaturePackage.readHashes(Files.newInputStream(fetched.file()), props.getMaxHashes());
            if (raw.isEmpty()) throw new IllegalArgumentException("拒绝空 MISP 快照，已有库保留");
            Map<String, SignaturePackage.Hash> hashes = new TreeMap<>();
            for (String sha : raw.keySet()) hashes.put(sha, SignaturePackage.checkedHash(sha, "MISP.KnownHash", 4));
            return new SignaturePackage("", hashes, List.of());
        }
    }
}
