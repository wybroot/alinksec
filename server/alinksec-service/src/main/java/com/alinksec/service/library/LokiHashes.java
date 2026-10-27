package com.alinksec.service.library;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Signature-Base hash-iocs.txt is a complete, mixed MD5/SHA1/SHA256 snapshot. */
public final class LokiHashes {
    private LokiHashes() {}
    public static SignaturePackage read(InputStream input, int max) throws IOException {
        Map<String, SignaturePackage.Hash> hashes = new TreeMap<>();
        try (var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8.newDecoder()))) {
            String line;
            while ((line = SignaturePackage.readLine(reader)) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int separator = line.indexOf(';');
                if (separator < 1) throw new IllegalArgumentException("LOKI hash record is invalid");
                String hash = line.substring(0, separator).trim();
                if (!hash.matches("(?i)([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})"))
                    throw new IllegalArgumentException("LOKI hash record is invalid");
                if (hash.length() != 64) continue;
                hashes.put(hash.toLowerCase(Locale.ROOT), SignaturePackage.checkedHash(hash, "LOKI.SignatureBase.KnownHash", 4));
                if (hashes.size() > max) throw new IllegalArgumentException("LOKI hash capacity exceeded");
            }
        }
        if (hashes.isEmpty()) throw new IllegalArgumentException("LOKI snapshot has no SHA256 records");
        return new SignaturePackage("", hashes, List.of());
    }
}
