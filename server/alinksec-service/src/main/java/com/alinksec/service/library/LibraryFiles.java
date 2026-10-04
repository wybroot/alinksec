package com.alinksec.service.library;

import com.alinksec.service.config.AlinkSecProperties;
import jakarta.annotation.PreDestroy;
import org.springframework.core.io.Resource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.UUID;

/** Stores immutable library artifacts. Downloads keep the existing Agent CA/token boundary. */
@Service
public class LibraryFiles {
    public record Download(Resource resource, long size) {}
    private final LibraryProperties props;
    private final AlinkSecProperties platform;
    private S3Client s3;
    public LibraryFiles(LibraryProperties props, AlinkSecProperties platform) {
        this.props = props;
        this.platform = platform;
        if (!"local".equals(props.getStorage().getBackend()) && !"s3".equals(props.getStorage().getBackend())) {
            throw new IllegalArgumentException("libraries.storage.backend must be local or s3");
        }
    }
    public Path temporary(String suffix) throws IOException {
        Path dir = Path.of(props.getWorkDir()).resolve("tmp");
        Files.createDirectories(dir);
        return Files.createTempFile(dir, "library-", suffix);
    }
    public Path localPath(String namespace, String key) {
        validateKey(key);
        String dir = switch (namespace) {
            case "signature" -> platform.getSignature().getStorageDir();
            case "patch" -> platform.getPatch().getStorageDir();
            default -> throw new IllegalArgumentException("Unknown artifact namespace");
        };
        return Path.of(dir).resolve(key);
    }
    public void put(String namespace, String key, Path file) throws IOException {
        Path dest = localPath(namespace, key);
        if ("s3".equals(props.getStorage().getBackend())) {
            try {
                client().putObject(b -> b.bucket(props.getStorage().getBucket()).key(objectKey(namespace, key)), RequestBody.fromFile(file));
            } catch (RuntimeException e) { throw new IOException("Object storage upload failed", e); }
        } else {
            Files.createDirectories(dest.getParent());
            Path tmp = dest.resolveSibling(key + "." + UUID.randomUUID() + ".tmp");
            try {
                Files.copy(file, tmp);
                Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE);
            } finally { Files.deleteIfExists(tmp); }
        }
    }
    public Download download(String namespace, String key) throws IOException {
        Path local = localPath(namespace, key);
        // Existing local artifacts remain readable when S3 is enabled.
        if (Files.isRegularFile(local)) return new Download(new FileSystemResource(local), Files.size(local));
        if (!"s3".equals(props.getStorage().getBackend())) return null;
        try {
            var stream = client().getObject(b -> b.bucket(props.getStorage().getBucket()).key(objectKey(namespace, key)));
            return new Download(new InputStreamResource(stream), stream.response().contentLength());
        } catch (S3Exception e) {
            if (e.statusCode() == 404) return null;
            throw new IOException("Object storage download failed", e);
        } catch (RuntimeException e) { throw new IOException("Object storage download failed", e); }
    }
    public void copyTo(String namespace, String key, Path destination) throws IOException {
        Download download = download(namespace, key);
        if (download == null) throw new IOException("Library artifact is missing");
        try (InputStream in = download.resource().getInputStream()) {
            Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }
    public void delete(String namespace, String key) throws IOException {
        Path local = localPath(namespace, key);
        if ("s3".equals(props.getStorage().getBackend())) {
            try { client().deleteObject(b -> b.bucket(props.getStorage().getBucket()).key(objectKey(namespace, key))); }
            catch (RuntimeException e) { throw new IOException("Object storage deletion failed", e); }
        }
        Files.deleteIfExists(local);
    }
    private String objectKey(String ns, String key) {
        String prefix = props.getStorage().getPrefix().replaceAll("^/+|/+$", "");
        return (prefix.isEmpty() ? "" : prefix + "/") + ns + "/" + key;
    }
    private synchronized S3Client client() {
        if (s3 == null) {
            var cfg = props.getStorage();
            if (cfg.getBucket().isBlank() || cfg.getAccessKey().isBlank() || cfg.getSecretKey().isBlank()) {
                throw new IllegalArgumentException("S3 bucket and credentials are required");
            }
            var builder = S3Client.builder().region(Region.of(cfg.getRegion()))
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(cfg.getAccessKey(), cfg.getSecretKey())))
                    .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(10)).socketTimeout(Duration.ofSeconds(60)))
                    .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofMinutes(10)).apiCallAttemptTimeout(Duration.ofMinutes(5)))
                    .forcePathStyle(true);
            if (!cfg.getEndpoint().isBlank()) builder.endpointOverride(URI.create(cfg.getEndpoint()));
            s3 = builder.build();
        }
        return s3;
    }
    public static void validateKey(String key) {
        if (key == null || !key.matches("[\\p{L}\\p{N}._~+()@\\[\\]%-]{1,255}") || key.contains("..")) throw new IllegalArgumentException("Invalid artifact key");
    }
    @PreDestroy public synchronized void close() { if (s3 != null) s3.close(); }
}
