package com.alinksec.service.library;

import org.springframework.stereotype.Component;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Map;

/** Streaming, bounded HTTPS retrieval; redirects cannot forward provider credentials. */
@Component
public class FeedDownload {
    public record Result(Path file, int status, String etag, String modified) implements AutoCloseable {
        @Override public void close() throws IOException { Files.deleteIfExists(file); }
    }
    private final LibraryFiles files;
    private final LibraryProperties props;
    public FeedDownload(LibraryFiles files, LibraryProperties props) { this.files = files; this.props = props; }
    public Result fetch(String address, Map<String, String> headers, String form) throws IOException {
        return request(address, headers, form, "application/x-www-form-urlencoded");
    }
    public Result postJson(String address, Map<String, String> headers, String json) throws IOException {
        return request(address, headers, json, "application/json");
    }
    public static URI validateAddress(String address) {
        URI uri;
        try { uri = URI.create(address); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("远端地址格式非法"); }
        // Plain HTTP is accepted only for loopback integration fixtures, never remote hosts.
        boolean loopback = "http".equals(uri.getScheme()) && ("127.0.0.1".equals(uri.getHost()) || "localhost".equals(uri.getHost()) || "[::1]".equals(uri.getHost()));
        if ((!"https".equals(uri.getScheme()) && !loopback) || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) throw new IllegalArgumentException("远端数据源必须使用 HTTPS");
        return uri;
    }
    private Result request(String address, Map<String, String> headers, String body, String contentType) throws IOException {
        URI uri = validateAddress(address);
        Path tmp = files.temporary(".download");
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(10_000);
            connection.setReadTimeout(15_000);
            connection.setRequestProperty("User-Agent", "ALinkSec-LibrarySync/0.0.2");
            headers.forEach(connection::setRequestProperty);
            if (body != null) {
                connection.setRequestMethod("POST"); connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", contentType);
                byte[] requestBody = body.getBytes(StandardCharsets.UTF_8);
                connection.setFixedLengthStreamingMode(requestBody.length);
                try (var out = connection.getOutputStream()) { out.write(requestBody); }
            }
            int status = connection.getResponseCode();
            if (status != 200 && status != 304) throw new IOException("远端返回 HTTP " + status);
            if (connection.getContentLengthLong() > props.getMaxDownloadBytes()) throw new IOException("远端数据超过下载大小上限");
            if (status == 200) {
                long deadline = System.nanoTime() + 120_000_000_000L;
                try (InputStream in = connection.getInputStream(); OutputStream out = Files.newOutputStream(tmp)) {
                    byte[] buffer = new byte[8192]; int n; long size = 0;
                    while ((n = in.read(buffer)) != -1) {
                        size += n;
                        if (size > props.getMaxDownloadBytes() || System.nanoTime() > deadline) throw new IOException("远端下载超过大小或时间上限");
                        out.write(buffer, 0, n);
                    }
                    if (connection.getContentLengthLong() >= 0 && size != connection.getContentLengthLong())
                        throw new IOException("远端响应未完整下载");
                }
            }
            return new Result(tmp, status, value(connection.getHeaderField("ETag"), 512), value(connection.getHeaderField("Last-Modified"), 128));
        } catch (IOException | RuntimeException e) { Files.deleteIfExists(tmp); throw e; }
        finally { if (connection != null) connection.disconnect(); }
    }
    private static String value(String text, int max) { return text == null ? "" : text.substring(0, Math.min(text.length(), max)); }
}
