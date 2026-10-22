package com.alinksec.service.library;

import org.springframework.stereotype.Component;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Map;
import java.util.List;
import java.nio.ByteBuffer;
import java.net.http.*;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.Flow;

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
    private static final HttpClient BOUNDED_CLIENT=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
    /** Absolute deadline includes DNS, headers and body; the subscriber cancels before buffering excess bytes. */
    public Result fetchBounded(String address,Map<String,String> headers,long limit,int timeoutMs)throws IOException {
        if(limit<1||timeoutMs<100||timeoutMs>30_000)throw new IllegalArgumentException("下载边界无效");
        long cap=Math.min(limit,props.getMaxDownloadBytes());if(cap<1)throw new IllegalArgumentException("下载上限无效");
        var request=HttpRequest.newBuilder(validateAddress(address)).timeout(Duration.ofMillis(timeoutMs)).header("User-Agent","ALinkSec-BaselineUpstream/1");
        headers.forEach(request::header);
        Path tmp=files.temporary(".download");CompletableFuture<HttpResponse<byte[]>> pending=null;
        try {
            pending=BOUNDED_CLIENT.sendAsync(request.GET().build(),info->{
                if(info.statusCode()!=200&&info.statusCode()!=304)throw new IllegalArgumentException("远端状态无效");
                long size=info.statusCode()==304?0:info.headers().firstValueAsLong("Content-Length").orElse(-1);
                return new LimitedBody(cap,size);
            });
            var response=pending.get(timeoutMs,TimeUnit.MILLISECONDS);
            Files.write(tmp,response.body());
            return new Result(tmp,response.statusCode(),value(response.headers().firstValue("ETag").orElse(""),512),value(response.headers().firstValue("Last-Modified").orElse(""),128));
        }catch(InterruptedException e){Thread.currentThread().interrupt();Files.deleteIfExists(tmp);throw new IOException("下载中断");}
        catch(Exception e){Files.deleteIfExists(tmp);throw new IOException("远端下载超过边界、响应无效或连接失败");}
        finally{if(pending!=null&&!pending.isDone())pending.cancel(true);}
    }
    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final long limit,expected;
        private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body=new CompletableFuture<>();
        private Flow.Subscription subscription;
        LimitedBody(long limit,long expected){this.limit=limit;this.expected=expected;}
        public CompletionStage<byte[]> getBody(){return body;}
        public void onSubscribe(Flow.Subscription subscription){this.subscription=subscription;if(expected>limit){subscription.cancel();body.completeExceptionally(new IOException("下载大小超限"));}else subscription.request(1);}
        public void onNext(List<ByteBuffer> buffers){
            for(var buffer:buffers){if(bytes.size()+(long)buffer.remaining()>limit){subscription.cancel();body.completeExceptionally(new IOException("下载大小超限"));return;}byte[] chunk=new byte[buffer.remaining()];buffer.get(chunk);bytes.writeBytes(chunk);}subscription.request(1);
        }
        public void onError(Throwable error){body.completeExceptionally(error);}
        public void onComplete(){if(expected>=0&&bytes.size()!=expected)body.completeExceptionally(new IOException("响应未完整下载"));else body.complete(bytes.toByteArray());}
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
