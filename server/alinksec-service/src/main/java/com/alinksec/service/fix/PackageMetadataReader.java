package com.alinksec.service.fix;

import com.alinksec.service.scan.PackageVersions;
import com.alinksec.service.scan.VulnerabilityScope;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/** Reads actual binary headers; header fields do not authenticate a vendor or a distribution claim. */
@Component
public class PackageMetadataReader {
    public record Metadata(String name, String version, String architecture, String source) {}
    private static final Semaphore PARSER = new Semaphore(1);
    static final int OUTPUT_LIMIT = 16 * 1024;
    static final Duration TIME_LIMIT = Duration.ofSeconds(10);

    public Metadata inspect(String type, Path file) throws IOException {
        if (!List.of("deb", "rpm").contains(type)) throw new IllegalArgumentException("仅支持 Linux 二进制 DEB/RPM，其他补丁请人工处理");
        if (!PARSER.tryAcquire()) throw new IllegalArgumentException("补丁解析正在进行，请稍后重试");
        Path directory = null;
        try {
            directory = Files.createTempDirectory("alinksec-patch-reader-");
            Path input = directory.resolve("package." + type);
            Files.copy(file, input);
            Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("r--r--r--"));
            Path temporary = Files.createDirectory(directory.resolve("tmp"));
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rwx------"));
            // A root application must not parse untrusted packages as root. Non-root applications
            // keep their existing UID; every parser has cleared credentials and no_new_privs.
            if (rootProcess()) {
                Files.setAttribute(temporary, "unix:uid", 65534);
                Files.setAttribute(temporary, "unix:gid", 65534);
            }
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-xr-xr-x"));
            List<String> arguments = "deb".equals(type)
                    ? List.of("/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\u001f${Version}\u001f${Architecture}\n", input.toString())
                    : List.of("/usr/bin/rpm", "-qp", "--nosignature", "--qf", "%{NAME}\u001f%{EPOCHNUM}\u001f%{VERSION}\u001f%{RELEASE}\u001f%{ARCH}\n", "--", input.toString());
            return parse(type, runBounded(directory, arguments, TIME_LIMIT));
        } finally {
            try {
                if (directory != null) {
                    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
                    Files.walkFileTree(directory, new java.nio.file.SimpleFileVisitor<>() {
                        @Override public java.nio.file.FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes attrs) throws IOException {
                            Files.delete(file); return java.nio.file.FileVisitResult.CONTINUE;
                        }
                        @Override public java.nio.file.FileVisitResult postVisitDirectory(Path dir, IOException error) throws IOException {
                            if (error != null) throw error;
                            Files.delete(dir); return java.nio.file.FileVisitResult.CONTINUE;
                        }
                    });
                }
            } finally { PARSER.release(); }
        }
    }

    static boolean rootProcess() throws IOException {
        return ((Number) Files.getAttribute(Path.of("/proc/self"), "unix:uid")).intValue() == 0;
    }

    static String runBounded(Path directory, List<String> arguments, Duration timeout) throws IOException {
        var command = new ArrayList<>(List.of("/usr/bin/setsid", "/usr/bin/prlimit", "--as=134217728", "--cpu=10", "--fsize=1048576", "--nofile=32", "--core=0", "--",
                "/usr/bin/setpriv", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all"));
        if (rootProcess()) command.addAll(List.of("--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all"));
        command.addAll(arguments);
        ProcessBuilder builder = new ProcessBuilder(command).directory(directory.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().clear();
        builder.environment().put("LC_ALL", "C");
        builder.environment().put("PATH", "/usr/bin:/bin");
        if (Files.isDirectory(directory.resolve("tmp"))) builder.environment().put("TMPDIR", directory.resolve("tmp").toString());
        Process process = builder.start();
        var reader = Executors.newVirtualThreadPerTaskExecutor();
        try {
            process.getOutputStream().close();
            var output = reader.submit(() -> {
                byte[] bytes = process.getInputStream().readNBytes(OUTPUT_LIMIT + 1);
                if (bytes.length > OUTPUT_LIMIT) { terminate(process); throw new IOException("Package parser output limit"); }
                return bytes;
            });
            long deadline = System.nanoTime() + timeout.toNanos();
            while (!process.waitFor(Math.min(timeout.toMillis(), 100), TimeUnit.MILLISECONDS)) {
                temporaryBudget(directory.resolve("tmp"));
                if (System.nanoTime() >= deadline) throw new IOException("Package parser timeout");
            }
            temporaryBudget(directory.resolve("tmp"));
            byte[] bytes = output.get(1, TimeUnit.SECONDS);
            if (process.exitValue() != 0) throw new IOException("Package parser rejected the binary or its resource/privilege limits");
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("Package parser interrupted");
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException error) {
            throw new IOException("Package parser output unavailable");
        } finally {
            terminate(process);
            try { process.getInputStream().close(); }
            finally { reader.shutdownNow(); }
        }
    }

    private static void temporaryBudget(Path temporary) throws IOException {
        if (!Files.isDirectory(temporary)) return;
        Files.walkFileTree(temporary, new java.nio.file.SimpleFileVisitor<>() {
            private int entries;
            private long bytes;
            @Override public java.nio.file.FileVisitResult preVisitDirectory(Path dir, java.nio.file.attribute.BasicFileAttributes attrs) throws IOException {
                if (++entries > 64) throw new IOException("Package parser temporary file limit");
                return java.nio.file.FileVisitResult.CONTINUE;
            }
            @Override public java.nio.file.FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes attrs) throws IOException {
                bytes += attrs.size();
                if (++entries > 64 || bytes > 4 * 1024 * 1024) throw new IOException("Package parser temporary file limit");
                return java.nio.file.FileVisitResult.CONTINUE;
            }
            @Override public java.nio.file.FileVisitResult visitFileFailed(Path file, IOException error) throws IOException {
                if (error instanceof java.nio.file.NoSuchFileException) return java.nio.file.FileVisitResult.CONTINUE;
                throw error;
            }
        });
    }

    private static void terminate(Process process) {
        try {
            // setsid makes the parser and decompressor descendants a separate process group.
            var kill = new ProcessBuilder("/bin/kill", "-KILL", "--", "-" + process.pid()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if (!kill.waitFor(1, TimeUnit.SECONDS)) kill.destroyForcibly();
        } catch (IOException ignored) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
        } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        process.destroyForcibly();
    }

    static Metadata parse(String type, String output) {
        String line = output.endsWith("\n") ? output.substring(0, output.length() - 1) : output;
        if (line.contains("\n") || line.contains("\r")) throw invalid();
        String[] fields = line.split("\u001f", -1);
        Metadata result;
        if ("deb".equals(type) && fields.length == 3) result = new Metadata(fields[0], fields[1], fields[2], "dpkg");
        else if ("rpm".equals(type) && fields.length == 5 && fields[1].matches("[0-9]{1,64}"))
            result = new Metadata(fields[0], rpmVersion(fields[1], fields[2] + "-" + fields[3]), fields[4], "rpm");
        else throw invalid();
        if (!result.name().matches("[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}") || !VulnerabilityScope.architecture(result.architecture())
                || List.of("src", "nosrc").contains(result.architecture())) throw invalid();
        versionIdentity(result.source(), result.version());
        return result;
    }

    public static String versionIdentity(String source, String version) {
        PackageVersions.compare(source, version, version);
        if (!"rpm".equals(source)) return version;
        if (version.lastIndexOf('-') <= version.indexOf(':') + 1) throw invalid();
        int colon = version.indexOf(':');
        return rpmVersion(colon < 0 ? "0" : version.substring(0, colon), version.substring(colon + 1));
    }
    private static String rpmVersion(String epoch, String body) {
        String normalized = epoch.replaceFirst("^0+(?!$)", "");
        return "0".equals(normalized) ? body : normalized + ":" + body;
    }
    public static boolean sameVersion(String source, String left, String right) {
        try { return versionIdentity(source, left).equals(versionIdentity(source, right)); }
        catch (IllegalArgumentException error) { return false; }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("补丁包内部名称、完整版本或二进制架构无法确认"); }
}
