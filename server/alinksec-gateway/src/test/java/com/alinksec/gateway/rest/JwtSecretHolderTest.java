package com.alinksec.gateway.rest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class JwtSecretHolderTest {
    @TempDir Path temp;

    @Test
    void keepsPersistedSecretAcrossRestarts() throws Exception {
        JwtSecretHolder first = holder(temp.resolve("certs").toString(), "", false);
        first.init();
        JwtSecretHolder restarted = holder(temp.resolve("certs").toString(), "", false);
        restarted.init();
        assertEquals(first.secret(), restarted.secret());
        assertTrue(first.secret().length() >= 32);
        assertEquals(first.secret(), Files.readString(temp.resolve("jwt.secret")));
    }

    @Test
    void rejectsEmptyPersistedSecretWithoutRotatingIt() throws Exception {
        Path file = temp.resolve("jwt.secret");
        for (String value : new String[]{"", " \r\n"}) {
            Files.writeString(file, value);
            var failure = assertThrows(IllegalStateException.class,
                    () -> holder(temp.resolve("certs").toString(), "", false).init());
            assertEquals("jwt_secret_empty", failure.getMessage());
            assertEquals(value, Files.readString(file));
        }
    }

    @Test
    void environmentSecretRetainsPriorityAndExistingCompatibility() throws Exception {
        Files.writeString(temp.resolve("jwt.secret"), "");
        JwtSecretHolder configured = holder(temp.resolve("certs").toString(), "explicit-local-secret", false);
        configured.init();
        assertEquals("explicit-local-secret", configured.secret());
        assertEquals("", Files.readString(temp.resolve("jwt.secret")));
    }

    @Test
    void clusterNeverGeneratesMissingSharedSecret() {
        var failure = assertThrows(IllegalStateException.class,
                () -> holder(temp.resolve("certs").toString(), "", true).init());
        assertEquals("cluster_requires_initialized_shared_jwt", failure.getMessage());
        assertFalse(Files.exists(temp.resolve("jwt.secret")));
    }

    @Test
    void singleComponentRelativeCertificateDirectoryWorksInIsolatedProcess() throws Exception {
        Path output = temp.resolve("child.log");
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx48m", "-XX:ActiveProcessorCount=1", "-cp", classpath, RelativeDirectoryProbe.class.getName())
                .directory(temp.toFile()).redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "relative-directory child timed out");
            assertEquals(0, process.exitValue(), () -> {
                try { return Files.readString(output); }
                catch (Exception failure) { return failure.toString(); }
            });
            assertTrue(Files.isRegularFile(temp.resolve("jwt.secret")));
        } finally {
            if (process.isAlive()) process.destroyForcibly().waitFor();
        }
    }

    private static JwtSecretHolder holder(String directory, String environment, boolean cluster) throws Exception {
        JwtSecretHolder result = new JwtSecretHolder();
        for (var entry : java.util.Map.of("dataDir", directory, "fromEnv", environment, "clusterEnabled", cluster).entrySet()) {
            var field = JwtSecretHolder.class.getDeclaredField(entry.getKey());
            field.setAccessible(true);
            field.set(result, entry.getValue());
        }
        return result;
    }

    public static class RelativeDirectoryProbe {
        public static void main(String[] args) throws Exception {
            JwtSecretHolder first = holder("certs", "", false);
            first.init();
            JwtSecretHolder restarted = holder("certs", "", false);
            restarted.init();
            if (first.secret().isBlank() || !first.secret().equals(restarted.secret())
                    || !first.secret().equals(Files.readString(Path.of("jwt.secret")))) {
                throw new AssertionError("relative-directory secret did not survive restart");
            }
        }
    }
}
