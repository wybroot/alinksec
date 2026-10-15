package com.alinksec.service.fix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class PackageMetadataReaderTest {
    @TempDir Path root;
    @Test void strictHeaderFieldsPreserveCompleteVersionsAndRejectSourcePackagesAndExtraRecords() {
        assertEquals("2:1.0~rc1-3ubuntu1", PackageMetadataReader.parse("deb", "fixture\u001f2:1.0~rc1-3ubuntu1\u001famd64\n").version());
        assertEquals("2:1.0-3.el9", PackageMetadataReader.parse("rpm", "fixture\u001f02\u001f1.0\u001f3.el9\u001fx86_64\n").version());
        assertTrue(PackageMetadataReader.sameVersion("rpm", "000:1.0-3.el9", "1.0-3.el9"));
        assertFalse(PackageMetadataReader.sameVersion("rpm", "1.0-03.el9", "1.0-3.el9"));
        assertFalse(PackageMetadataReader.sameVersion("dpkg", "1.0", "0:1.0-0"));
        assertFalse(PackageMetadataReader.sameVersion("rpm", "1.0", "1.0-1"));
        assertThrows(IllegalArgumentException.class, () -> PackageMetadataReader.parse("rpm", "fixture\u001f0\u001f1.0\u001f1\u001fsrc\n"));
        assertThrows(IllegalArgumentException.class, () -> PackageMetadataReader.parse("deb", "fixture\u001f1.0\u001famd64\nfixture\u001f2.0\u001famd64\n"));
    }
    @Test void parserRunsWithClearedEnvironmentNoNewPrivilegesAndBoundedResources() throws Exception {
        String status = PackageMetadataReader.runBounded(root, List.of("/bin/cat", "/proc/self/status", "/proc/self/limits"), Duration.ofSeconds(3));
        assertTrue(status.contains("NoNewPrivs:\t1")); assertTrue(status.contains("134217728"));
        if (PackageMetadataReader.rootProcess()) { assertTrue(status.contains("Uid:\t65534\t65534\t65534\t65534")); assertTrue(status.contains("CapEff:\t0000000000000000")); }
        String env = PackageMetadataReader.runBounded(root, List.of("/usr/bin/env"), Duration.ofSeconds(3));
        assertEquals(List.of("LC_ALL=C", "PATH=/usr/bin:/bin"), env.lines().sorted().toList());
    }
    @Test void excessiveOutputAndLongRunningParsersAreTerminatedWithinDeadline() {
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> assertThrows(IOException.class,
                () -> PackageMetadataReader.runBounded(root, List.of("/usr/bin/yes"), Duration.ofSeconds(1))));
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> assertThrows(IOException.class,
                () -> PackageMetadataReader.runBounded(root, List.of("/bin/sleep", "30"), Duration.ofMillis(200))));
    }
}
