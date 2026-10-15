package com.alinksec.bootstrap;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/** Trusted, disposable real DEB builder; never installs a fixture. */
final class NativePatchFixture {
    static byte[] deb(Path root, String name, String version, String architecture) throws Exception {
        Path tree = Files.createTempDirectory(root, "deb-");
        Files.createDirectories(tree.resolve("DEBIAN"));
        Files.writeString(tree.resolve("DEBIAN/control"), "Package: " + name + "\nVersion: " + version + "\nArchitecture: " + architecture
                + "\nMaintainer: CI <ci@example.test>\nDescription: disposable fixture\n");
        Files.writeString(tree.resolve("DEBIAN/postinst"), "#!/bin/sh\nexit 99\n");
        tree.resolve("DEBIAN/postinst").toFile().setExecutable(true, false);
        Path file = tree.resolveSibling(tree.getFileName() + ".deb");
        var process = new ProcessBuilder("/usr/bin/dpkg-deb", "--build", "--root-owner-group", tree.toString(), file.toString())
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        if (!process.waitFor(15, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IllegalStateException("Fixture builder timeout"); }
        if (process.exitValue() != 0) throw new IllegalStateException("Fixture builder failed");
        return Files.readAllBytes(file);
    }
    static Path rpm(Path root) throws Exception {
        Path tree = Files.createTempDirectory(root, "rpm-");
        for (String dir : java.util.List.of("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS")) Files.createDirectories(tree.resolve(dir));
        Path spec = tree.resolve("SPECS/fixture.spec");
        Files.writeString(spec, """
                Name: patch-fixture
                Version: 2.0~rc1
                Release: 3.el9
                Epoch: 2
                Summary: disposable validation fixture
                License: MIT
                BuildArch: noarch
                %description
                Disposable native binary fixture.
                %install
                mkdir -p %{buildroot}/usr/share/alinksec-patch-fixture
                echo fixture > %{buildroot}/usr/share/alinksec-patch-fixture/value
                %files
                /usr/share/alinksec-patch-fixture/value
                """);
        var process = new ProcessBuilder("/usr/bin/rpmbuild", "--define", "_topdir " + tree, "--define", "_build_id_links none", "--define", "_smp_mflags -j1", "-bb", spec.toString())
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IllegalStateException("RPM fixture builder timeout"); }
        if (process.exitValue() != 0) throw new IllegalStateException("RPM fixture builder failed");
        try (var paths = Files.walk(tree.resolve("RPMS"))) { return paths.filter(p -> p.toString().endsWith(".rpm")).findFirst().orElseThrow(); }
    }
    private NativePatchFixture() {}
}
