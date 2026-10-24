package com.alinksec.service.cluster;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;

/** Shared material is provisioned once, before any replica starts. */
public final class ClusterFiles {
    private ClusterFiles() {}

    public static Path root(String directory,String deployment) {
        try {
            Path root=Path.of(directory).toRealPath();
            Path marker=root.resolve(".cluster-deployment-id");
            if(!Files.isDirectory(root) || !Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS)
                    || Files.size(marker)>128 || !Files.readString(marker).strip().equals(deployment))
                throw new IOException();
            return root;
        } catch(Exception failure) { throw new IllegalStateException("cluster_shared_directory_not_initialized"); }
    }

    public static Path directory(Path root,String directory) {
        try {
            Path path=Path.of(directory).toAbsolutePath().normalize();
            if(!path.startsWith(root)) throw new IOException();
            Path ancestor=path;
            while(!Files.exists(ancestor,LinkOption.NOFOLLOW_LINKS)) ancestor=ancestor.getParent();
            if(!ancestor.toRealPath().startsWith(root)) throw new IOException();
            Files.createDirectories(path);
            if(!path.toRealPath().startsWith(root)) throw new IOException();
            return path.toRealPath();
        } catch(Exception failure) { throw new IllegalStateException("cluster_storage_outside_shared_directory"); }
    }

    public static void privateAtomicWrite(Path destination,String value) throws IOException {
        Path temporary=Files.createTempFile(destination.getParent(),".cluster-",".tmp");
        try {
            if(Files.getFileStore(temporary).supportsFileAttributeView("posix"))
                Files.setPosixFilePermissions(temporary,PosixFilePermissions.fromString("rw-------"));
            Files.writeString(temporary,value);
            Files.move(temporary,destination,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
        } finally { Files.deleteIfExists(temporary); }
    }
}
