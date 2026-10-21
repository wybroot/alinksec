package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/** Adjacent release differences use sorted hash streams, keeping memory bounded
 * independently of the hash inventory. Internal rules are replaced as a whole. */
public final class SignatureDelta {
    private SignatureDelta() {}
    private static final List<String> MEMBERS=List.of("manifest.json","hashes.txt","rules.json");
    public record Identity(String version,String digest) {}
    public record Difference(Identity base,Identity target) {}

    private static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    public static Identity identity(Path zip) throws IOException {
        Map<String,String> digests=new HashMap<>(); String version="";
        long remaining=64L<<20;
        try (ZipInputStream in=new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry entry;
            while ((entry=in.getNextEntry())!=null) {
                String name=entry.getName();
                if (!MEMBERS.contains(name) || entry.isDirectory() || digests.containsKey(name)) throw new IOException("Invalid complete signature archive");
                MessageDigest hash=digest();
                ByteArrayOutputStream manifest=new ByteArrayOutputStream();
                byte[] buffer=new byte[8192]; int n; long member=0;
                while ((n=in.read(buffer))!=-1) {
                    remaining-=n; member+=n;
                    if (remaining<0 || name.equals("manifest.json") && member>(64<<10) || name.equals("rules.json") && member>(2<<20)) throw new IOException("Signature content exceeds limits");
                    hash.update(buffer,0,n);
                    if (name.equals("manifest.json")) manifest.write(buffer,0,n);
                }
                if (name.equals("manifest.json")) version=JsonUtils.mapper().readTree(manifest.toByteArray()).path("db_version").asText("");
                digests.put(name,HexFormat.of().formatHex(hash.digest()));
            }
        }
        if (!version.matches("[A-Za-z0-9._-]{1,32}") || !digests.containsKey("hashes.txt")) throw new IOException("Missing signature identity");
        digests.putIfAbsent("rules.json",HexFormat.of().formatHex(digest().digest()));
        MessageDigest hash=digest();
        for (String name:MEMBERS) hash.update(digests.get(name).getBytes(StandardCharsets.US_ASCII));
        return new Identity(version,HexFormat.of().formatHex(hash.digest()));
    }

    public static Difference build(Path base,Path target,Path output,int maxHashes) throws IOException {
        Identity before=identity(base),after=identity(target);
        if (before.version().equals(after.version())) throw new IOException("Delta versions must differ");
        Path dir=Files.createTempDirectory(output.toAbsolutePath().getParent(),"delta-");
        try {
            extract(base,dir.resolve("base")); extract(target,dir.resolve("target"));
            Path updates=dir.resolve("updates"),removed=dir.resolve("removed");
            try (SortedHashes old=new SortedHashes(dir.resolve("base/hashes.txt"),maxHashes);
                 SortedHashes next=new SortedHashes(dir.resolve("target/hashes.txt"),maxHashes);
                 BufferedWriter up=Files.newBufferedWriter(updates,StandardCharsets.UTF_8);
                 BufferedWriter rm=Files.newBufferedWriter(removed,StandardCharsets.UTF_8)) {
                String a=old.next(),b=next.next();
                while (a!=null || b!=null) {
                    int order=a==null?1:b==null?-1:a.substring(0,64).compareTo(b.substring(0,64));
                    if (order<0) { rm.write(a.substring(0,64)); rm.newLine(); a=old.next(); }
                    else if (order>0) { up.write(b); up.write('\n'); b=next.next(); }
                    else { if (!a.equals(b)) { up.write(b); up.write('\n'); } a=old.next(); b=next.next(); }
                }
            }
            try (ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(output))) {
                zip.putNextEntry(new ZipEntry("delta.json"));
                zip.write(JsonUtils.write(Map.of("contract",1,"base_version",before.version(),"base_content_sha256",before.digest(),"target_version",after.version(),"target_content_sha256",after.digest())).getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
                for (var entry:Map.of("manifest.json",dir.resolve("target/manifest.json"),"rules.json",dir.resolve("target/rules.json"),"hashes.txt",updates,"removed.txt",removed).entrySet()) {
                    zip.putNextEntry(new ZipEntry(entry.getKey())); Files.copy(entry.getValue(),zip); zip.closeEntry();
                }
            }
            return new Difference(before,after);
        } finally {
            try (var paths=Files.walk(dir)) {
                for (Path p:paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
    }

    private static void extract(Path source,Path destination) throws IOException {
        Files.createDirectory(destination);
        try (ZipInputStream zip=new ZipInputStream(Files.newInputStream(source))) {
            long remaining=64L<<20; Set<String> seen=new HashSet<>(); ZipEntry entry;
            while ((entry=zip.getNextEntry())!=null) {
                if (!MEMBERS.contains(entry.getName()) || entry.isDirectory() || !seen.add(entry.getName())) throw new IOException("Invalid complete signature archive");
                try (var out=Files.newOutputStream(destination.resolve(entry.getName()))) {
                    byte[] buffer=new byte[8192]; int n;
                    while ((n=zip.read(buffer))!=-1) { remaining-=n; if (remaining<0) throw new IOException("Signature content exceeds limits"); out.write(buffer,0,n); }
                }
            }
        }
        if (!Files.exists(destination.resolve("rules.json"))) Files.write(destination.resolve("rules.json"),new byte[0]);
    }

    private static final class SortedHashes implements AutoCloseable {
        final BufferedReader reader; final int max; int count; String previous="";
        SortedHashes(Path file,int max) throws IOException { reader=Files.newBufferedReader(file,StandardCharsets.UTF_8); this.max=max; }
        String next() throws IOException {
            String line=SignaturePackage.readLine(reader);
            if (line==null) return null;
            String[] parts=line.split(" ",-1);
            if (++count>max || parts.length!=3 || !parts[0].matches("[a-f0-9]{64}") || parts[0].compareTo(previous)<=0) throw new IOException("Base is not a canonical sorted release");
            try { SignaturePackage.checkedHash(parts[0],parts[1],Integer.parseInt(parts[2])); }
            catch (IllegalArgumentException e) { throw new IOException("Invalid canonical signature entry"); }
            previous=parts[0]; return line;
        }
        public void close() throws IOException { reader.close(); }
    }
}
