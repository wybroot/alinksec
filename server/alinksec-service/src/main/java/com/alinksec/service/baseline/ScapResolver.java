package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import org.springframework.stereotype.Component;
import org.w3c.dom.*;
import javax.xml.XMLConstants;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

/** Resolve standard XCCDF loading/inheritance with OpenSCAP. No check, probe,
 * remediation or imported command is run on the server. SCC evaluates only the
 * resulting, reviewed content on the target OS. */
@Component
public class ScapResolver {
    private static final Semaphore SLOT=new Semaphore(1);
    public record Resolved(ScapPackage content,String provenance) {}
    public Resolved resolve(ScapPackage source) {
        if (!SLOT.tryAcquire()) throw new IllegalArgumentException("标准内容解析正在进行，请稍后重试");
        Path directory=null;
        try {
            var files=files(source.archive());String name=source.manifest().path("benchmarkFile").asText();
            Document document=ScapPackage.xml(files.get(name));Element benchmark=benchmark(document);
            byte[] original=serialize(benchmark);
            directory=Files.createTempDirectory("alinksec-scap-resolve-");
            Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));
            Path input=directory.resolve("input.xml"),output=directory.resolve("resolved.xml");Files.write(input,original);
            if (root()) {
                for(Path path:List.of(directory,input)) {Files.setAttribute(path,"unix:uid",65534);Files.setAttribute(path,"unix:gid",65534);}
            }
            String version=run(directory,List.of("/usr/bin/oscap","--version")).lines().findFirst().orElse("");
            if (!supportedVersion(version)) throw new IOException("OpenSCAP 1.3.9 or newer is required");
            run(directory,List.of("/usr/bin/oscap","xccdf","resolve","--force","-o",output.toString(),input.toString()));
            if (!Files.isRegularFile(output,LinkOption.NOFOLLOW_LINKS)||Files.size(output)>ScapPackage.MAX_EXPANDED)throw new IOException("resolution output limit");
            byte[] resolved=Files.readAllBytes(output);Element normalized=ScapPackage.xml(resolved).getDocumentElement();
            if (!normalized.getLocalName().equals("Benchmark")||!normalized.getAttribute("id").equals(source.manifest().path("benchmarkId").asText())
                    || !Set.of("true","1").contains(normalized.getAttribute("resolved"))) throw new IOException("unbound resolver output");
            for(Element element:elements(normalized)) if(element.hasAttribute("extends"))throw new IOException("unresolved inheritance");
            benchmark.getParentNode().replaceChild(document.importNode(normalized,true),benchmark);
            // The derived bytes have a new reviewed digest. Preserve signatures
            // in the original archive, remove stale signatures from derivation.
            var signatures=document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature");
            boolean signed=signatures.getLength()>0;
            while(signatures.getLength()>0){var signature=signatures.item(0);signature.getParentNode().removeChild(signature);}
            files.put(name,serialize(document));
            var content=ScapPackage.read(archive(files));
            Map<String,Object> provenance=new LinkedHashMap<>();provenance.put("resolver",version);provenance.put("inputXccdfSha256",ScapPackage.digest(original));provenance.put("resolvedXccdfSha256",ScapPackage.digest(resolved));
            provenance.put("sourceCanonicalSha256",source.sha256());provenance.put("algorithm","XCCDF standard loading and inheritance; OpenSCAP xccdf resolve --force");
            provenance.put("signaturePolicy",signed?"original_preserved_derived_signature_removed":"source_unsigned");
            return new Resolved(content,JsonUtils.write(provenance));
        } catch (IOException|TransformerException e) {throw new IllegalArgumentException("XCCDF 标准解析失败，请检查内容、继承关系和服务端 OpenSCAP（1.3.9 或更高版本）安装");}
        finally {try {if(directory!=null)try(var paths=Files.walk(directory)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}catch(IOException ignored){}SLOT.release();}
    }
    static boolean supportedVersion(String version) {
        var match=java.util.regex.Pattern.compile("OpenSCAP command line tool \\(oscap\\) ([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}).*").matcher(version);
        if (version.length()>256||!match.matches())return false;
        int value=Integer.parseInt(match.group(1))*1000000+Integer.parseInt(match.group(2))*1000+Integer.parseInt(match.group(3));
        return value>=1003009;
    }
    private static boolean root()throws IOException{return ((Number)Files.getAttribute(Path.of("/proc/self"),"unix:uid")).intValue()==0;}
    static Map<String,byte[]> files(byte[] archive)throws IOException{
        Map<String,byte[]> files=new LinkedHashMap<>();try(var zip=new ZipInputStream(new ByteArrayInputStream(archive),StandardCharsets.UTF_8)){for(var entry=zip.getNextEntry();entry!=null;entry=zip.getNextEntry())files.put(entry.getName(),zip.readAllBytes());}return files;
    }
    static byte[] archive(Map<String,byte[]> files)throws IOException{
        try(var out=new ByteArrayOutputStream();var zip=new ZipOutputStream(out)){for(var file:files.entrySet()){zip.putNextEntry(new ZipEntry(file.getKey()));zip.write(file.getValue());zip.closeEntry();}zip.finish();return out.toByteArray();}
    }
    static Element benchmark(Document document){for(Element element:elements(document.getDocumentElement()))if("Benchmark".equals(element.getLocalName())&&Set.of(ScapPackage.XCCDF11,ScapPackage.XCCDF12).contains(element.getNamespaceURI()))return element;throw new IllegalArgumentException("缺少 Benchmark");}
    static List<Element> elements(Element root){List<Element> result=new ArrayList<>();var todo=new ArrayDeque<Element>();todo.push(root);while(!todo.isEmpty()){var element=todo.pop();result.add(element);for(Node node=element.getFirstChild();node!=null;node=node.getNextSibling())if(node instanceof Element child)todo.push(child);}return result;}
    static byte[] serialize(Node node)throws TransformerException{
        var factory=TransformerFactory.newInstance();factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
        var transformer=factory.newTransformer();transformer.setOutputProperty(OutputKeys.ENCODING,"UTF-8");var out=new ByteArrayOutputStream();transformer.transform(new DOMSource(node),new StreamResult(out));return out.toByteArray();
    }
    private static String run(Path directory,List<String> arguments)throws IOException{
        var command=new ArrayList<>(List.of("/usr/bin/setsid","/usr/bin/prlimit","--as=402653184","--data=268435456","--cpu=10","--fsize=33554432","--nofile=64","--core=0","--","/usr/bin/setpriv","--no-new-privs","--inh-caps=-all","--ambient-caps=-all"));
        if(root())command.addAll(List.of("--reuid=65534","--regid=65534","--clear-groups","--bounding-set=-all"));command.addAll(arguments);
        var builder=new ProcessBuilder(command).directory(directory.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD);builder.environment().clear();builder.environment().put("LC_ALL","C");builder.environment().put("PATH","/usr/bin:/bin");
        Process process=builder.start();var reader=Executors.newVirtualThreadPerTaskExecutor();
        try {
            process.getOutputStream().close();var output=reader.submit(()->process.getInputStream().readNBytes(16385));
            if(!process.waitFor(15,TimeUnit.SECONDS)||process.exitValue()!=0)throw new IOException("resolver failed or timed out");
            byte[] bytes=output.get(1,TimeUnit.SECONDS);if(bytes.length>16384)throw new IOException("resolver output limit");return new String(bytes,StandardCharsets.UTF_8);
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("resolver interrupted");}
        catch(ExecutionException|TimeoutException e){throw new IOException("resolver output unavailable");}
        finally{try{new ProcessBuilder("/bin/kill","-KILL","--","-"+process.pid()).redirectError(ProcessBuilder.Redirect.DISCARD).start().waitFor(1,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}process.destroyForcibly();reader.shutdownNow();}
    }
}
