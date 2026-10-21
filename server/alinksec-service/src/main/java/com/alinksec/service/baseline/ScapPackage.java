package com.alinksec.service.baseline;

import com.fasterxml.jackson.databind.JsonNode;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipInputStream;

/** Immutable, offline SCAP content. Semantic evaluation belongs to the native
 * interpreter; this class validates transport, identity and execution boundaries. */
public record ScapPackage(byte[] archive, String sha256, String sourceSha256, JsonNode manifest,
                          List<Map<String, String>> rules, List<String> profiles) {
    public static final int MAX_ARCHIVE = 2 * 1024 * 1024;
    public static final int MAX_EXPANDED = 32 * 1024 * 1024;
    public static final int MAX_RULES = 2000;
    public static final String XCCDF11 = "http://checklists.nist.gov/xccdf/1.1";
    public static final String XCCDF12 = "http://checklists.nist.gov/xccdf/1.2";
    private static final Set<String> FIELDS = Set.of("schemaVersion", "code", "version", "name", "osType",
            "osVersionPattern", "benchmarkFile", "benchmarkId", "profileId");

    public static ScapPackage read(byte[] archive) {
        if (archive.length == 0 || archive.length > MAX_ARCHIVE) throw invalid("内容 ZIP 最多 2 MiB");
        Map<String, byte[]> files = new LinkedHashMap<>();
        int expanded = 0;
        try (var zip = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                String name = entry.getName();
                if (entry.isDirectory() || !safePath(name) || files.containsKey(name) || files.size() >= 128
                        || !(name.equals("alinksec-scap.json") || name.endsWith(".xml"))) {
                    throw invalid("ZIP 仅允许唯一的清单及本地 XML 文件，最多 128 个文件");
                }
                byte[] bytes = zip.readNBytes(MAX_EXPANDED - expanded + 1);
                expanded += bytes.length;
                if (expanded > MAX_EXPANDED) throw invalid("解压内容超过 32 MiB");
                files.put(name, bytes);
            }
        } catch (IOException e) { throw invalid("ZIP 格式或校验无效"); }
        byte[] manifestBytes = files.get("alinksec-scap.json");
        if (manifestBytes == null || manifestBytes.length > 16384) throw invalid("缺少有效的 alinksec-scap.json 清单");
        // Jackson's shared mapper permits duplicate keys for legacy APIs. Reject
        // them locally before trusting a package identity or selection.
        JsonNode manifest;
        try {
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
            mapper.enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
            manifest = mapper.readTree(manifestBytes);
        } catch (IOException e) { throw invalid("清单 JSON 无效或字段重复"); }
        if (manifest == null || !manifest.isObject()) throw invalid("清单必须为对象");
        manifest.fieldNames().forEachRemaining(key -> { if (!FIELDS.contains(key)) throw invalid("未知清单字段: " + key); });
        if (!manifest.path("schemaVersion").isIntegralNumber() || manifest.path("schemaVersion").intValue() != 1
                || !manifest.path("osType").isIntegralNumber() || !Set.of(1, 2).contains(manifest.path("osType").intValue()))
            throw invalid("SCAP 清单版本或系统无效");
        for (String field : List.of("code", "version", "name", "osVersionPattern", "benchmarkFile", "benchmarkId", "profileId")) {
            if (!manifest.path(field).isTextual() || manifest.path(field).asText().isBlank() || manifest.path(field).asText().length() > 256)
                throw invalid("清单字段无效: " + field);
        }
        for (String field : List.of("code", "version", "benchmarkId", "profileId"))
            if (!manifest.path(field).asText().matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")) throw invalid("清单标识无效: " + field);
        try { com.google.re2j.Pattern.compile(manifest.path("osVersionPattern").asText()); }
        catch (RuntimeException e) { throw invalid("系统版本正则无效"); }
        String benchmarkFile = manifest.path("benchmarkFile").asText();
        if (!files.containsKey(benchmarkFile) || !benchmarkFile.endsWith(".xml")) throw invalid("基准文件不在内容包内");
        Element benchmark = null;
        int benchmarks = 0;
        for (var file : files.entrySet()) {
            if (!file.getKey().endsWith(".xml")) continue;
            var document = xml(file.getValue());
            var elements = document.getElementsByTagName("*");
            if (elements.getLength() > 150000) throw invalid("XML 元素数量超过上限");
            Set<String> localIds = new HashSet<>();
            Map<String, String> catalog = new LinkedHashMap<>();
            for (int i = 0; i < elements.getLength(); i++) {
                Element element = (Element) elements.item(i);
                if (element.hasAttribute("id")) localIds.add(element.getAttribute("id"));
                if ("urn:oasis:names:tc:entity:xmlns:xml:catalog".equals(element.getNamespaceURI()) && "uri".equals(element.getLocalName())) {
                    String alias = element.getAttribute("name"), target = element.getAttribute("uri");
                    if (!safePath(alias) || !target.startsWith("#") || target.length() < 2
                            || catalog.containsKey(alias) && !catalog.get(alias).equals(target)) throw invalid("数据流目录映射无效");
                    catalog.put(alias, target);
                }
            }
            if (catalog.values().stream().anyMatch(target -> !localIds.contains(target.substring(1)))) throw invalid("数据流目录引用缺失");
            for (int i = 0; i < elements.getLength(); i++) {
                Element element = (Element) elements.item(i);
                String local = element.getLocalName();
                if ("Benchmark".equals(local) && xccdf(element)) {
                    benchmarks++;
                    if (file.getKey().equals(benchmarkFile) && element.getAttribute("id").equals(manifest.path("benchmarkId").asText())) benchmark = element;
                }
                if (xccdf(element) && "fix".equals(local)) throw invalid("核查内容不得包含可执行修复");
                if (xccdf(element) && "check".equals(local)
                        && !Set.of("http://oval.mitre.org/XMLSchema/oval-definitions-5", "http://scap.nist.gov/schema/ocil/2", "http://scap.nist.gov/schema/ocil/2.0").contains(element.getAttribute("system")))
                    throw invalid("只允许 OVAL 声明式检查或 OCIL 人工问题");
                if ("check-content".equals(local) || local != null && local.matches("(?i).*(shellcommand|powershell|cmdlet).*"))
                    throw invalid("核查内容不得包含脚本探针");
                if ("http://www.w3.org/2001/XInclude".equals(element.getNamespaceURI()) || element.hasAttributeNS(XMLConstants.XML_NS_URI, "base"))
                    throw invalid("核查内容不得包含 XInclude 或外部基路径");
                for (int a = 0; a < element.getAttributes().getLength(); a++) {
                    var attribute = element.getAttributes().item(a);
                    if ("href".equals(attribute.getLocalName()) && !Set.of("reference", "metadata").contains(local))
                        reference(attribute.getNodeValue(), file.getKey(), files, localIds, catalog);
                }
            }
        }
        if (benchmarks != 1 || benchmark == null) throw invalid("每个内容包必须包含且仅包含所选 XCCDF Benchmark");
        String namespace = benchmark.getNamespaceURI();
        List<Map<String, String>> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        var nodes = benchmark.getElementsByTagNameNS(namespace, "Rule");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element rule = (Element) nodes.item(i);
            String id = rule.getAttribute("id");
            if (!id.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}") || !ids.add(id)) throw invalid("规则编号无效或重复");
            var titles = rule.getElementsByTagNameNS(namespace, "title");
            String title = titles.getLength() == 0 ? id : titles.item(0).getTextContent().strip();
            rules.add(Map.of("id", id, "title", title.substring(0, Math.min(title.length(), 512)), "severity", rule.getAttribute("severity")));
        }
        if (rules.isEmpty() || rules.size() > MAX_RULES) throw invalid("内容包需包含 1 至 2000 项规则");
        List<String> profiles = new ArrayList<>();
        var profileNodes = benchmark.getElementsByTagNameNS(namespace, "Profile");
        for (int i = 0; i < profileNodes.getLength(); i++) {
            String id = ((Element) profileNodes.item(i)).getAttribute("id");
            if (!id.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}") || profiles.contains(id)) throw invalid("Profile 编号无效或重复");
            profiles.add(id);
        }
        if (!profiles.contains(manifest.path("profileId").asText())) throw invalid("所选 Profile 不在 Benchmark 内");
        // Normalize the reviewed local ZIP records before delivery. Java's local
        // entry reader and Go's central-directory reader must never see two
        // different documents from an ambiguous, attacker-authored archive.
        byte[] canonical;
        try (var output = new java.io.ByteArrayOutputStream(); var zip = new java.util.zip.ZipOutputStream(output, StandardCharsets.UTF_8)) {
            for (String name : files.keySet().stream().sorted().toList()) {
                var entry = new java.util.zip.ZipEntry(name);
                entry.setTimeLocal(java.time.LocalDateTime.of(1980, 1, 1, 0, 0));
                zip.putNextEntry(entry); zip.write(files.get(name)); zip.closeEntry();
            }
            zip.finish(); canonical = output.toByteArray();
        } catch (IOException e) { throw new IllegalStateException(e); }
        if (canonical.length > MAX_ARCHIVE) throw invalid("规范化内容 ZIP 超过 2 MiB");
        return new ScapPackage(canonical, digest(canonical), digest(archive), manifest.deepCopy(), List.copyOf(rules), List.copyOf(profiles));
    }

    static boolean safePath(String name) {
        return name.length() <= 512 && name.matches("[A-Za-z0-9_][A-Za-z0-9_./-]*")
                && java.util.Arrays.stream(name.split("/", -1)).noneMatch(s -> s.isEmpty() || s.equals(".") || s.equals(".."));
    }
    private static void reference(String href, String source, Map<String, byte[]> files, Set<String> ids, Map<String, String> catalog) {
        if (href.startsWith("#")) {
            if (!ids.contains(href.substring(1))) throw invalid("数据流内部引用缺失");
            return;
        }
        String file = href.split("#", 2)[0];
        if (!safePath(file)) throw invalid("检查引用必须为包内相对路径");
        int slash = source.lastIndexOf('/');
        String path = (slash < 0 ? "" : source.substring(0, slash + 1)) + file;
        if (!files.containsKey(path) && !catalog.containsKey(file)) throw invalid("缺少本地引用文件: " + path);
    }
    private static boolean xccdf(Element element) { return Set.of(XCCDF11, XCCDF12).contains(element.getNamespaceURI() == null ? "" : element.getNamespaceURI()); }
    public static org.w3c.dom.Document xml(byte[] bytes) {
        if (bytes.length == 0 || bytes.length > MAX_EXPANDED) throw invalid("XML 大小无效");
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes));
            for (byte value : bytes) if (value == 0) throw invalid("XML 必须使用 UTF-8");
            var factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setAttribute("jdk.xml.maxElementDepth", "128");
            factory.setXIncludeAware(false);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
                @Override public void error(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
                @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
            });
            return builder.parse(new ByteArrayInputStream(bytes));
        } catch (Exception e) { throw invalid("XML 格式无效或包含外部实体"); }
    }
    public static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
