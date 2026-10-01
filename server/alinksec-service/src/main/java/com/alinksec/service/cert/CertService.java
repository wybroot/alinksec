package com.alinksec.service.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;

import com.alinksec.service.config.AlinkSecProperties;

import jakarta.annotation.PostConstruct;

/**
 * 平台 PKI（设计文档 §6）：
 * - 首次启动生成平台自签 CA（EC P-256，10 年），落盘 certDir；
 * - 生成服务端证书（SAN 覆盖配置的接入地址）；
 * - Enroll 时为 Agent 签发客户端证书（CN=agent_id，10 年）。
 * 私钥以 PKCS#8 PEM 明文落盘（M1 单机私有部署；M2 可接入 KMS/加密盘）。
 */
@Service
public class CertService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final AlinkSecProperties props;
    private X509Certificate caCert;
    private java.security.PrivateKey caPrivateKey;
    private X509Certificate serverCert;

    public CertService(AlinkSecProperties props) {
        this.props = props;
    }

    @PostConstruct
    void init() throws Exception {
        String publicHost = props.getServer().getPublicHost();
        if (publicHost != null && !publicHost.isBlank()) {
            validatePublicHost(publicHost);
            if (props.getServer().getTlsSans().stream().noneMatch(publicHost::equalsIgnoreCase)) {
                throw new IllegalArgumentException("server TLS SANs do not include public host: " + publicHost);
            }
        }
        Path dir = Paths.get(props.getServer().getCertDir());
        Files.createDirectories(dir);
        if (Files.exists(dir.resolve("ca.crt"))) {
            loadCa(dir);
        } else {
            createCa(dir);
        }
        if (Files.exists(dir.resolve("server.crt"))) {
            loadServer(dir);
        } else {
            createServer(dir);
        }
        if (publicHost != null && !publicHost.isBlank() && !certificateContains(publicHost)) {
            throw new IllegalStateException("existing server certificate SAN does not include public host: "
                    + publicHost + "; restore the certificate with the documented TLS recovery procedure");
        }
        publishWebTls(dir);
    }

    static void validatePublicHost(String host) {
        String normalized = host == null ? "" : host.toLowerCase(Locale.ROOT);
        if (host == null || host.isBlank() || !host.equals(host.trim())
                || normalized.equals("localhost") || normalized.equals("alinksec-server")
                || normalized.equals("192.168.1.100")) {
            throw new IllegalArgumentException("HOST_IP must be a configured Agent-reachable IPv4 or DNS name");
        }
        if (host.matches("[0-9.]+")) {
            String[] parts = host.split("\\.", -1);
            if (parts.length != 4) {
                throw new IllegalArgumentException("HOST_IP is not a valid IPv4 address: " + host);
            }
            for (String part : parts) {
                if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
                    throw new IllegalArgumentException("HOST_IP is not a valid IPv4 address: " + host);
                }
                int octet = Integer.parseInt(part);
                if (octet > 255) {
                    throw new IllegalArgumentException("HOST_IP is not a valid IPv4 address: " + host);
                }
            }
            int first = Integer.parseInt(parts[0]);
            if (first == 0 || first == 127 || first >= 224) {
                throw new IllegalArgumentException("HOST_IP must be Agent-reachable: " + host);
            }
        } else if (host.length() > 253 || !host.matches(
                "(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")) {
            throw new IllegalArgumentException("HOST_IP is not a valid IPv4 or DNS name: " + host);
        }
    }

    private boolean certificateContains(String host) throws java.security.cert.CertificateParsingException {
        var names = serverCert.getSubjectAlternativeNames();
        if (names == null) {
            return false;
        }
        return names.stream().anyMatch(name -> (Integer.valueOf(2).equals(name.get(0))
                || Integer.valueOf(7).equals(name.get(0)))
                && host.equalsIgnoreCase(String.valueOf(name.get(1))));
    }

    public X509Certificate caCert() { return caCert; }

    public File serverCertFile() { return Paths.get(props.getServer().getCertDir(), "server.crt").toFile(); }

    public File serverKeyFile() { return Paths.get(props.getServer().getCertDir(), "server.key").toFile(); }

    /**
     * 为 Agent 签发客户端证书（CN=agent_id），返回 [cert, key] 的 PEM。
     */
    public IssuedCert issueClientCert(String agentId) throws Exception {
        KeyPair keyPair = newKeyPair();
        X500Name subject = new X500Name("CN=" + agentId + ", O=ALinkSec, OU=Agent");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert, newSerial(), notBefore(), notAfter(props.getServer().getAgentCertDays()), subject, keyPair.getPublic());
        // EKU clientAuth
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                        new org.bouncycastle.asn1.x509.KeyPurposeId[]{org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth}));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caPrivateKey);
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
        return new IssuedCert(toPem(cert),
                toPem(new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded())),
                cert.getSerialNumber().toString(16));
    }

    public record IssuedCert(String certPem, String keyPem, String serial) {}

    /* ==================== 内部 ==================== */

    private void createCa(Path dir) throws Exception {
        KeyPair keyPair = newKeyPair();
        X500Name subject = new X500Name("CN=ALinkSec Platform CA, O=ALinkSec");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, newSerial(), notBefore(), notAfter(3650), subject, keyPair.getPublic());
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true));
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.keyCertSign | org.bouncycastle.asn1.x509.KeyUsage.cRLSign));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        caCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        caPrivateKey = keyPair.getPrivate();
        writePem(dir.resolve("ca.crt"), caCert);
        writePem(dir.resolve("ca.key"), caPrivateKey);
    }

    private void createServer(Path dir) throws Exception {
        KeyPair keyPair = newKeyPair();
        X500Name subject = new X500Name("CN=alinksec-server, O=ALinkSec");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert, newSerial(), notBefore(), notAfter(3650), subject, keyPair.getPublic());
        org.bouncycastle.asn1.x509.GeneralNames names = buildSans();
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, names);
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                        new org.bouncycastle.asn1.x509.KeyPurposeId[]{org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth}));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caPrivateKey);
        serverCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        writePem(dir.resolve("server.crt"), serverCert);
        writePem(dir.resolve("server.key"), keyPair.getPrivate());
    }

    private void loadCa(Path dir) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream in = new FileInputStream(dir.resolve("ca.crt").toFile())) {
            caCert = (X509Certificate) cf.generateCertificate(in);
        }
        try (PEMParser parser = new PEMParser(new StringReader(Files.readString(dir.resolve("ca.key"))))) {
            Object key = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (key instanceof PEMKeyPair pair) {
                var curve = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded())
                        .getAlgorithm().getParameters();
                var info = new PrivateKeyInfo(
                        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curve),
                        pair.getPrivateKeyInfo().parsePrivateKey());
                caPrivateKey = converter.getPrivateKey(info);
            } else if (key instanceof PrivateKeyInfo info) {
                caPrivateKey = converter.getPrivateKey(info);
            } else {
                throw new IllegalStateException("unsupported CA private key format");
            }
        }
    }

    private void loadServer(Path dir) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream in = new FileInputStream(dir.resolve("server.crt").toFile())) {
            serverCert = (X509Certificate) cf.generateCertificate(in);
        }
    }

    /** Shares only the leaf certificate and its key with the HTTPS reverse proxy. */
    private void publishWebTls(Path certDir) throws IOException {
        Path webTlsDir = Paths.get(props.getServer().getWebTlsDir());
        Files.createDirectories(webTlsDir);
        copyAtomically(certDir.resolve("server.crt"), webTlsDir.resolve("server.crt"));
        copyAtomically(certDir.resolve("server.key"), webTlsDir.resolve("server.key"));
    }

    private static void copyAtomically(Path source, Path destination) throws IOException {
        Path temporary = destination.resolveSibling(destination.getFileName() + ".tmp");
        Files.copy(source, temporary, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        try {
            Files.move(temporary, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
            Files.move(temporary, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private org.bouncycastle.asn1.x509.GeneralNames buildSans() {
        var list = new java.util.ArrayList<org.bouncycastle.asn1.x509.GeneralName>();
        for (String san : props.getServer().getTlsSans()) {
            if (san.contains(":") && !san.contains(".")) {
                list.add(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, san));
            } else if (san.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                list.add(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, san));
            } else {
                list.add(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, san));
            }
        }
        return new org.bouncycastle.asn1.x509.GeneralNames(list.toArray(new org.bouncycastle.asn1.x509.GeneralName[0]));
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return gen.generateKeyPair();
    }

    private static BigInteger newSerial() {
        return new BigInteger(63, new SecureRandom());
    }

    private static Date notBefore() { return new Date(System.currentTimeMillis() - 60_000L); }

    private static Date notAfter(int days) { return new Date(System.currentTimeMillis() + days * 24L * 3600 * 1000); }

    private static String toPem(Object obj) throws IOException {
        var sw = new java.io.StringWriter();
        try (JcaPEMWriter pem = new JcaPEMWriter(sw)) {
            pem.writeObject(obj);
        }
        return sw.toString();
    }

    private static void writePem(Path path, Object obj) throws IOException {
        try (JcaPEMWriter pem = new JcaPEMWriter(new FileWriter(path.toFile()))) {
            if (obj instanceof PrivateKey key) {
                pem.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
            } else {
                pem.writeObject(obj);
            }
        }
    }

}
