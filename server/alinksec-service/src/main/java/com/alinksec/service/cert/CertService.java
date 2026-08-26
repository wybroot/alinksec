package com.alinksec.service.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

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
        return new IssuedCert(toPem(cert), toPem(keyPair), cert.getSerialNumber().toString(16));
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
        byte[] der = parsePemDer(Files.readString(dir.resolve("ca.key")));
        caPrivateKey = java.security.KeyFactory.getInstance("EC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
    }

    private void loadServer(Path dir) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream in = new FileInputStream(dir.resolve("server.crt").toFile())) {
            serverCert = (X509Certificate) cf.generateCertificate(in);
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
            pem.writeObject(obj);
        }
    }

    private static byte[] parsePemDer(String pem) {
        String body = pem.replaceAll("-----BEGIN [A-Z ]*-----", "")
                .replaceAll("-----END [A-Z ]*-----", "")
                .replaceAll("\\s", "");
        return java.util.Base64.getDecoder().decode(body);
    }
}
