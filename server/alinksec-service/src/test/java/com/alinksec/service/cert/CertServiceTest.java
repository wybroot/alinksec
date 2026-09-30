package com.alinksec.service.cert;

import com.alinksec.service.config.AlinkSecProperties;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertServiceTest {

    @TempDir Path temp;

    @Test
    void rejectsMissingPlaceholderAndMalformedDeploymentAddresses() {
        for (String host : List.of("", "192.168.1.100", "127.0.0.1", "0.0.0.0",
                "999.1.1.1", "192.168.01.2", "bad_host", "2001:db8::1")) {
            assertThrows(IllegalArgumentException.class, () -> CertService.validatePublicHost(host), host);
        }
        assertDoesNotThrow(() -> CertService.validatePublicHost("192.168.56.10"));
        assertDoesNotThrow(() -> CertService.validatePublicHost("security.example.test"));
    }

    @Test
    void validatesAddressBeforeCreatingCertificateAndRejectsStaleSan() throws Exception {
        AlinkSecProperties props = new AlinkSecProperties();
        Path certs = temp.resolve("certs");
        props.getServer().setCertDir(certs.toString());
        props.getServer().setWebTlsDir(temp.resolve("web-tls").toString());
        props.getServer().setPublicHost("192.168.1.100");
        props.getServer().setTlsSans(List.of("localhost", "192.168.1.100"));

        assertThrows(IllegalArgumentException.class, () -> new CertService(props).init());
        assertFalse(Files.exists(certs));

        props.getServer().setPublicHost("192.168.56.10");
        props.getServer().setTlsSans(List.of("localhost", "192.168.56.10"));
        new CertService(props).init();
        assertTrue(Files.isRegularFile(certs.resolve("server.crt")));
        assertTrue(Files.readString(certs.resolve("ca.key")).startsWith("-----BEGIN PRIVATE KEY-----"));
        assertDoesNotThrow(() -> new CertService(props).init());

        try (PEMParser parser = new PEMParser(new StringReader(Files.readString(certs.resolve("ca.key"))));
             StringWriter output = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(output)) {
            writer.writeObject(new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) parser.readObject()));
            writer.flush();
            Files.writeString(certs.resolve("ca.key"), output.toString());
        }
        assertTrue(Files.readString(certs.resolve("ca.key")).startsWith("-----BEGIN EC PRIVATE KEY-----"));
        CertService restored = new CertService(props);
        restored.init();
        var issued = restored.issueClientCert("agent-test");
        var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(issued.certPem().getBytes(StandardCharsets.UTF_8)));
        cert.verify(restored.caCert().getPublicKey());

        props.getServer().setPublicHost("192.168.56.11");
        props.getServer().setTlsSans(List.of("localhost", "192.168.56.11"));
        assertThrows(IllegalStateException.class, () -> new CertService(props).init());
    }
}
