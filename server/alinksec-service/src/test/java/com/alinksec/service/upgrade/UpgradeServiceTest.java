package com.alinksec.service.upgrade;

import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UpgradeServiceTest {
    @Mock private JdbcTemplate jdbc;
    @Mock private CommandService commands;
    @Mock private AgentDownloadTokenService tokens;

    private UpgradeService service() {
        return new UpgradeService(jdbc, commands, new AlinkSecProperties(), tokens);
    }

    private void packageFor(String platform) {
        when(jdbc.queryForMap(anyString(), eq(1L))).thenReturn(Map.of(
                "platform", platform, "version", "0.0.2", "package_key", "agent.bin", "sha256", "a".repeat(64)));
    }

    private void host(String id, int os, String arch) {
        when(jdbc.queryForList(anyString(), eq(id))).thenReturn(List.of(Map.of("os_type", os, "arch", arch)));
    }

    @ParameterizedTest
    @CsvSource({"linux-arm64, 1, arm64", "linux-arm64, 1, aarch64", "linux-amd64, 1, amd64",
            "linux-amd64, 1, x86_64", "windows-amd64, 2, AMD64", "windows-amd64, 2, x64"})
    void acceptsMatchingPlatformsIncludingLegacyKernelNames(String platform, int os, String arch) {
        packageFor(platform);
        host("host-1", os, arch);
        when(tokens.issue("host-1", "agent-upgrade", "agent.bin")).thenReturn("token");
        assertEquals(1, service().dispatch(1L, List.of("host-1"), null).get("dispatched"));
        verify(commands).dispatch(eq("host-1"), any(Command.Builder.class), isNull());
    }

    @ParameterizedTest
    @CsvSource({"1, amd64", "2, arm64", "0, arm64", "1, armv7l", "1, unknown"})
    void incompatibleTargetRejectsEntireBatchBeforeDispatch(int os, String arch) {
        packageFor("linux-arm64");
        host("compatible", 1, "aarch64");
        host("incompatible", os, arch);
        assertThrows(IllegalArgumentException.class,
                () -> service().dispatch(1L, List.of("compatible", "incompatible"), null));
        verifyNoInteractions(commands, tokens);
    }

    @Test
    void missingHostRejectsBatch() {
        packageFor("linux-arm64");
        when(jdbc.queryForList(anyString(), eq("missing"))).thenReturn(List.of());
        assertThrows(IllegalArgumentException.class,
                () -> service().dispatch(1L, List.of("missing"), null));
        verifyNoInteractions(commands, tokens);
    }

    @Test
    void unsupportedUploadPlatformIsRejectedBeforeWriting() {
        assertThrows(IllegalArgumentException.class,
                () -> service().upload(new ByteArrayInputStream(new byte[0]), "0.0.2", "linux-armv7", "", null));
        verifyNoInteractions(jdbc, commands, tokens);
    }
}
