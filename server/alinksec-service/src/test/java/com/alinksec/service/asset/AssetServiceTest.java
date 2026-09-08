package com.alinksec.service.asset;

import com.alinksec.proto.RptAssetSnapshot;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.scan.VulnMatchService;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AssetServiceTest {

    @Test
    void targetedProcessSnapshotDoesNotReplaceOtherAssetCategories() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        VulnMatchService vulnMatchService = mock(VulnMatchService.class);
        AssetService service = new AssetService(jdbc, vulnMatchService, mock(SecurityEventService.class));

        service.replaceSnapshot("agent-1", RptAssetSnapshot.newBuilder()
                .addCollected("processes")
                .build());

        verify(jdbc).update(eq("DELETE FROM t_asset_process WHERE agent_id = ?"), eq("agent-1"));
        verify(jdbc, never()).update(contains("t_asset_software"), any(Object[].class));
        verify(jdbc, never()).update(contains("t_asset_port"), any(Object[].class));
        verify(jdbc, never()).update(contains("t_asset_account"), any(Object[].class));
        verify(jdbc, never()).update(contains("t_asset_container"), any(Object[].class));
        verify(vulnMatchService).matchAgent("agent-1", 0L);
    }
}
