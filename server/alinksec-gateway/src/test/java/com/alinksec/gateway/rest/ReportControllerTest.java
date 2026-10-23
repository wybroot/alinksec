package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.service.report.*;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.util.*;
import java.security.MessageDigest;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ReportControllerTest {
    private final ComplianceReportService reports=mock(ComplianceReportService.class);
    private final String secret="report-test-secret-".repeat(4);
    private MockMvc mvc() {
        var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(secret);
        return MockMvcBuilders.standaloneSetup(new ReportController(reports)).setControllerAdvice(new RestExceptionHandler()).addInterceptors(new JwtAuthInterceptor(holder)).build();
    }
    private String auth(String role){return "Bearer "+JwtUtil.sign(secret,Map.of("uid",7L,"username","fixture","role",role),3600);}
    @Test void previewAndExportRequireAuthenticationAndNeverExposeCacheableOrPublicDownloads()throws Exception {
        var mvc=mvc();mvc.perform(get("/api/reports/preview")).andExpect(status().isUnauthorized());
        when(reports.preview(any())).thenReturn(Map.of("contract",1,"dataDigest","a".repeat(64)));
        for(String role:List.of("admin","operator","viewer")) {
            mvc.perform(get("/api/reports/preview").header("Authorization",auth(role))).andExpect(status().isOk()).andExpect(jsonPath("$.data.contract").value(1));
            var response=mvc.perform(get("/api/reports/compliance.json").header("Authorization",auth(role))).andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store")).andExpect(header().string("X-Content-Type-Options","nosniff")).andExpect(header().string("Content-Disposition","attachment; filename=\"alinksec-report.json\"")).andReturn().getResponse();
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(response.getContentAsByteArray())),response.getHeader("X-Content-SHA256"));
            assertTrue(response.getHeader("Content-Security-Policy").startsWith("sandbox;"));
        }
        mvc.perform(get("/api/reports/compliance.json").param("expectedDataDigest","stale").header("Authorization",auth("viewer"))).andExpect(status().isBadRequest()).andExpect(jsonPath("$.msg").value("报表数据已变化，请刷新预览或查看已保存的快照"));
    }
    @Test void snapshotCreationUsesOnlyAuthenticatedActorAndEnforcesReadOnlyAndAdministratorBoundaries()throws Exception {
        var mvc=mvc();String body="{\"title\":\"Fixture\",\"from\":\"2026-02-01\",\"to\":\"2026-02-02\",\"created_by\":999}";
        mvc.perform(post("/api/reports/snapshots").header("Authorization",auth("operator")).contentType("application/json").content(body)).andExpect(status().isOk());
        verify(reports).save(new ReportQuery("2026-02-01","2026-02-02",null,null),"Fixture",7L);
        mvc.perform(post("/api/reports/snapshots").header("Authorization",auth("viewer")).contentType("application/json").content(body)).andExpect(status().isForbidden());
        for(String role:List.of("operator","viewer")) {
            mvc.perform(post("/api/reports/schedules").header("Authorization",auth(role)).contentType("application/json").content("{}")).andExpect(status().isForbidden());
            mvc.perform(delete("/api/reports/snapshots/123").header("Authorization",auth(role))).andExpect(status().isForbidden());
        }
    }
    @Test void storedExportsUseVerifiedSnapshotDataAndItsDocumentCommitment()throws Exception {
        when(reports.snapshot("saved")).thenReturn(Map.of("sha256","b".repeat(64),"report",Map.of("contract",1)));
        mvc().perform(get("/api/reports/snapshots/saved/export.json").header("Authorization",auth("viewer"))).andExpect(status().isOk()).andExpect(header().string("X-Report-Snapshot-SHA256","b".repeat(64))).andExpect(content().json("{\"contract\":1}"));
        verify(reports).snapshot("saved");verify(reports,never()).preview(any());
    }
}
