package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.service.evidence.EvidenceService;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class EvidenceControllerTest {
    final EvidenceService service=mock(EvidenceService.class);
    final String secret="evidence-private-test-secret-".repeat(4),id="11111111-1111-4111-8111-111111111111";
    MockMvc mvc(){var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(secret);return MockMvcBuilders.standaloneSetup(new EvidenceController(service)).setControllerAdvice(new RestExceptionHandler()).addInterceptors(new JwtAuthInterceptor(holder)).build();}
    String auth(String role){return "Bearer "+JwtUtil.sign(secret,Map.of("uid",7L,"username","fixture","role",role),3600);}
    @Test void allMetadataSamplesAndFileRoutesRequireCurrentAdministratorClaims()throws Exception {
        var mvc=mvc();for(String path:List.of("/api/evidence","/api/evidence/targets","/api/evidence/targets/a/samples","/api/evidence/"+id+"/download")) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
            for(String role:List.of("viewer","operator"))mvc.perform(get(path).header("Authorization",auth(role))).andExpect(status().isForbidden());
        }
        for(String role:List.of("viewer","operator")) {
            mvc.perform(post("/api/evidence").contentType("application/json").content("{}").header("Authorization",auth(role))).andExpect(status().isForbidden());
            mvc.perform(delete("/api/evidence/"+id).header("Authorization",auth(role))).andExpect(status().isForbidden());
        }
        verifyNoInteractions(service);
    }
    @Test void downloadIsAnAuthenticatedNonCacheableAttachmentWithExactByteDigest()throws Exception {
        byte[] bytes={1,2,3};String hash=EvidenceService.sha(bytes);when(service.download(id,7L)).thenReturn(new EvidenceService.Download(bytes,hash,"fixture.sample.bin"));
        mvc().perform(get("/api/evidence/"+id+"/download").header("Authorization",auth("admin")))
                .andExpect(status().isOk()).andExpect(content().bytes(bytes)).andExpect(content().contentType("application/octet-stream"))
                .andExpect(header().string("Content-Disposition","attachment; filename=\"fixture.sample.bin\""))
                .andExpect(header().string("Cache-Control","no-store")).andExpect(header().string("X-Content-Type-Options","nosniff"))
                .andExpect(header().string("Content-Security-Policy","sandbox; default-src 'none'"))
                .andExpect(header().string("X-Content-SHA256",hash));
    }
    @Test void actorComesFromVerifiedSessionAndNeverFromRequestPayload()throws Exception {
        mvc().perform(post("/api/evidence").header("Authorization",auth("admin")).contentType("application/json")
                .content("{\"agentId\":\"a\",\"kind\":\"diagnostic\",\"reason\":\"SEC-123\",\"actor\":999}")).andExpect(status().isOk());
        verify(service).create(new EvidenceService.Request("a","diagnostic",null,"SEC-123"),7L);
    }
}
