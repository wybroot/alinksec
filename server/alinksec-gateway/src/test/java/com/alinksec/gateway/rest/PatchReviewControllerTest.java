package com.alinksec.gateway.rest;

import com.alinksec.service.fix.*;
import com.alinksec.service.query.FixQueryService;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.util.Map;
import static org.mockito.Mockito.*;

class PatchReviewControllerTest {
    @Test void bodyReviewerCannotReplaceTheAuthenticatedIdentity() throws Exception {
        var repo = mock(PatchRepoService.class);
        var controller = new FixController(mock(FixTaskService.class), mock(FixQueryService.class), repo, mock(AgentDownloadTokenService.class));
        var req = new MockHttpServletRequest(); req.setAttribute("uid", 7L);
        controller.reviewPatch(12, Map.of("cveId","CVE-2099-12345","ruleDigest","digest","patchDigest","patch","notes","manual distribution confirmation","acknowledged",true,"reviewedBy",999L),req);
        verify(repo).review(12,"CVE-2099-12345","digest","patch","manual distribution confirmation",true,7L);
        controller.revokeReview(12,"review",Map.of("note","scope withdrawn","reviewer",999L),req);
        verify(repo).revoke(12,"review",7L,"scope withdrawn");
    }
}
