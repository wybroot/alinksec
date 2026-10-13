package com.alinksec.gateway.rest;

import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.fix.*;
import com.alinksec.service.query.FixQueryService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.util.Map;
import static org.mockito.Mockito.*;

class FixControllerTest {
    @Test void approvalAndCancellationUseOnlyTheAuthenticatedAccount() {
        var service=mock(FixTaskService.class);
        var controller=new FixController(service,mock(FixQueryService.class),mock(PatchRepoService.class),mock(AgentDownloadTokenService.class));
        var request=new MockHttpServletRequest(); request.setAttribute("uid",7L);
        controller.approve(11,Map.of("operator","assigned-admin","uid",99L),request);
        controller.cancel(11,Map.of("reason","Change maintenance plan","uid",99L),request);
        verify(service).approve(11,7L); verify(service).cancel(11,7L,"Change maintenance plan");
    }
}
