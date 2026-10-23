package com.alinksec.gateway.rest;

import com.alinksec.service.library.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LibraryGovernanceControllerTest {
    @Test void trustPolicyAndItemDecisionUseOnlyAuthenticatedActorAndQueueDurableDelivery() throws Exception {
        var catalog=mock(LibraryCatalog.class);var sync=mock(LibrarySyncService.class);
        var controller=new LibraryController(sync,catalog,new LibraryProperties(),mock(LibrarySchedule.class));
        var request=new MockHttpServletRequest();request.setAttribute("uid",7L);
        controller.sourcePolicy("provider",new LibraryController.SourcePolicyRequest("reviewed",40,true,3L,"Quarantine review"),request);
        verify(catalog).setSourcePolicy("provider","reviewed",40,true,3L,7L,"Quarantine review");
        controller.selectionDecision(new LibraryController.SelectionRequest("cve","CVE-2099-12345","select","provider","a".repeat(64),4L,"Applicability review"),request);
        verify(catalog).decideSelection("cve","CVE-2099-12345","select","provider","a".repeat(64),4L,7L,"Applicability review");
        verify(sync,times(2)).selectionChanged();
        assertThrows(IllegalArgumentException.class,()->controller.sourcePolicy("provider",new LibraryController.SourcePolicyRequest("reviewed",40,true,3L,"No user"),new MockHttpServletRequest()));
    }
    @Test void lifecycleUsesAuthenticatedActorAndRequiresExplicitDecision() throws Exception {
        var catalog=mock(LibraryCatalog.class); var sync=mock(LibrarySyncService.class);
        var controller=new LibraryController(sync,catalog,new LibraryProperties(),mock(LibrarySchedule.class));
        var request=new MockHttpServletRequest(); request.setAttribute("uid",7L);
        when(catalog.decideCve(anyString(),anyString(),anyBoolean(),anyString(),anyLong(),anyString())).thenReturn(Map.of());
        controller.decision("provider","CVE-2099-12345",new LibraryController.GovernanceRequest(true,"digest","Bad applicability"),request);
        verify(catalog).decideCve("provider","CVE-2099-12345",true,"digest",7L,"Bad applicability");
        verify(sync).recheckAssets();
        assertThrows(IllegalArgumentException.class,()->controller.decision("provider","CVE-2099-12345",new LibraryController.GovernanceRequest(null,"digest","note"),request));
        when(sync.retireSource(anyString(),anyLong(),anyString())).thenReturn(Map.of());
        controller.retire("provider",new LibraryController.RetirementRequest("Provider stopped"),request);
        verify(sync).retireSource("provider",7L,"Provider stopped");
        assertThrows(IllegalArgumentException.class,()->controller.retire("provider",new LibraryController.RetirementRequest("note"),new MockHttpServletRequest()));
    }
}
