package com.alinksec.gateway.rest;
import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.virus.*;
import com.alinksec.service.query.VirusQueryService;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class VirusControllerTest {
 @Test void fractionalIdentifiersAndCoercedSwitchesAreRejectedBeforeDispatch() {
  var action=mock(VirusActionService.class);var task=mock(VirusTaskService.class);
  var api=new VirusController(mock(VirusQueryService.class),task,action,mock(VirusDbService.class),mock(AgentDownloadTokenService.class));
  var req=new MockHttpServletRequest();req.setAttribute("uid",7L);
  for(String id:List.of("1.2","\"1\"","9223372036854775808")) assertThrows(IllegalArgumentException.class,()->api.act(JsonUtils.read("{\"findingIds\":["+id+"],\"action\":\"delete\"}"),req));
  assertThrows(IllegalArgumentException.class,()->api.createTask(JsonUtils.read("{\"agentIds\":[\"host\"],\"mode\":1.2}"),req));
  for(String value:List.of("1","\"false\"","null")) assertThrows(IllegalArgumentException.class,()->api.realtime(JsonUtils.read("{\"enabled\":"+value+",\"action\":\"quarantine\"}"),req));
  verifyNoInteractions(action,task);
  when(action.act(anyList(),anyString(),anyLong())).thenReturn(Map.of());
  api.act(JsonUtils.read("{\"findingIds\":[1],\"action\":\"delete\"}"),req);verify(action).act(List.of(1L),"delete",7L);
  assertThrows(IllegalArgumentException.class,()->api.act(JsonUtils.read("{\"findingIds\":[1],\"action\":\"delete\"}"),new MockHttpServletRequest()));
 }
}
