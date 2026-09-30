package com.alinksec.service.query;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class VulnQueryServiceTest {

    @Test
    void defaultFindingsQueryDoesNotBindMissingFilters() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(Object[].class))).thenReturn(0L);
        when(jdbc.queryForList(anyString(), any(Object[].class))).thenReturn(List.of());
        VulnQueryService service = new VulnQueryService(jdbc);

        service.findings(null, null, null, null, 1, 20);

        ArgumentCaptor<Object[]> countArgs = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).queryForObject(anyString(), eq(Long.class), countArgs.capture());
        assertEquals(0, countArgs.getValue().length);
        ArgumentCaptor<Object[]> pageArgs = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).queryForList(anyString(), pageArgs.capture());
        assertEquals(List.of(20, 0), List.of(pageArgs.getValue()));
    }

    @Test
    void statsCountFixedFindingsOutsideTheDefaultOpenList() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForMap(anyString())).thenReturn(Map.of("pending", 2L, "fixed", 1L, "total", 3L));
        when(jdbc.queryForList(anyString())).thenReturn(List.of());
        when(jdbc.queryForObject(anyString(), eq(Long.class))).thenReturn(0L);
        VulnQueryService service = new VulnQueryService(jdbc);

        Map<String, Object> stats = service.stats();

        assertEquals(1L, stats.get("fixed"));
        assertEquals(3L, stats.get("total"));
        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).queryForMap(sql.capture());
        assertTrue(sql.getValue().contains("status = 3"));
    }
}
