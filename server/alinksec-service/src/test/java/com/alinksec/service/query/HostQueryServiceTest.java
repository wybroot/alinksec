package com.alinksec.service.query;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HostQueryServiceTest {

    @Test
    void paginationWithoutKeywordUsesOnlyActualSqlParameters() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(Object[].class))).thenReturn(101L);
        when(jdbc.queryForList(anyString(), any(Object[].class))).thenReturn(List.of());
        HostQueryService service = new HostQueryService(jdbc);

        service.list(null, 1, null, 2, 20);

        ArgumentCaptor<String> countSql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> countArgs = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).queryForObject(countSql.capture(), eq(Long.class), countArgs.capture());
        assertTrue(countSql.getValue().contains("a.status = ?"));
        assertArrayEquals(new Object[]{1}, countArgs.getValue());

        ArgumentCaptor<String> pageSql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> pageArgs = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).queryForList(pageSql.capture(), pageArgs.capture());
        assertTrue(pageSql.getValue().contains("a.status = ?\nORDER BY"));
        assertArrayEquals(new Object[]{1, 20, 20}, pageArgs.getValue());
    }
}
