package com.alinksec.service.audit;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditServiceTest {

    @Test
    void queryDoesNotProjectHistoricalRequestBodies() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);

        new AuditService(jdbc).query(null, null, 1, 20);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).queryForList(sql.capture());
        assertFalse(sql.getValue().contains("body_digest"));
    }
}
