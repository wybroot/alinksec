package com.alinksec.service.user;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.SimpleTransactionStatus;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class UserServiceTest {
    @Test void auditRollbackFailureMustReachTheCaller() {
        var jdbc=mock(JdbcTemplate.class);
        var manager=mock(PlatformTransactionManager.class);
        var status=new SimpleTransactionStatus();
        when(manager.getTransaction(any(TransactionDefinition.class))).thenReturn(status);
        when(jdbc.update(anyString(),any(Object[].class)))
                .thenThrow(new DataIntegrityViolationException("fixture audit failure"));
        var failure=new TransactionSystemException("fixture rollback unavailable");
        doThrow(failure).when(manager).rollback(status);
        var users=new UserService(jdbc,manager);
        assertSame(failure,assertThrows(TransactionSystemException.class,
                ()->users.audit(1L,"fixture","password_changed","")));
    }
}
