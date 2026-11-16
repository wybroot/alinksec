package com.alinksec.service.cluster;
import org.junit.jupiter.api.Test;
import javax.sql.DataSource;
import java.sql.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class BusinessReadinessTest {
 @Test void dependencyFailureAndRecoveryAreReflected()throws Exception{
  var source=mock(DataSource.class);var connection=mock(Connection.class);var statement=mock(Statement.class);var rows=mock(ResultSet.class);
  when(source.getConnection()).thenThrow(new SQLException("offline")).thenReturn(connection);when(connection.createStatement()).thenReturn(statement);when(statement.executeQuery(anyString())).thenReturn(rows);when(rows.next()).thenReturn(true);when(statement.executeUpdate(anyString())).thenReturn(1);
  var readiness=new BusinessReadiness(source);try{assertFalse(readiness.ready());assertTrue(readiness.ready());verify(statement).setQueryTimeout(1);}finally{readiness.close();}
 }
 @Test void failedWriteFailsReadiness()throws Exception{
  var source=mock(DataSource.class);var connection=mock(Connection.class);var statement=mock(Statement.class);var rows=mock(ResultSet.class);
  when(source.getConnection()).thenReturn(connection);when(connection.createStatement()).thenReturn(statement);when(statement.executeQuery(anyString())).thenReturn(rows);when(rows.next()).thenReturn(true);when(statement.executeUpdate(anyString())).thenThrow(new SQLException("read-only"));
  var readiness=new BusinessReadiness(source);try{assertFalse(readiness.ready());}finally{readiness.close();}
 }
 @Test void blockedPoolHasDeadlineAndNoUnboundedProbeQueue()throws Exception{
  var source=mock(DataSource.class);when(source.getConnection()).thenAnswer(i->{try{Thread.sleep(10000);}catch(InterruptedException stop){Thread.currentThread().interrupt();}throw new SQLException("blocked");});
  var readiness=new BusinessReadiness(source);long begin=System.nanoTime();try{assertFalse(readiness.ready());assertTrue(System.nanoTime()-begin<3_000_000_000L);}finally{readiness.close();}
 }
}
