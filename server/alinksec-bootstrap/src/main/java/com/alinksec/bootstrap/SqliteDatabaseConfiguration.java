package com.alinksec.bootstrap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ScriptUtils;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** Initializes the local SQLite file before JdbcTemplate-backed services are created. */
@Configuration(proxyBeanMethods = false)
@Profile("sqlite")
public class SqliteDatabaseConfiguration {

    @Bean
    static SqliteMigrationBeanPostProcessor sqliteMigrationBeanPostProcessor() {
        return new SqliteMigrationBeanPostProcessor();
    }

    static final class SqliteMigrationBeanPostProcessor implements BeanPostProcessor, Ordered {

        private static final Logger log = LoggerFactory.getLogger(SqliteMigrationBeanPostProcessor.class);
        private static final List<String> MIGRATIONS = List.of(
                "db/sqlite/V001__initial.sql",
                "db/common/V002__security_libraries.sql",
                "db/common/V003__library_schedules.sql",
                "db/common/V004__baseline_packages.sql",
                "db/common/V005__baseline_execution_evidence.sql"
        );

        private final AtomicBoolean initialized = new AtomicBoolean();

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
            if (bean instanceof DataSource dataSource && initialized.compareAndSet(false, true)) {
                migrate(dataSource);
            }
            return bean;
        }

        private void migrate(DataSource dataSource) {
            try (Connection connection = dataSource.getConnection()) {
                configure(connection);
                createMigrationTable(connection);
                for (String path : MIGRATIONS) {
                    apply(connection, path);
                }
            } catch (Exception e) {
                throw new IllegalStateException("SQLite database migration failed", e);
            }
        }

        private void configure(Connection connection) throws SQLException {
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA foreign_keys = ON");
                statement.execute("PRAGMA journal_mode = WAL");
                statement.execute("PRAGMA synchronous = NORMAL");
                statement.execute("PRAGMA busy_timeout = 5000");
            }
        }

        private void createMigrationTable(Connection connection) throws SQLException {
            try (Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TABLE IF NOT EXISTS t_schema_migration (
                          version TEXT PRIMARY KEY,
                          description TEXT NOT NULL,
                          checksum TEXT NOT NULL,
                          applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                        """);
            }
        }

        private void apply(Connection connection, String path) throws Exception {
            ClassPathResource resource = new ClassPathResource(path);
            String filename = resource.getFilename();
            if (filename == null || !filename.matches("V[0-9]{3}__.+\\.sql")) {
                throw new IllegalStateException("Invalid SQLite migration filename: " + path);
            }
            String version = filename.substring(1, 4);
            String description = filename.substring(6, filename.length() - 4).replace('_', ' ');
            String checksum = checksum(resource);
            String appliedChecksum = appliedChecksum(connection, version);
            if (appliedChecksum != null) {
                if (!appliedChecksum.equals(checksum)) {
                    throw new IllegalStateException("Checksum mismatch for SQLite migration V" + version);
                }
                return;
            }

            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                ScriptUtils.executeSqlScript(connection, resource);
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO t_schema_migration(version, description, checksum)
                        VALUES (?, ?, ?)
                        """)) {
                    statement.setString(1, version);
                    statement.setString(2, description);
                    statement.setString(3, checksum);
                    statement.executeUpdate();
                }
                connection.commit();
                log.info("Applied SQLite migration V{}: {}", version, description);
            } catch (Exception e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }

        private String appliedChecksum(Connection connection, String version) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT checksum FROM t_schema_migration WHERE version = ?")) {
                statement.setString(1, version);
                try (ResultSet result = statement.executeQuery()) {
                    return result.next() ? result.getString(1) : null;
                }
            }
        }

        private String checksum(ClassPathResource resource) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = resource.getInputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        }
    }
}
