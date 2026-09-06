package com.alinksec.bootstrap;

import com.alinksec.service.command.CommandRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/** Handles pending commands persisted before full protobuf payloads were introduced. */
@Component
public class LegacyCommandMigrationRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(LegacyCommandMigrationRunner.class);

    private final CommandRepository repository;

    @Value("${ALINKSEC_LEGACY_COMMAND_POLICY:report}")
    private String policy;

    public LegacyCommandMigrationRunner(CommandRepository repository) {
        this.repository = repository;
    }

    @Override
    public void run(String... args) {
        int count = repository.countLegacyPending();
        if (count == 0) {
            return;
        }
        if ("fail".equalsIgnoreCase(policy)) {
            int migrated = repository.failLegacyPending();
            log.warn("Marked {} unreplayable legacy pending commands as failed", migrated);
            return;
        }
        log.warn("Found {} unreplayable legacy pending commands. Set ALINKSEC_LEGACY_COMMAND_POLICY=fail to resolve them explicitly", count);
    }
}
