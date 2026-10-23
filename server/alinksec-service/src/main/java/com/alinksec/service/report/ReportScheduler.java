package com.alinksec.service.report;

import java.time.Instant;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ReportScheduler {
    private final ComplianceReportService reports;
    public ReportScheduler(ComplianceReportService reports){this.reports=reports;}
    @Scheduled(fixedDelayString="${alinksec.reports.poll-ms:60000}")
    public void tick(){reports.runDue(Instant.now());}
}
