package com.alinksec.gateway.rest;

import com.alinksec.service.report.ComplianceReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;

/** 合规报表（M4）：CSV 导出，Excel 可直接打开 */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final ComplianceReportService reportService;

    public ReportController(ComplianceReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping(value = "/compliance.csv", produces = "text/csv;charset=UTF-8")
    public ResponseEntity<byte[]> complianceCsv(@RequestParam(required = false) String from,
                                                @RequestParam(required = false) String to) {
        String f = from != null ? from : LocalDate.now().minusDays(30).toString();
        String t = to != null ? to : LocalDate.now().toString();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"alinksec-report-" + f + "_" + t + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .body(reportService.csv(f, t));
    }
}
