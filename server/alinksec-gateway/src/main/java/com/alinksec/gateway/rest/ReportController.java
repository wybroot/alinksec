package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.report.*;
import com.alinksec.service.scan.VulnerabilityEvidence;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
public class ReportController {
    private final ComplianceReportService reports;
    public ReportController(ComplianceReportService reports){this.reports=reports;}
    @ModelAttribute public void privateResponse(jakarta.servlet.http.HttpServletResponse response){response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");}
    @GetMapping("/preview")
    public ApiResult<?> preview(@RequestParam(required=false)String from,@RequestParam(required=false)String to,
                               @RequestParam(required=false)Long groupId,@RequestParam(required=false)Integer osType) {
        return ApiResult.ok(reports.preview(new ReportQuery(from,to,groupId,osType)));
    }
    @GetMapping("/compliance.{format}")
    public ResponseEntity<byte[]> live(@PathVariable String format,@RequestParam(required=false)String from,@RequestParam(required=false)String to,
                                      @RequestParam(required=false)Long groupId,@RequestParam(required=false)Integer osType,@RequestParam(required=false)String expectedDataDigest) {
        var report=reports.preview(new ReportQuery(from,to,groupId,osType));
        if(expectedDataDigest!=null && !expectedDataDigest.equals(report.get("dataDigest")))throw new IllegalArgumentException("报表数据已变化，请刷新预览或查看已保存的快照");
        return download(report,format,null);
    }
    public record SnapshotRequest(String title,String from,String to,Long groupId,Integer osType){}
    @PostMapping("/snapshots") public ApiResult<?> save(@RequestBody SnapshotRequest body,HttpServletRequest request) {
        return ApiResult.ok(reports.save(new ReportQuery(body.from(),body.to(),body.groupId(),body.osType()),body.title(),actor(request)));
    }
    @GetMapping("/snapshots") public ApiResult<?> history(@RequestParam(defaultValue="1")int page,@RequestParam(defaultValue="20")int size){return ApiResult.ok(reports.history(page,size));}
    @GetMapping("/snapshots/{id}") public ApiResult<?> snapshot(@PathVariable String id){return ApiResult.ok(reports.snapshot(id));}
    @SuppressWarnings("unchecked")
    @GetMapping("/snapshots/{id}/export.{format}") public ResponseEntity<byte[]> export(@PathVariable String id,@PathVariable String format) {
        var snapshot=reports.snapshot(id);return download((Map<String,Object>)snapshot.get("report"),format,(String)snapshot.get("sha256"));
    }
    @DeleteMapping("/snapshots/{id}") public ApiResult<?> delete(@PathVariable String id,HttpServletRequest request){reports.delete(id,actor(request));return ApiResult.ok(null);}
    @GetMapping("/schedules") public ApiResult<?> schedules(){return ApiResult.ok(reports.schedules());}
    @PostMapping("/schedules") public ApiResult<?> createSchedule(@RequestBody ComplianceReportService.ScheduleRequest body,HttpServletRequest request){return ApiResult.ok(reports.schedule(null,body,actor(request)));}
    @PutMapping("/schedules/{id}") public ApiResult<?> updateSchedule(@PathVariable String id,@RequestBody ComplianceReportService.ScheduleRequest body,HttpServletRequest request){return ApiResult.ok(reports.schedule(id,body,actor(request)));}
    @DeleteMapping("/schedules/{id}") public ApiResult<?> deleteSchedule(@PathVariable String id,@RequestParam long revision,HttpServletRequest request){reports.deleteSchedule(id,revision,actor(request));return ApiResult.ok(null);}
    private static Long actor(HttpServletRequest request) {
        if(!(request.getAttribute("uid") instanceof Number id))throw new IllegalArgumentException("需要已登录账号");return id.longValue();
    }
    private static String digest(byte[] bytes) {
        try{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
    private static ResponseEntity<byte[]> download(Map<String,Object> report,String format,String snapshotDigest) {
        byte[] bytes=ReportExport.render(report,format);
        String type=switch(format){case "csv"->"text/csv;charset=UTF-8";case "xlsx"->"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";case "html"->"text/html;charset=UTF-8";case "json"->"application/json;charset=UTF-8";default->throw new IllegalArgumentException("导出格式无效");};
        var response=ResponseEntity.ok().contentType(MediaType.parseMediaType(type))
                .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\"alinksec-report."+format+"\"")
                .header(HttpHeaders.CACHE_CONTROL,"no-store").header("X-Content-Type-Options","nosniff")
                .header("Content-Security-Policy","sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
                .header("X-Content-SHA256",digest(bytes));
        if(snapshotDigest!=null)response.header("X-Report-Snapshot-SHA256",snapshotDigest);
        return response.body(bytes);
    }
}
