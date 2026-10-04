package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.library.LibraryCatalog;
import com.alinksec.service.library.LibraryProperties;
import com.alinksec.service.library.LibrarySyncService;
import com.alinksec.service.library.LibrarySchedule;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.Map;

@RestController
@RequestMapping("/api/libraries")
public class LibraryController {
    private final LibrarySyncService sync;
    private final LibraryCatalog catalog;
    private final LibraryProperties props;
    private final LibrarySchedule schedules;
    public LibraryController(LibrarySyncService sync, LibraryCatalog catalog, LibraryProperties props, LibrarySchedule schedules) {
        this.sync = sync; this.catalog = catalog; this.props = props; this.schedules = schedules;
    }
    @GetMapping public ApiResult<Map<String, Object>> status() { return ApiResult.ok(sync.status()); }
    @PostMapping("/sources/{id}/sync")
    public ApiResult<Map<String, Object>> synchronize(@PathVariable String id) {
        return ApiResult.ok(Map.of("accepted", sync.trigger(id)));
    }
    public record ScheduleRequest(Boolean enabled, Long intervalMs) {}
    @PutMapping("/sources/{id}/schedule")
    public ApiResult<?> schedule(@PathVariable String id, @RequestBody ScheduleRequest request) {
        return ApiResult.ok(schedules.update(id, request.enabled(), request.intervalMs()));
    }
    @DeleteMapping("/sources/{id}/schedule")
    public ApiResult<?> resetSchedule(@PathVariable String id) { return ApiResult.ok(schedules.reset(id)); }
    @GetMapping("/sources/{id}/runs")
    public ApiResult<?> runs(@PathVariable String id) { return ApiResult.ok(sync.history(id)); }
    @PostMapping("/cves/import")
    public ApiResult<Map<String, Object>> importCves(@RequestParam("file") MultipartFile file) throws Exception {
        if (file.getSize() > props.getMaxDownloadBytes()) throw new IllegalArgumentException("漏洞文件超过大小上限");
        var documents = sync.readCves(file.getInputStream());
        int count = catalog.cves("manual", documents);
        sync.recheckAssets();
        return ApiResult.ok(Map.of("imported", count));
    }
}
