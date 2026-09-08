package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.notify.NotifyChannelService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/notify/channels")
public class NotifyChannelController {

    private final NotifyChannelService channels;

    public NotifyChannelController(NotifyChannelService channels) {
        this.channels = channels;
    }

    @GetMapping
    public ApiResult<List<Map<String, Object>>> list() {
        return ApiResult.ok(channels.list());
    }

    @PostMapping
    public ApiResult<Map<String, Object>> create(@RequestBody Map<String, Object> body) {
        return ApiResult.ok(channels.create(body));
    }

    @PutMapping("/{id}")
    public ApiResult<Map<String, Object>> update(@PathVariable long id, @RequestBody Map<String, Object> body) {
        return ApiResult.ok(channels.update(id, body));
    }

    @DeleteMapping("/{id}")
    public ApiResult<Void> delete(@PathVariable long id) {
        channels.delete(id);
        return ApiResult.ok();
    }
}
