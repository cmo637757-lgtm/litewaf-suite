package com.litewaf.platform.blocklist;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 黑名单接口：查看 / 手动解封。
 *
 * <p>封禁入口不对外暴露 —— 只有告警服务在红色告警时内部调用 {@link BlocklistService#block}，
 * 避免「谁都能把别人的 IP 封掉」。人工要封，用执行器 `/blocklist` 或改配置文件。
 */
@RestController
@RequestMapping("/api/blocklist")
public class BlocklistController {

    private final BlocklistService service;

    public BlocklistController(BlocklistService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(defaultValue = "100") int limit) {
        List<BlocklistService.Entry> items = service.list(limit);
        return Map.of(
                "items", items,
                "total", items.size(),
                "active", service.activeCount(),
                "as_of", System.currentTimeMillis());
    }

    @PostMapping("/{ip}/unblock")
    public Map<String, Object> unblock(@PathVariable String ip) {
        boolean changed = service.unblock(ip);
        return Map.of("ip", ip, "changed", changed, "active", service.activeCount());
    }
}
