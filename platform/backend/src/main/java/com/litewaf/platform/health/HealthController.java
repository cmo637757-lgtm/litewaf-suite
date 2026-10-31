package com.litewaf.platform.health;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 健康检查（需求卡片 R37-02）。
 *
 * <p>返回 200 + 一个配置 marker，用来确认「平台自己活着、连的还是这套配置」。
 * 演示环境里 nginx 侧的 /health 会关闭 access_log 且不参与 CC 计数（由 S5 的
 * nginx 配置完成），这里只负责平台自身的存活。
 */
@RestController
public class HealthController {

    /**
     * marker 从环境变量读，默认 demo。部署时设成版本号或提交哈希，
     * 排查「用户看到的到底是哪一版」会很方便。
     */
    private final String marker = System.getenv().getOrDefault("LITEWAF_CONFIG_MARKER", "demo");

    @GetMapping("/api/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "up",
                "config_marker", marker,
                "time_ms", System.currentTimeMillis());
    }
}
