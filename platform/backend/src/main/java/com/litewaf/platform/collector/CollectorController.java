package com.litewaf.platform.collector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 采集器健康状态。
 *
 * <p>背景：采集器是独立进程，它挂掉的时候 WAF 还在正常拦截、平台接口也正常，
 * 只有页面上的数字会停止增长 —— 靠人眼发现太晚。采集器每轮把自己「还活着、
 * 读到哪、积压多少」写成 JSON（见 {@code lwaf_collect.py:write_status}），
 * 这里读出来加上「多久没更新」一起给前端。
 *
 * <p>判活口径故意不用文件存在与否：进程被 kill -9 时文件还在，只能靠心跳时间判断。
 * 超过 {@code liveWindowMs}（默认 15 秒，是轮询间隔的 15 倍）就算不健康。
 */
@RestController
@RequestMapping("/api/collector")
public class CollectorController {

    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${app.collector.status-file:/opt/litewaf/runtime/logs/collector_status.json}")
    private String statusFile;

    @Value("${app.collector.alive-window-ms:15000}")
    private long aliveWindowMs;

    /** 前端要的数据结构，一次给全，省得前端算时间差。 */
    public record SourceItem(String name, String kind, String path,
                             long offset, long size, long lagBytes) {
    }

    public record CollectorStatus(
            boolean alive,          // 心跳是否新鲜
            boolean fileFound,      // 状态文件在不在（从没启动过 = false）
            long ts,                // 采集器最后一次心跳（epoch ms）
            long ageMs,             // 距今多久
            long pid,
            int rounds,
            long ingestedTotal,
            long errorsTotal,
            String lastError,
            List<SourceItem> sources,
            String hint             // 给人看的一句话
    ) {
    }

    @GetMapping("/status")
    public CollectorStatus status() {
        File f = new File(statusFile);
        if (!f.isFile()) {
            return new CollectorStatus(false, false, 0, -1, 0, 0, 0, 0,
                    "", List.of(),
                    "还没收到过采集器心跳：确认采集器已启动（见使用说明第 1 节第 ⑤ 步）");
        }
        JsonNode root;
        try {
            root = mapper.readTree(f);
        } catch (Exception e) {
            // 文件存在但读不动，通常是写到一半被读到（正常情况下不会，因为写了原子替换）
            return new CollectorStatus(false, true, 0, -1, 0, 0, 0, 0,
                    "状态文件解析失败：" + e.getClass().getSimpleName(), List.of(),
                    "状态文件损坏，下一轮心跳会自动覆盖");
        }

        long ts = root.path("ts").asLong(0);
        long age = ts <= 0 ? -1 : Math.max(0, System.currentTimeMillis() - ts);
        boolean alive = age >= 0 && age <= aliveWindowMs;

        List<SourceItem> sources = new ArrayList<>();
        for (JsonNode s : root.path("sources")) {
            sources.add(new SourceItem(
                    s.path("name").asText(""),
                    s.path("kind").asText(""),
                    s.path("path").asText(""),
                    s.path("offset").asLong(0),
                    s.path("size").asLong(0),
                    s.path("lag_bytes").asLong(0)));
        }

        String hint = alive
                ? "采集器运行中"
                : String.format("采集器已 %d 秒没有心跳，页面数字会停更；看 /tmp/collector.log", age / 1000);

        return new CollectorStatus(
                alive, true, ts, age,
                root.path("pid").asLong(0),
                root.path("rounds").asInt(0),
                root.path("ingested_total").asLong(0),
                root.path("errors_total").asLong(0),
                root.path("last_error").asText(""),
                sources, hint);
    }
}
