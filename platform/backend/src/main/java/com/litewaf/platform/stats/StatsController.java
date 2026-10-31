package com.litewaf.platform.stats;

import com.litewaf.platform.stats.StatsDtos.Summary;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;

/**
 * 只读统计接口。
 *
 * <p>窗口规则：
 * <ul>
 *   <li>不传 {@code from}/{@code to} 时，取「当前时刻往前 {@code window_s} 秒」</li>
 *   <li>传了就用传入的 UTC 毫秒，闭开区间 [from, to)</li>
 *   <li>窗口最长 7 天（604800 秒），防止有人拉一把大窗口把库扫穿</li>
 * </ul>
 *
 * <p>F20 验收示例：
 * {@code GET /api/stats/summary?from=1789862400000&to=1789862460000}
 * 必须返回 N=20、B=5、ratio=0.25、qps=0.3333、P50=100、P95=190。
 */
@RestController
@RequestMapping("/api/stats")
public class StatsController {

    private final StatsService stats;
    private final StatsStreamService stream;

    public StatsController(StatsService stats, StatsStreamService stream) {
        this.stats = stats;
        this.stream = stream;
    }

    @GetMapping("/summary")
    public Summary summary(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(name = "window_s", defaultValue = "60")
            @Min(1) @Max(604800) int windowSeconds) {

        long toMs = (to != null) ? to : System.currentTimeMillis();
        long fromMs = (from != null) ? from : toMs - windowSeconds * 1000L;

        if (fromMs >= toMs) {
            throw new IllegalArgumentException("窗口起点必须小于终点（闭开区间 [from, to)）");
        }
        if (toMs - fromMs > 604800_000L) {
            throw new IllegalArgumentException("窗口最长 7 天，请缩小范围");
        }
        return stats.summary(fromMs, toMs);
    }

    /**
     * 趋势曲线：按固定时间桶返回访问数与拦截数。
     *
     * <p>示例：{@code GET /api/stats/trend?window_s=3600&bucket_s=60}
     * → 最近一小时的每分钟一个点。{@code bucket_s} 限 10–86400，避免有人要 1 秒粒度把库打穿。
     */
    @GetMapping("/trend")
    public Map<String, Object> trend(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(name = "window_s", defaultValue = "3600")
            @Min(1) @Max(604800) int windowSeconds,
            @RequestParam(name = "bucket_s", defaultValue = "60")
            @Min(10) @Max(86400) int bucketSeconds) {

        long toMs = (to != null) ? to : System.currentTimeMillis();
        long fromMs = (from != null) ? from : toMs - windowSeconds * 1000L;
        if (fromMs >= toMs) {
            throw new IllegalArgumentException("窗口起点必须小于终点（闭开区间 [from, to)）");
        }
        return Map.of(
                "window", Map.of("start_ms", fromMs, "end_ms", toMs, "bucket_s", bucketSeconds),
                "points", stats.trend(fromMs, toMs, bucketSeconds));
    }

    /** 首页底部「最近拦截」表格，默认 8 条 */
    @GetMapping("/recent")
    public Map<String, Object> recent(@RequestParam(defaultValue = "8") @Min(1) @Max(50) int limit) {
        return Map.of("items", stats.recent(limit), "as_of", System.currentTimeMillis());
    }

    /**
     * 实时推送（Server-Sent Events）。
     *
     * <p>每 2 秒推一个 {@code tick} 事件，内容是「最近 8 条拦截 + 最新事件 id + 事件总数」。
     * 前端只在 {@code latest_id} 变化时才回头拉一次全量统计，避免每次都查库。
     *
     * <p>注意：浏览器 {@code EventSource} 不能自定义请求头，所以 token 用查询参数传
     * （{@link com.litewaf.platform.security.JwtAuthFilter} 对这条路径额外接受 {@code ?token=}）。
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return stream.subscribe();
    }
}
