package com.litewaf.platform.stats;

import java.util.List;

/**
 * 统计接口的 DTO 集合。
 *
 * <p>字段全部用 record 表达（不可变、序列化顺序稳定）；
 * 输出命名由 application.yml 的 SNAKE_CASE 策略统一转成 snake_case，与前端约定一致。
 */
public final class StatsDtos {

    private StatsDtos() {
    }

    /**
     * 统计窗口：UTC epoch 毫秒，闭开区间 [start, end)。
     * 前端拿到 start/end 后自行按 Asia/Shanghai 渲染，后端不再做时区换算。
     */
    public record Window(long startMs, long endMs, long seconds) {
    }

    /**
     * 首行四张 KPI。
     * <ul>
     *   <li>n = 窗口内访问记录数</li>
     *   <li>b = 窗口内 WAF 拒绝事件数</li>
     *   <li>ratio = b / n；n=0 时为 null，前端显示「—」而不是 0%</li>
     *   <li>qps = n / 窗口秒数</li>
     * </ul>
     */
    public record Kpi(long n, long b, Double ratio, double qps) {
    }

    /**
     * 耗时指标。
     * 访问耗时取 requests.request_time_ms（毫秒）；
     * 拦截处理耗时取 waf_events.cost_us（微秒，含异步 BODY 等待，不是纯匹配耗时）。
     */
    public record Latency(Double requestP50Ms, Double requestP95Ms,
                          Double rejectCostMeanUs, Double rejectCostP95Us) {
    }

    /** 分组计数项（分类、Top IP、Top URI 共用） */
    public record CountItem(String key, long count) {
    }

    /** 首页一次性返回的聚合结果，避免首屏打四五个请求 */
    public record Summary(Window window, Kpi kpi, Latency latency,
                          List<CountItem> categories, List<CountItem> topIps,
                          List<CountItem> topUris) {
    }

    /**
     * 趋势图上的一个点：固定时间桶的起点（UTC 毫秒）、访问数、拦截数。
     *
     * <p>桶按 UTC 对齐（floor(ts / bucket) * bucket），跨时区不变形；
     * 展示时前端再按 Asia/Shanghai 换成横轴标签。
     */
    public record TrendItem(long t, long n, long b) {
    }
}
