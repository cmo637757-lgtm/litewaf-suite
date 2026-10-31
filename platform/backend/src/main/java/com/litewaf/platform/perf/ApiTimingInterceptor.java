package com.litewaf.platform.perf;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;

/**
 * 平台自身接口的耗时统计（R33-06 的一半）。
 *
 * <p>WAF 的 cost_us 和源站 request_time 都已经从日志里采进来了，唯独
 * 「平台自己的接口有多慢」没人测。这里用拦截器把每个 /api/** 请求的耗时
 * 记进一个固定大小的环形缓冲，再算 P50/P95。
 *
 * <p>为什么不落库：这是运维自检用的滑窗数据，量级和保留期都不值得占一张表；
 * 进程重启后清零也不影响任何业务口径。
 */
@Component
public class ApiTimingInterceptor implements HandlerInterceptor {

    private static final String ATTR_START = "litewaf.apiStartNanos";

    private final long[] samples;
    private int cursor = 0;
    private int filled = 0;
    private long total = 0;

    public ApiTimingInterceptor(@Value("${app.perf.buffer-size:200}") int size) {
        this.samples = new long[Math.max(20, size)];
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        request.setAttribute(ATTR_START, System.nanoTime());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        Object t0 = request.getAttribute(ATTR_START);
        if (!(t0 instanceof Long)) {
            return;
        }
        long micros = (System.nanoTime() - (Long) t0) / 1000;
        synchronized (this) {
            samples[cursor] = micros;
            cursor = (cursor + 1) % samples.length;
            if (filled < samples.length) {
                filled++;
            }
            total++;
        }
    }

    /** 快照：返回 P50/P95/最大值，单位毫秒（保留 2 位）。 */
    public synchronized Snapshot snapshot() {
        if (filled == 0) {
            return new Snapshot(0, 0.0, 0.0, 0.0, 0);
        }
        long[] copy = Arrays.copyOf(samples, filled);
        Arrays.sort(copy);
        return new Snapshot(
                total,
                round2(percentile(copy, 50) / 1000.0),
                round2(percentile(copy, 95) / 1000.0),
                round2(copy[copy.length - 1] / 1000.0),
                filled);
    }

    /** 最近邻秩法，与 StatsService 用的是同一套口径（k = ceil(p/100 × n)）。 */
    private static long percentile(long[] sorted, double p) {
        int k = (int) Math.ceil(p / 100.0 * sorted.length);
        k = Math.max(1, Math.min(k, sorted.length));
        return sorted[k - 1];
    }

    private static double round2(double v) {
        return Math.round(v * 100) / 100.0;
    }

    /** count=累计请求数，p50Ms/p95Ms/maxMs 单位毫秒，window=缓冲里实际保存的样本数。 */
    public record Snapshot(long count, double p50Ms, double p95Ms, double maxMs, int window) {
    }
}
