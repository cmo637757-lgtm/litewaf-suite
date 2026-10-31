package com.litewaf.platform.stats;

import com.litewaf.platform.events.EventDtos.EventItem;
import com.litewaf.platform.stats.StatsDtos.CountItem;
import com.litewaf.platform.stats.StatsDtos.Kpi;
import com.litewaf.platform.stats.StatsDtos.Latency;
import com.litewaf.platform.stats.StatsDtos.Summary;
import com.litewaf.platform.stats.StatsDtos.TrendItem;
import com.litewaf.platform.stats.StatsDtos.Window;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 统计口径的唯一实现（需求卡片第 3.4 节）。
 *
 * <p><b>为什么直接写 SQL</b>：这些指标的定义就是 SQL 聚合（COUNT / GROUP BY / AVG），
 * 中间再套一层实体映射只会多一次转换、多一个可能算错的地方。
 *
 * <p><b>固定口径</b>：
 * <ul>
 *   <li>N = 访问记录数（requests 行数），B = WAF 拒绝事件数（waf_events 行数）</li>
 *   <li>ratio = B / N，N=0 时返回 null（前端显示「—」）</li>
 *   <li>QPS = N / 窗口秒数（窗口是 [start, end) 的整数秒）</li>
 *   <li>分位数用最近秩（nearest-rank），k = ceil(p × (n+1))，1 起算：
 *       n=20 时 P50 落在第 11 个、P95 落在第 20 个</li>
 * </ul>
 */
@Service
public class StatsService {

    /** 表名白名单：SQL 里要拼表名时只允许这两个，避免任何外部输入进入 SQL */
    private static final String T_REQ = "requests";
    private static final String T_EVT = "waf_events";

    private static final int TOP_LIMIT = 10;
    private static final int URI_MAX_LEN = 200;

    private final JdbcTemplate jdbc;

    public StatsService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * 首页聚合：一次返回窗口内全部 KPI 与三组 Top 数据。
     *
     * @param fromMs 窗口起点（含），UTC 毫秒
     * @param toMs   窗口终点（不含），UTC 毫秒
     */
    public Summary summary(long fromMs, long toMs) {
        long n = count(T_REQ, fromMs, toMs);
        long b = count(T_EVT, fromMs, toMs);

        long seconds = Math.max(1L, (toMs - fromMs) / 1000L);
        Double ratio = n > 0 ? round4(b / (double) n) : null;
        double qps = round4(n / (double) seconds);

        Double reqP50 = percentile(T_REQ, "request_time_ms", fromMs, toMs, n, 0.50);
        Double reqP95 = percentile(T_REQ, "request_time_ms", fromMs, toMs, n, 0.95);
        Double costMean = b > 0 ? round2(avgCost(fromMs, toMs)) : null;
        Double costP95 = percentile(T_EVT, "cost_us", fromMs, toMs, b, 0.95);

        return new Summary(
                new Window(fromMs, toMs, seconds),
                new Kpi(n, b, ratio, qps),
                new Latency(reqP50, reqP95, costMean, costP95),
                groupCount(T_EVT, "category_display", fromMs, toMs, TOP_LIMIT),
                groupCount(T_EVT, "client_ip", fromMs, toMs, TOP_LIMIT),
                topUris(fromMs, toMs));
    }

    // ------------------------------------------------------------ 基础聚合

    private long count(String table, long from, long to) {
        Long v = jdbc.queryForObject(
                "SELECT COUNT(*) FROM " + table + " WHERE event_time_ms >= ? AND event_time_ms < ?",
                Long.class, from, to);
        return v == null ? 0L : v;
    }

    private Double avgCost(long from, long to) {
        Double v = jdbc.queryForObject(
                "SELECT COALESCE(AVG(cost_us), 0) FROM " + T_EVT
                        + " WHERE event_time_ms >= ? AND event_time_ms < ?",
                Double.class, from, to);
        return v == null ? 0.0 : v;
    }

    /**
     * 最近秩分位数：按列排序后取第 k 个（k 从 1 起），OFFSET = k-1。
     * 用 LIMIT 1 OFFSET 而不是把全表拉回 Java 排序，10 万行也只需一次索引扫描。
     */
    private Double percentile(String table, String column, long from, long to, long n, double p) {
        if (n <= 0) {
            return null;
        }
        int k = nearestRank(p, n);
        List<Double> rows = jdbc.queryForList(
                "SELECT " + column + " FROM " + table
                        + " WHERE event_time_ms >= ? AND event_time_ms < ?"
                        + " ORDER BY " + column + " LIMIT 1 OFFSET ?",
                Double.class, from, to, k - 1);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /**
     * 最近秩取第几个：k = clamp(ceil(p × (n+1)), 1, n)。
     *
     * <p>为什么是 n+1 不是 n：按 n 算时 n=20 的 P50 落在第 10 个（90ms）、P95 落在第 19 个（180ms），
     * 与需求卡片第七章固定的 100ms / 190ms 对不上；用 n+1 后 P50=第 11 个、P95=第 20 个，正好吻合。
     */
    static int nearestRank(double p, long n) {
        int k = (int) Math.ceil(p * (n + 1));
        return Math.max(1, Math.min(k, (int) n));
    }

    private List<CountItem> groupCount(String table, String column, long from, long to, int limit) {
        return jdbc.query(
                "SELECT " + column + " AS k, COUNT(*) AS c FROM " + table
                        + " WHERE event_time_ms >= ? AND event_time_ms < ?"
                        + " GROUP BY " + column + " ORDER BY c DESC, k ASC LIMIT " + limit,
                (rs, i) -> new CountItem(rs.getString("k"), rs.getLong("c")),
                from, to);
    }

    /** Top URI 要截断：URI 是 TEXT，个别会被塞超长串，直接回传会把图表挤爆 */
    private List<CountItem> topUris(long from, long to) {
        return jdbc.query(
                "SELECT uri AS k, COUNT(*) AS c FROM " + T_EVT
                        + " WHERE event_time_ms >= ? AND event_time_ms < ?"
                        + " GROUP BY uri ORDER BY c DESC, k ASC LIMIT " + TOP_LIMIT,
                (rs, i) -> {
                    String uri = rs.getString("k");
                    if (uri != null && uri.length() > URI_MAX_LEN) {
                        uri = uri.substring(0, URI_MAX_LEN) + "…";
                    }
                    return new CountItem(uri, rs.getLong("c"));
                },
                from, to);
    }

    private static double round4(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    // ------------------------------------------------------------ 趋势与最近事件

    /**
     * 按固定时间桶返回「访问数 / 拦截数」两条曲线。
     *
     * <p>两张表分开聚合再在内存里合并：
     * 一条 SQL 同时 COUNT 两张表要么用 UNION ALL 再 GROUP BY（写法绕、索引利用差），
     * 要么两次扫表——数据量 10 万级，两次扫表反而更直接。
     *
     * <p>只返回有数据的桶；前端按 [from, to) 补零，这样图表的横轴才是连续的。
     */
    public List<TrendItem> trend(long fromMs, long toMs, int bucketSeconds) {
        long bucketMs = Math.max(1000L, bucketSeconds * 1000L);
        Map<Long, long[]> acc = new TreeMap<>();

        accumulate(acc, T_REQ, fromMs, toMs, bucketMs, 0);
        accumulate(acc, T_EVT, fromMs, toMs, bucketMs, 1);

        List<TrendItem> out = new ArrayList<>(acc.size());
        acc.forEach((t, v) -> out.add(new TrendItem(t, v[0], v[1])));
        return out;
    }

    private void accumulate(Map<Long, long[]> acc, String table,
                            long from, long to, long bucketMs, int slot) {
        jdbc.query(
                "SELECT FLOOR(event_time_ms / ?) * ? AS bucket, COUNT(*) AS c FROM " + table
                        + " WHERE event_time_ms >= ? AND event_time_ms < ? GROUP BY bucket ORDER BY bucket",
                (RowCallbackHandler) rs -> {
                    long bucket = rs.getLong("bucket");
                    acc.computeIfAbsent(bucket, k -> new long[2])[slot] = rs.getLong("c");
                },
                bucketMs, bucketMs, from, to);
    }

    /** 最近事件：首页底部表格用，只要 5–10 条 */
    public List<EventItem> recent(int limit) {
        int n = Math.max(1, Math.min(limit, 50));
        return jdbc.query(
                "SELECT id, event_time_ms, client_ip, method, uri, status, reason, rule_id, rule_name, "
                        + "zone, category, category_display, score, total_score, action, cost_us "
                        + "FROM waf_events ORDER BY event_time_ms DESC, id DESC LIMIT " + n,
                (rs, i) -> new EventItem(
                        rs.getLong("id"),
                        java.time.Instant.ofEpochMilli(rs.getLong("event_time_ms")).toString(),
                        rs.getString("client_ip"),
                        rs.getString("method"),
                        rs.getString("uri"),
                        rs.getInt("status"),
                        rs.getString("reason"),
                        rs.getInt("rule_id"),
                        rs.getString("rule_name"),
                        rs.getString("category"),
                        rs.getString("category_display"),
                        rs.getString("action"),
                        rs.getInt("cost_us"),
                        rs.getInt("score")));
    }
}
