package com.litewaf.platform.alert;

import com.litewaf.platform.alert.AlertDtos.Alert;
import com.litewaf.platform.alert.AlertDtos.AlertDetail;
import com.litewaf.platform.alert.AlertDtos.ConsumerState;
import com.litewaf.platform.alert.AlertDtos.Delivery;
import com.litewaf.platform.alert.AlertDtos.EventBrief;
import com.litewaf.platform.alert.AlertDtos.Rule;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 告警模块的数据访问层。
 *
 * 全部用显式 SQL：告警语义（固定桶、抑制、去重）很难用 ORM 表达清楚，
 * 写出来反而更容易对照需求卡片逐条核验。
 *
 * P5 起「数什么」由 rule.metric 决定，所以计数相关的 SQL 都改成
 * 「metricWhere() 拼 WHERE + metricArgs() 给参数」两段式，避免为每个维度
 * 复制一份几乎相同的 SQL。注意拼进去的只有列名/运算符，值一律走占位符。
 */
@Repository
public class AlertRepository {

    private final JdbcTemplate jdbc;

    public AlertRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ── 规则 ────────────────────────────────────────────────────────────

    private static final String RULE_COLS =
            "id, name, metric, match_value, category, threshold, ratio, window_s, suppress_s, "
                    + "severity, channel, webhook_url, enabled";

    private static Rule mapRule(java.sql.ResultSet rs, int i) throws java.sql.SQLException {
        return new Rule(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getInt(6), rs.getDouble(7), rs.getInt(8), rs.getInt(9),
                rs.getString(10), rs.getString(11), rs.getString(12), rs.getInt(13) == 1);
    }

    public List<Rule> rules() {
        return jdbc.query("SELECT " + RULE_COLS + " FROM alert_rules ORDER BY id", AlertRepository::mapRule);
    }

    /** 全量更新一条规则（前端「保存」按钮走这里）。 */
    public void updateRule(int id, int threshold, double ratio, int windowS, int suppressS,
                           String severity, String channel, String webhookUrl, boolean enabled) {
        jdbc.update("UPDATE alert_rules SET threshold = ?, ratio = ?, window_s = ?, suppress_s = ?, "
                        + "severity = ?, channel = ?, webhook_url = ?, enabled = ? WHERE id = ?",
                threshold, ratio, windowS, suppressS, severity, channel, webhookUrl, enabled ? 1 : 0, id);
    }

    // ── 消费游标 ─────────────────────────────────────────────────────────

    public ConsumerState cursor() {
        return jdbc.queryForObject(
                "SELECT last_event_id, updated_at, skipped_total FROM alert_consumer_cursor WHERE id = 1",
                (rs, i) -> new ConsumerState(rs.getLong(1), rs.getLong(2), rs.getInt(3)));
    }

    public void advanceCursor(long lastEventId, int skippedDelta) {
        jdbc.update("UPDATE alert_consumer_cursor SET last_event_id = ?, updated_at = ?, "
                + "skipped_total = skipped_total + ? WHERE id = 1", lastEventId, System.currentTimeMillis(), skippedDelta);
    }

    /** 一批待消费的事件（只取告警关心的列）。 */
    public List<Map<String, Object>> eventsAfter(long lastId, int limit) {
        return jdbc.queryForList(
                "SELECT id, event_time_ms, client_ip, category_display, reason FROM waf_events "
                        + "WHERE id > ? ORDER BY id LIMIT ?", lastId, limit);
    }

    // ── 按监控项计数 ─────────────────────────────────────────────────────

    /**
     * 监控项对应的 WHERE 片段。
     *
     * 这里拼的只有列名和运算符，所有用户输入（IP / 关键词 / 状态码）都走占位符，
     * 不存在拼接注入。
     */
    private static String metricWhere(Rule r) {
        return switch (r.metric() == null ? "category" : r.metric()) {
            case "ip" -> "client_ip = ?";
            case "uri" -> "uri LIKE ?";
            case "rule" -> "rule_name LIKE ?";
            case "status" -> "status = ?";
            default -> "client_ip = ? AND category_display = ?";
        };
    }

    private static Object[] metricArgs(Rule r, String ip, String cat) {
        return switch (r.metric() == null ? "category" : r.metric()) {
            case "ip" -> new Object[]{ip};
            case "uri", "rule" -> new Object[]{"%" + r.matchValue() + "%"};
            case "status" -> new Object[]{Integer.parseInt(r.matchValue().trim())};
            default -> new Object[]{ip, cat};
        };
    }

    /** 当前固定桶内、到事件时刻为止的累计事件数。 */
    public int countInBucket(Rule rule, String ip, String category, long bucketStart, long upToMs) {
        List<Object> args = new ArrayList<>(List.of(metricArgs(rule, ip, category)));
        args.add(bucketStart);
        args.add(upToMs);
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM waf_events WHERE " + metricWhere(rule)
                        + " AND event_time_ms >= ? AND event_time_ms <= ?",
                Integer.class, args.toArray());
        return n == null ? 0 : n;
    }

    /** 桶内到此刻为止的事件 id（首次触发时要把它们全部补进关联表）。 */
    public List<Long> eventIdsInBucket(Rule rule, String ip, String category, long bucketStart, long upToMs) {
        List<Object> args = new ArrayList<>(List.of(metricArgs(rule, ip, category)));
        args.add(bucketStart);
        args.add(upToMs);
        return jdbc.queryForList(
                "SELECT id FROM waf_events WHERE " + metricWhere(rule)
                        + " AND event_time_ms >= ? AND event_time_ms <= ? ORDER BY id",
                Long.class, args.toArray());
    }

    /**
     * 过去 lookbackMs 内、同维度每窗口事件数的均值（突增检测的基线）。
     *
     * 只统计窗口大小与规则一致的桶，空桶不计入——否则流量稀疏时段均值被
     * 稀释到接进 0，任何两条事件都能判成「突增 100 倍」。
     *
     * 维度口径与计数一致：category 规则按类别看全站历史，ip 规则只看这个 IP 自己。
     *
     * @return 均值；没有任何历史桶时返回 0（调用方据此跳过突增判定，冷启动保护）
     */
    public double baselineAvg(Rule rule, String ip, String category, long windowMs, long lookbackMs, long nowMs) {
        List<Object> args = new ArrayList<>();
        args.add(windowMs);                     // FLOOR(event_time_ms / ?) 出现在 SELECT 里，排最前
        switch (rule.metric() == null ? "category" : rule.metric()) {
            case "ip" -> args.add(ip);
            case "uri", "rule" -> args.add("%" + rule.matchValue() + "%");
            case "status" -> args.add(Integer.parseInt(rule.matchValue().trim()));
            default -> args.add(category);
        }
        args.add(nowMs - lookbackMs);
        args.add(nowMs);
        Double avg = jdbc.queryForObject(
                "SELECT AVG(c) FROM (SELECT FLOOR(event_time_ms / ?) AS b, COUNT(*) AS c FROM waf_events WHERE "
                        + baselineWhere(rule) + " AND event_time_ms >= ? AND event_time_ms < ? GROUP BY b) t",
                Double.class, args.toArray());
        return avg == null ? 0.0 : avg;
    }

    /** 基线统计用的 WHERE 片段：与 {@link #metricWhere} 一致，只是 category 维度按类别看全站。 */
    private static String baselineWhere(Rule r) {
        return switch (r.metric() == null ? "category" : r.metric()) {
            case "ip" -> "client_ip = ?";
            case "uri" -> "uri LIKE ?";
            case "rule" -> "rule_name LIKE ?";
            case "status" -> "status = ?";
            default -> "category_display = ?";
        };
    }

    // ── 告警实例 ─────────────────────────────────────────────────────────

    /** 抑制期内的活跃告警（同一规则 + IP + 分类），没有则 null。 */
    public Long findActive(long ruleId, String ip, String category, long nowMs) {
        List<Long> ids = jdbc.queryForList(
                "SELECT id FROM alerts WHERE rule_id = ? AND client_ip = ? AND category = ? "
                        + "AND suppressed_until_ms > ? ORDER BY id DESC LIMIT 1",
                Long.class, ruleId, ip, category, nowMs);
        return ids.isEmpty() ? null : ids.get(0);
    }

    public long createAlert(long ruleId, String ip, String category, String metric, long bucketStart,
                            long firstTriggerMs, long suppressedUntilMs, String severity, double burstRatio) {
        jdbc.update("INSERT INTO alerts (rule_id, client_ip, category, metric, bucket_start, first_trigger_ms, "
                        + "last_trigger_ms, trigger_count, event_count, suppressed_until_ms, handled, delivery_count, "
                        + "severity, burst_ratio, created_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 0, 0, ?, ?, ?)",
                ruleId, ip, category, metric, bucketStart, firstTriggerMs, firstTriggerMs, suppressedUntilMs,
                severity, burstRatio, System.currentTimeMillis());
        return jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
    }

    /** 关联事件，返回是否真的新增（去重靠主键）。 */
    public boolean linkEvent(long alertId, long eventId) {
        int n = jdbc.update("INSERT IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", alertId, eventId);
        if (n > 0) {
            jdbc.update("UPDATE alerts SET event_count = event_count + 1 WHERE id = ?", alertId);
        }
        return n > 0;
    }

    /** 一次候选触发：trigger_count +1，刷新最后触发时间；级别只升不降。 */
    public void bumpTrigger(long alertId, long triggerMs, String severity) {
        jdbc.update("UPDATE alerts SET trigger_count = trigger_count + 1, last_trigger_ms = ?, "
                + "severity = IF(severity = 'red' OR ? = 'red', 'red', severity) WHERE id = ?",
                triggerMs, severity, alertId);
    }

    public void bumpDeliveryCount(long alertId) {
        jdbc.update("UPDATE alerts SET delivery_count = delivery_count + 1 WHERE id = ?", alertId);
    }

    public void setHandled(long alertId, boolean handled) {
        jdbc.update("UPDATE alerts SET handled = ? WHERE id = ?", handled ? 1 : 0, alertId);
    }

    // ── 列表与详情 ───────────────────────────────────────────────────────

    private static final String ALERT_SELECT =
            "SELECT a.id, r.name, a.client_ip, a.category, a.metric, a.bucket_start, a.first_trigger_ms, "
                    + "a.last_trigger_ms, a.suppressed_until_ms, a.trigger_count, a.event_count, a.delivery_count, "
                    + "a.severity, a.burst_ratio, a.handled, "
                    + "(SELECT d.status FROM alert_deliveries d WHERE d.alert_id = a.id ORDER BY d.id DESC LIMIT 1) "
                    + "FROM alerts a JOIN alert_rules r ON r.id = a.rule_id ";

    private static Alert mapAlert(java.sql.ResultSet rs, int i, long now) throws java.sql.SQLException {
        return new Alert(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getLong(9), rs.getInt(10), rs.getInt(11),
                rs.getInt(12), rs.getString(13), rs.getDouble(14), rs.getLong(9) > now,
                rs.getInt(15) == 1, rs.getString(16));
    }

    public List<Alert> list(Long fromMs, Long toMs, Boolean handled, int limit) {
        StringBuilder sql = new StringBuilder(ALERT_SELECT).append("WHERE 1 = 1");
        List<Object> args = new ArrayList<>();
        if (fromMs != null) {
            sql.append(" AND a.first_trigger_ms >= ?");
            args.add(fromMs);
        }
        if (toMs != null) {
            sql.append(" AND a.first_trigger_ms < ?");
            args.add(toMs);
        }
        if (handled != null) {
            sql.append(" AND a.handled = ?");
            args.add(handled ? 1 : 0);
        }
        sql.append(" ORDER BY a.first_trigger_ms DESC, a.id DESC LIMIT ?");
        args.add(limit);

        long now = System.currentTimeMillis();
        return jdbc.query(sql.toString(), (rs, i) -> mapAlert(rs, i, now), args.toArray());
    }

    public AlertDetail detail(long id) {
        long now = System.currentTimeMillis();
        List<Alert> one = jdbc.query(ALERT_SELECT + "WHERE a.id = ?", (rs, i) -> mapAlert(rs, i, now), id);
        if (one.isEmpty()) {
            return null;
        }
        List<Long> eventIds = jdbc.queryForList(
                "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id", Long.class, id);
        List<Delivery> ds = jdbc.query(
                "SELECT id, url, status, http_code, attempts, last_error, updated_at FROM alert_deliveries "
                        + "WHERE alert_id = ? ORDER BY id", (rs, i) -> new Delivery(
                        rs.getLong(1), rs.getString(2), rs.getString(3),
                        (Integer) rs.getObject(4), rs.getInt(5), rs.getString(6), rs.getLong(7)), id);
        List<EventBrief> events = eventIds.isEmpty() ? List.of() : jdbc.query(
                "SELECT e.id, e.event_time_ms, e.uri, e.rule_name FROM waf_events e "
                        + "JOIN alert_events l ON l.event_id = e.id WHERE l.alert_id = ? ORDER BY e.id",
                (rs, i) -> new EventBrief(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4)), id);
        return new AlertDetail(one.get(0), eventIds, events, ds);
    }

    // ── 投递 ────────────────────────────────────────────────────────────

    /** 某条告警所属的规则（人工重试时要用它的 webhook 地址）。 */
    public Rule ruleOf(long alertId) {
        List<Rule> rs = jdbc.query(
                "SELECT " + RULE_COLS.replace("id,", "r.id,").replace("name,", "r.name,")
                        + " FROM alert_rules r JOIN alerts a ON a.rule_id = r.id WHERE a.id = ?",
                AlertRepository::mapRule, alertId);
        return rs.isEmpty() ? null : rs.get(0);
    }

    public long createDelivery(long alertId, String url) {
        jdbc.update("INSERT INTO alert_deliveries (alert_id, url, status, attempts, created_at, updated_at) "
                + "VALUES (?, ?, 'pending', 0, ?, ?)", alertId, url, System.currentTimeMillis(), System.currentTimeMillis());
        return jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
    }

    public void updateDelivery(long deliveryId, String status, Integer httpCode, String error, long nextRetryMs) {
        jdbc.update("UPDATE alert_deliveries SET status = ?, http_code = ?, last_error = ?, attempts = attempts + 1, "
                        + "next_retry_ms = ?, updated_at = ? WHERE id = ?",
                status, httpCode, error, nextRetryMs, System.currentTimeMillis(), deliveryId);
    }

    /** 到期待重试的投递（失败且 next_retry_ms 已到）。 */
    public List<Map<String, Object>> dueRetries(int limit) {
        return jdbc.queryForList(
                "SELECT id, alert_id, url FROM alert_deliveries "
                        + "WHERE status IN ('failed', 'unknown') AND next_retry_ms IS NOT NULL "
                        + "AND next_retry_ms <= ? ORDER BY id LIMIT ?", System.currentTimeMillis(), limit);
    }
}
