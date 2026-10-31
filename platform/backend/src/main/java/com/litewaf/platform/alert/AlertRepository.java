package com.litewaf.platform.alert;

import com.litewaf.platform.alert.AlertDtos.Alert;
import com.litewaf.platform.alert.AlertDtos.AlertDetail;
import com.litewaf.platform.alert.AlertDtos.EventBrief;
import com.litewaf.platform.alert.AlertDtos.ConsumerState;
import com.litewaf.platform.alert.AlertDtos.Delivery;
import com.litewaf.platform.alert.AlertDtos.Rule;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

/**
 * 告警模块的数据访问层。
 *
 * 全部用显式 SQL：告警语义（固定桶、抑制、去重）很难用 ORM 表达清楚，
 * 写出来反而更容易对照需求卡片逐条核验。
 */
@Repository
public class AlertRepository {

    private final JdbcTemplate jdbc;

    public AlertRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ── 规则 ────────────────────────────────────────────────────────────

    public List<Rule> rules() {
        return jdbc.query("SELECT id, name, category, threshold, window_s, suppress_s, webhook_url, enabled "
                        + "FROM alert_rules ORDER BY id",
                (rs, i) -> new Rule(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getInt(4),
                        rs.getInt(5), rs.getInt(6), rs.getString(7), rs.getInt(8) == 1));
    }

    public void updateRule(int id, int threshold, int windowS, int suppressS, String webhookUrl, boolean enabled) {
        jdbc.update("UPDATE alert_rules SET threshold = ?, window_s = ?, suppress_s = ?, webhook_url = ?, enabled = ? "
                + "WHERE id = ?", threshold, windowS, suppressS, webhookUrl, enabled ? 1 : 0, id);
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

    // ── 固定时间桶计数 ───────────────────────────────────────────────────

    /**
     * 统计某个 IP 在某个固定桶内、到事件时刻为止的累计事件数。
     *
     * 桶边界 = floor(event_time / window) * window，与卡片 R35-02 一致。
     * 上界用「本条事件的时间」而不是「桶结束时间」：判定"第 N 个事件触发"必须看
     * 截至这一刻攒了多少，否则批量补数时会把同一批的后续事件也算进前面的候选里，
     * trigger_count 会被放大。
     */
    public int countInBucket(String ip, String category, long bucketStart, long upToMs) {
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM waf_events WHERE client_ip = ? AND category_display = ? "
                        + "AND event_time_ms >= ? AND event_time_ms <= ?",
                Integer.class, ip, category, bucketStart, upToMs);
        return n == null ? 0 : n;
    }

    /** 桶内到此刻为止的事件 id（首次触发时要把它们全部补进关联表）。 */
    public List<Long> eventIdsInBucket(String ip, String category, long bucketStart, long upToMs) {
        return jdbc.queryForList(
                "SELECT id FROM waf_events WHERE client_ip = ? AND category_display = ? "
                        + "AND event_time_ms >= ? AND event_time_ms <= ? ORDER BY id",
                Long.class, ip, category, bucketStart, upToMs);
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

    public long createAlert(long ruleId, String ip, String category, long bucketStart,
                            long firstTriggerMs, long suppressedUntilMs) {
        jdbc.update("INSERT INTO alerts (rule_id, client_ip, category, bucket_start, first_trigger_ms, "
                        + "last_trigger_ms, trigger_count, event_count, suppressed_until_ms, handled, delivery_count, created_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, 0, 0, ?)",
                ruleId, ip, category, bucketStart, firstTriggerMs, firstTriggerMs, suppressedUntilMs,
                System.currentTimeMillis());
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

    /** 一次候选触发：trigger_count +1，刷新最后触发时间。 */
    public void bumpTrigger(long alertId, long triggerMs) {
        jdbc.update("UPDATE alerts SET trigger_count = trigger_count + 1, last_trigger_ms = ? WHERE id = ?",
                triggerMs, alertId);
    }

    public void bumpDeliveryCount(long alertId) {
        jdbc.update("UPDATE alerts SET delivery_count = delivery_count + 1 WHERE id = ?", alertId);
    }

    public void setHandled(long alertId, boolean handled) {
        jdbc.update("UPDATE alerts SET handled = ? WHERE id = ?", handled ? 1 : 0, alertId);
    }

    // ── 列表与详情 ───────────────────────────────────────────────────────

    public List<Alert> list(Long fromMs, Long toMs, Boolean handled, int limit) {
        StringBuilder sql = new StringBuilder(
                "SELECT a.id, r.name, a.client_ip, a.category, a.bucket_start, a.first_trigger_ms, a.last_trigger_ms, a.suppressed_until_ms, "
                        + "a.trigger_count, a.event_count, a.delivery_count, a.suppressed_until_ms, a.handled, "
                        + "(SELECT d.status FROM alert_deliveries d WHERE d.alert_id = a.id ORDER BY d.id DESC LIMIT 1) "
                        + "FROM alerts a JOIN alert_rules r ON r.id = a.rule_id WHERE 1 = 1");
        List<Object> args = new java.util.ArrayList<>();
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
        return jdbc.query(sql.toString(), (rs, i) -> new Alert(
                rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5),
                rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getInt(9), rs.getInt(10), rs.getInt(11),
                rs.getLong(12) > now, rs.getInt(13) == 1, rs.getString(14)), args.toArray());
    }

    public AlertDetail detail(long id) {
        List<Alert> one = jdbc.query(
                "SELECT a.id, r.name, a.client_ip, a.category, a.bucket_start, a.first_trigger_ms, a.last_trigger_ms, a.suppressed_until_ms, "
                        + "a.trigger_count, a.event_count, a.delivery_count, a.suppressed_until_ms, a.handled, "
                        + "(SELECT d.status FROM alert_deliveries d WHERE d.alert_id = a.id ORDER BY d.id DESC LIMIT 1) "
                        + "FROM alerts a JOIN alert_rules r ON r.id = a.rule_id WHERE a.id = ?",
                (rs, i) -> new Alert(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5),
                        rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getInt(9), rs.getInt(10), rs.getInt(11),
                        rs.getLong(12) > System.currentTimeMillis(), rs.getInt(13) == 1, rs.getString(14)), id);
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
                "SELECT r.id, r.name, r.category, r.threshold, r.window_s, r.suppress_s, r.webhook_url, r.enabled "
                        + "FROM alert_rules r JOIN alerts a ON a.rule_id = r.id WHERE a.id = ?",
                (r, i) -> new Rule(r.getInt(1), r.getString(2), r.getString(3), r.getInt(4),
                        r.getInt(5), r.getInt(6), r.getString(7), r.getInt(8) == 1), alertId);
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
