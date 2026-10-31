package com.litewaf.platform.fp;

import com.litewaf.platform.fp.FpDtos.Mark;
import com.litewaf.platform.fp.FpDtos.MarkItem;
import com.litewaf.platform.fp.FpDtos.MarkPage;
import com.litewaf.platform.fp.FpDtos.Metrics;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

/**
 * 误报标记的读写（R34-10）。
 *
 * <p>一张表 {@code false_positive_marks}：event_id 主键就是"一个事件一个标记"的唯一约束。
 * 重复标记同一事件时走覆盖（改判定），不新建行——这满足了卡片里"重复提交返回同标记"的要求，
 * 也避免了同一个人手滑点两次留下两条互相矛盾的记录。
 */
@Repository
public class FpRepository {

    private static final RowMapper<Mark> MARK_MAPPER = (rs, i) -> new Mark(
            rs.getLong("event_id"),
            rs.getString("decision"),
            rs.getString("operator"),
            rs.getString("remark"),
            rs.getLong("created_at_ms"),
            rs.getLong("updated_at_ms"));

    private static final RowMapper<MarkItem> ITEM_MAPPER = (rs, i) -> new MarkItem(
            rs.getLong("event_id"),
            rs.getLong("event_time_ms"),
            rs.getString("client_ip"),
            rs.getString("uri"),
            rs.getString("category_display"),
            rs.getString("rule_name"),
            rs.getString("decision"),
            rs.getString("operator"),
            rs.getString("remark"),
            rs.getLong("updated_at_ms"));

    private final JdbcTemplate jdbc;

    public FpRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Mark byEvent(long eventId) {
        List<Mark> rows = jdbc.query(
                "SELECT event_id, decision, operator, remark, created_at_ms, updated_at_ms "
                        + "FROM false_positive_marks WHERE event_id = ?", MARK_MAPPER, eventId);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** 事件是否存在（标记前必须确认，否则会写出一条指向不存在事件的记录）。 */
    public boolean eventExists(long eventId) {
        Integer n = jdbc.queryForObject("SELECT COUNT(*) FROM waf_events WHERE id = ?", Integer.class, eventId);
        return n != null && n > 0;
    }

    /**
     * 插入或覆盖标记。created_at_ms 首次写入后不再变动，updated_at_ms 每次刷新。
     */
    public Mark upsert(long eventId, String decision, String operator, String remark) {
        long now = Instant.now().toEpochMilli();
        jdbc.update("INSERT INTO false_positive_marks "
                        + "(event_id, decision, operator, remark, created_at_ms, updated_at_ms) "
                        + "VALUES (?,?,?,?,?,?) "
                        + "ON DUPLICATE KEY UPDATE decision=VALUES(decision), "
                        + "operator=VALUES(operator), remark=VALUES(remark), updated_at_ms=VALUES(updated_at_ms)",
                eventId, decision, operator, remark, now, now);
        return byEvent(eventId);
    }

    public void clear(long eventId) {
        jdbc.update("DELETE FROM false_positive_marks WHERE event_id = ?", eventId);
    }

    /**
     * 三个指标一次查完：先按窗口统计全部拦截数，再按"该事件是否被标记"分桶。
     * 用左连接而不是查三次，10 万行量级下差别不大，但少两次往返。
     */
    public Metrics metrics(Long from, Long to) {
        StringBuilder sql = new StringBuilder(
                "SELECT COUNT(*) AS total, "
                        + "SUM(CASE WHEN m.decision = 'confirmed' THEN 1 ELSE 0 END) AS confirmed, "
                        + "SUM(CASE WHEN m.decision = 'rejected' THEN 1 ELSE 0 END) AS rejected "
                        + "FROM waf_events e LEFT JOIN false_positive_marks m ON m.event_id = e.id WHERE 1=1 ");
        List<Object> args = new java.util.ArrayList<>();
        if (from != null) {
            sql.append("AND e.event_time_ms >= ? ");
            args.add(from);
        }
        if (to != null) {
            sql.append("AND e.event_time_ms < ? ");
            args.add(to);
        }
        // 注意：必须是带 args 的重载 query(sql, Object[], ResultSetExtractor)。
        // 只传 (sql, extractor) 的那个重载不会绑定 ?，驱动直接把字面量 "?" 发给数据库，
        // 报 "You have an error in your SQL syntax ... near '?'"。
        return jdbc.query(sql.toString(), args.toArray(), rs -> {
            long total = 0;
            long confirmed = 0;
            long rejected = 0;
            if (rs.next()) {
                total = rs.getLong("total");
                confirmed = rs.getLong("confirmed");
                rejected = rs.getLong("rejected");
            }
            long unreviewed = total - confirmed - rejected;
            double cRatio = total == 0 ? 0d : (double) confirmed / total;
            double covRatio = total == 0 ? 0d : (double) (confirmed + rejected) / total;
            double fpRatio = (confirmed + rejected) == 0 ? 0d : (double) confirmed / (confirmed + rejected);
            long f = from == null ? 0 : from;
            long t = to == null ? Long.MAX_VALUE : to;
            return new Metrics(f, t, total, confirmed, rejected, unreviewed,
                    round4(cRatio), round4(covRatio), round4(fpRatio));
        });
    }

    public MarkPage list(Long from, Long to, String decision, int page, int size) {
        StringBuilder where = new StringBuilder("WHERE 1=1 ");
        List<Object> args = new java.util.ArrayList<>();
        if (from != null) {
            where.append("AND e.event_time_ms >= ? ");
            args.add(from);
        }
        if (to != null) {
            where.append("AND e.event_time_ms < ? ");
            args.add(to);
        }
        if (decision != null && !decision.isBlank()) {
            where.append("AND m.decision = ? ");
            args.add(decision);
        }

        Long total = jdbc.queryForObject(
                "SELECT COUNT(*) FROM false_positive_marks m JOIN waf_events e ON e.id = m.event_id "
                        + where, Long.class, args.toArray());

        List<Object> pageArgs = new java.util.ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<MarkItem> items = jdbc.query(
                "SELECT m.event_id, e.event_time_ms, e.client_ip, e.uri, e.category_display, "
                        + "e.rule_name, m.decision, m.operator, m.remark, m.updated_at_ms "
                        + "FROM false_positive_marks m JOIN waf_events e ON e.id = m.event_id "
                        + where + "ORDER BY m.updated_at_ms DESC LIMIT ? OFFSET ?",
                ITEM_MAPPER, pageArgs.toArray());

        return new MarkPage(items, total == null ? 0 : total, page, size);
    }

    private static double round4(double v) {
        return Math.round(v * 10000d) / 10000d;
    }
}
