package com.litewaf.platform.events;

import com.litewaf.platform.events.EventDtos.EventItem;
import com.litewaf.platform.events.EventDtos.PageResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 事件检索。
 *
 * <p>所有过滤条件都走预编译参数（{@code ?}），不拼字符串——URI 里可能带引号、分号、
 * 甚至 SQL 片段，拼进去就是注入。排序字段用白名单映射，因为列名没法参数化。
 */
@Service
public class EventsService {

    /** 排序白名单：前端传 time/ip/cost，其他值直接忽略（回到默认按时间倒序） */
    private static final Set<String> SORTABLE = Set.of("time", "ip", "cost");

    private static final String COLUMNS =
            "id, event_time_ms, client_ip, method, uri, status, reason, rule_id, rule_name, "
                    + "zone, category, category_display, score, total_score, action, cost_us";

    private final JdbcTemplate jdbc;

    public EventsService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * 分页检索。
     *
     * @param fromMs   窗口起点（含），null 表示不限
     * @param toMs     窗口终点（不含），null 表示不限
     * @param ip       精确匹配来源 IP，可空
     * @param category 按展示分类过滤（SQLi/XSS/CC/SCAN/...），可空
     * @param uriLike  URI 模糊匹配（% 由调用方决定是否加），可空
     * @param page     1 起的页码
     * @param pageSize 每页条数（1–200）
     * @param sortby   time / ip / cost
     * @param order    asc / desc
     */
    public PageResult<EventItem> search(Long fromMs, Long toMs, String ip, String category,
                                        String uriLike, int page, int pageSize,
                                        String sortby, String order) {
        Condition cond = buildWhere(fromMs, toMs, ip, category, uriLike);

        long totalRows = countRows(cond);

        String orderBy = orderByClause(sortby, order);
        List<Object> pageArgs = new ArrayList<>(cond.args());
        pageArgs.add(pageSize);
        pageArgs.add((long) (page - 1) * pageSize);

        List<EventItem> items = jdbc.query(
                "SELECT " + COLUMNS + " FROM waf_events" + cond.where() + orderBy + " LIMIT ? OFFSET ?",
                mapper(), pageArgs.toArray());

        return new PageResult<>(items, totalRows, page, pageSize, System.currentTimeMillis());
    }

    /** 只数行数：导出前先判断会不会超上限（R36-01 的 1 万行硬约束）。 */
    public long count(Long fromMs, Long toMs, String ip, String category, String uriLike) {
        return countRows(buildWhere(fromMs, toMs, ip, category, uriLike));
    }

    /**
     * 导出用：同样的筛选条件，但不分页、按时间正序。
     *
     * <p>条数上限由调用方给（卡片定 1 万行）。这里用 LIMIT 兜底，
     * 万一并发插入了新事件让 count 和实际行数不一致，也不会把响应撑爆。
     */
    public List<EventItem> exportRows(Long fromMs, Long toMs, String ip, String category,
                                      String uriLike, int limit) {
        Condition cond = buildWhere(fromMs, toMs, ip, category, uriLike);
        List<Object> args = new ArrayList<>(cond.args());
        args.add(limit);
        return jdbc.query(
                "SELECT " + COLUMNS + " FROM waf_events" + cond.where()
                        + " ORDER BY event_time_ms ASC, id ASC LIMIT ?",
                mapper(), args.toArray());
    }

    /** 详情：找不到时返回 null，由控制器转 404 */
    public EventItem byId(long id) {
        List<EventItem> rows = jdbc.query(
                "SELECT " + COLUMNS + " FROM waf_events WHERE id = ?", mapper(), id);
        return rows.isEmpty() ? null : rows.get(0);
    }

    // ------------------------------------------------------------ 内部

    /** WHERE 子句 + 参数，抽出来给分页和导出复用，避免两处条件写岔。 */
    private record Condition(String where, List<Object> args) {
    }

    private static Condition buildWhere(Long fromMs, Long toMs, String ip, String category, String uriLike) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> args = new ArrayList<>();

        if (fromMs != null) {
            where.append(" AND event_time_ms >= ?");
            args.add(fromMs);
        }
        if (toMs != null) {
            where.append(" AND event_time_ms < ?");
            args.add(toMs);
        }
        if (ip != null && !ip.isBlank()) {
            where.append(" AND client_ip = ?");
            args.add(ip.trim());
        }
        if (category != null && !category.isBlank()) {
            where.append(" AND category_display = ?");
            args.add(category.trim());
        }
        if (uriLike != null && !uriLike.isBlank()) {
            where.append(" AND uri LIKE ?");
            args.add("%" + uriLike.trim() + "%");
        }
        return new Condition(where.toString(), args);
    }

    private long countRows(Condition cond) {
        Long total = jdbc.queryForObject(
                "SELECT COUNT(*) FROM waf_events" + cond.where(), Long.class, cond.args().toArray());
        return (total == null) ? 0L : total;
    }

    private static String orderByClause(String sortby, String order) {
        String col;
        if ("ip".equals(sortby)) {
            col = "client_ip";
        } else if ("cost".equals(sortby)) {
            col = "cost_us";
        } else {
            col = "event_time_ms";
        }
        String dir = "asc".equalsIgnoreCase(order) ? "ASC" : "DESC";
        // id 做次级排序，保证同一毫秒内的记录翻页时不飘
        return " ORDER BY " + col + " " + dir + ", id " + dir;
    }

    private static RowMapper<EventItem> mapper() {
        return (rs, i) -> new EventItem(
                rs.getLong("id"),
                Instant.ofEpochMilli(rs.getLong("event_time_ms")).toString(),
                rs.getString("client_ip"),
                rs.getString("method"),
                rs.getString("uri"),
                rs.getInt("status"),
                rs.getString("reason"),
                rs.getInt("rule_id"),
                blankToDefault(rs.getString("rule_name"), "日志未记录"),
                rs.getString("category"),
                rs.getString("category_display"),
                rs.getString("action"),
                rs.getInt("cost_us"),
                rs.getInt("score"));
    }

    private static String blankToDefault(String v, String fallback) {
        return (v == null || v.isBlank()) ? fallback : v;
    }

    /** 供控制器校验：排序字段非法时回落到默认，不抛异常（前端传错不该 500） */
    public static boolean isSortable(String sortby) {
        return sortby == null || SORTABLE.contains(sortby);
    }
}
