package com.litewaf.platform.export;

import com.litewaf.platform.events.EventDtos.EventItem;
import com.litewaf.platform.events.EventsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

/**
 * 事件导出（需求卡片 R36-01）。
 *
 * <p>三个硬约束：
 * <ol>
 *   <li><b>上限 1 万行</b>：超过直接 400 让人缩小范围，不静默截断——
 *       静默截断最坑，用户以为导全了，其实少了后半个时间窗；</li>
 *   <li><b>CSV 公式注入</b>：以 {@code = + - @} 开头的格子前面加一个单引号，
 *       否则 Excel 会把 {@code =cmd|...} 当公式执行；</li>
 *   <li><b>脱敏</b>：只导 waf_events 已有的字段，不含请求体、Cookie、Authorization——
 *       这些本来就没入库，导出自然带不出来。</li>
 * </ol>
 *
 * <p>导出流式写响应，10 万行量级也不会把堆撑爆（分批 query 在 EventsService 里）。
 */
@RestController
public class ExportController {

    /** 单次导出上限：卡片 R36-01 定的 10000 行。 */
    private static final int MAX_ROWS = 10_000;

    private static final String[] HEADERS = {
            "id", "event_time", "client_ip", "method", "uri", "status",
            "reason", "rule_id", "rule_name", "category", "category_display",
            "action", "cost_us", "score"
    };

    private final EventsService events;

    public ExportController(EventsService events) {
        this.events = events;
    }

    @GetMapping("/api/export")
    public void export(@RequestParam(defaultValue = "csv") String format,
                       @RequestParam(required = false) Long from,
                       @RequestParam(required = false) Long to,
                       @RequestParam(required = false) String ip,
                       @RequestParam(required = false) String category,
                       @RequestParam(required = false) String uri,
                       HttpServletResponse res) throws IOException {

        if (from != null && to != null && from >= to) {
            throw new IllegalArgumentException("窗口起点必须小于终点（闭开区间 [from, to)）");
        }
        boolean csv = !"jsonl".equalsIgnoreCase(format);
        String fmt = csv ? "csv" : "jsonl";

        // 先数一遍再决定要不要干——比导到一半再报错友好
        long total = events.count(from, to, ip, category, uri);
        if (total > MAX_ROWS) {
            throw new IllegalArgumentException(
                    "本次筛选命中 " + total + " 行，超过单次导出上限 " + MAX_ROWS + " 行；请缩小时间范围或加过滤条件");
        }

        List<EventItem> rows = events.exportRows(from, to, ip, category, uri, MAX_ROWS);

        res.setCharacterEncoding(StandardCharsets.UTF_8.name());
        res.setContentType(csv ? "text/csv; charset=UTF-8" : "application/x-ndjson; charset=UTF-8");
        res.setHeader("Content-Disposition", "attachment; filename=\"waf-events-"
                + Instant.now().toEpochMilli() + "." + fmt + "\"");

        PrintWriter out = res.getWriter();
        if (csv) {
            // UTF-8 BOM：不加的话 Excel 打开中文是乱码，这是现实妥协
            out.write('\ufeff');
            out.println(String.join(",", HEADERS));
            for (EventItem e : rows) {
                out.println(String.join(",",
                        String.valueOf(e.id()),
                        csvCell(e.event_time()),
                        csvCell(e.client_ip()),
                        csvCell(e.method()),
                        csvCell(e.uri()),
                        String.valueOf(e.status()),
                        csvCell(e.reason()),
                        String.valueOf(e.rule_id()),
                        csvCell(e.rule_name()),
                        csvCell(e.category()),
                        csvCell(e.category_display()),
                        csvCell(e.action()),
                        String.valueOf(e.cost_us()),
                        String.valueOf(e.score())));
            }
        } else {
            for (EventItem e : rows) {
                out.println(toJson(e));
            }
        }
        out.flush();
    }

    /**
     * CSV 单元格转义：先防公式注入，再按 RFC4180 加引号。
     * 顺序不能反——先加引号的话 {@code "'=1+1"} 就不以 = 开头了，公式反而安全，
     * 但 {@code =1+1} 会被原样保留在引号里，Excel 依旧执行。所以先补单引号再包引号。
     */
    static String csvCell(String raw) {
        if (raw == null) {
            return "";
        }
        String v = raw;
        if (!v.isEmpty() && "=+-@".indexOf(v.charAt(0)) >= 0) {
            v = "'" + v;
        }
        if (v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r")) {
            return "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }

    /** 手写而不是用 Jackson：字段顺序固定、不含嵌套，省一次对象构建。 */
    static String toJson(EventItem e) {
        return new StringBuilder(256)
                .append("{\"id\":").append(e.id())
                .append(",\"event_time\":").append(quote(e.event_time()))
                .append(",\"client_ip\":").append(quote(e.client_ip()))
                .append(",\"method\":").append(quote(e.method()))
                .append(",\"uri\":").append(quote(e.uri()))
                .append(",\"status\":").append(e.status())
                .append(",\"reason\":").append(quote(e.reason()))
                .append(",\"rule_id\":").append(e.rule_id())
                .append(",\"rule_name\":").append(quote(e.rule_name()))
                .append(",\"category\":").append(quote(e.category()))
                .append(",\"category_display\":").append(quote(e.category_display()))
                .append(",\"action\":").append(quote(e.action()))
                .append(",\"cost_us\":").append(e.cost_us())
                .append(",\"score\":").append(e.score())
                .append("}")
                .toString();
    }

    private static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
