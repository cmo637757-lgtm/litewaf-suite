package com.litewaf.platform.perf;

import com.litewaf.platform.collector.CollectorController;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 性能与数据源状态（R33-06）。
 *
 * <p>答的是三个运维问题：
 * <ol>
 *   <li>平台接口本身慢不慢 —— 拦住看板打不开的锅；</li>
 *   <li>日志文件采到哪儿了、积压多少 —— 页面数字停涨时能马上定位；</li>
 *   <li>库里各表多少行 —— 判断是不是该按保留策略清老数据了。</li>
 * </ol>
 *
 * <p>WAF 侧的 cost_us 与源站 request_time 归 /api/stats/summary，这里不重复算。
 */
@RestController
@RequestMapping("/api/perf")
public class PerfController {

    private final ApiTimingInterceptor timing;
    private final CollectorController collector;
    private final JdbcTemplate jdbc;

    public PerfController(ApiTimingInterceptor timing, CollectorController collector, JdbcTemplate jdbc) {
        this.timing = timing;
        this.collector = collector;
        this.jdbc = jdbc;
    }

    public record SourceFile(String path, boolean exists, long sizeBytes, long modifiedMs) {
    }

    public record TableStat(String name, long rows) {
    }

    public record PerfSummary(
            ApiTimingInterceptor.Snapshot api,
            CollectorController.CollectorStatus collector,
            List<SourceFile> files,
            List<TableStat> tables,
            long nowMs
    ) {
    }

    @GetMapping("/summary")
    public PerfSummary summary() {
        List<SourceFile> files = new ArrayList<>();
        for (String p : new String[]{
                "/opt/litewaf/runtime/logs/access.log",
                "/opt/litewaf/runtime/logs/waf_audit.log",
                "/opt/litewaf/runtime/logs/error.log"}) {
            File f = new File(p);
            files.add(new SourceFile(p, f.isFile(), f.isFile() ? f.length() : 0,
                    f.isFile() ? f.lastModified() : 0));
        }

        List<TableStat> tables = new ArrayList<>();
        for (String t : new String[]{"requests", "waf_events", "ingest_errors", "false_positive_marks"}) {
            Long n = jdbc.queryForObject("SELECT COUNT(*) FROM " + t, Long.class);
            tables.add(new TableStat(t, n == null ? 0 : n));
        }

        return new PerfSummary(timing.snapshot(), collector.status(), files, tables,
                System.currentTimeMillis());
    }
}
