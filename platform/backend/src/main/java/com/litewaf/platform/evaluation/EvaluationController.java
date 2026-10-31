package com.litewaf.platform.evaluation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 带标签样本的评估报告（R34-11 的展示侧）。
 *
 * <p>数据来源是 s8_eval.py 跑完落在磁盘上的 {@code <run_id>/report.json}：
 * 平台不重算评估结果，只负责把「那一跑」的原始报告读出来给人看。
 * 这样做的好处是结果可追溯——每条报告都有 samples_sha256，样本集变了能对出来；
 * 坏处是平台不能自己发起评估（要发起就跑脚本），P0 阶段这点可以接受。
 *
 * <p>路径来自配置 {@code app.evaluation.dir}，默认 /opt/litewaf/evaluations。
 */
@RestController
@RequestMapping("/api/evaluations")
public class EvaluationController {

    /** run_id 的格式是 yyyyMMdd-HHmmss，只认这个形状，别的一律当非法路径。 */
    private static final Pattern RUN_ID = Pattern.compile("^\\d{8}-\\d{6}$");

    private final Path root;
    private final ObjectMapper om = new ObjectMapper();

    public EvaluationController(
            @Value("${app.evaluation.dir:/opt/litewaf/evaluations}") String dir) {
        this.root = Paths.get(dir);
    }

    /** 最近的评估跑次摘要，按时间倒序；没有报告时返回空数组而不是 404。 */
    @GetMapping
    public List<Map<String, Object>> list() throws IOException {
        if (!Files.isDirectory(root)) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        try (Stream<Path> runs = Files.list(root)) {
            List<Path> dirs = runs.filter(Files::isDirectory)
                    .sorted(Comparator.comparing(Path::getFileName).reversed())
                    .toList();
            for (Path dir : dirs) {
                Path f = dir.resolve("report.json");
                if (!Files.isRegularFile(f)) {
                    continue;
                }
                JsonNode r = read(f);
                JsonNode conf = r.path("confusion");
                JsonNode m = r.path("metrics");
                JsonNode cat = r.path("by_category");
                // 用 LinkedHashMap 保字段顺序：前端表格按这个顺序渲染，读起来顺
                Map<String, Object> item = new java.util.LinkedHashMap<>();
                item.put("run_id", dir.getFileName().toString());
                item.put("run_at", r.path("run_at").asText(""));
                item.put("target", r.path("target").asText(""));
                item.put("tp", conf.path("tp").asInt(0));
                item.put("fn", conf.path("fn").asInt(0));
                item.put("fp", conf.path("fp").asInt(0));
                item.put("tn", conf.path("tn").asInt(0));
                item.put("error", conf.path("error").asInt(0));
                item.put("fnr", m.path("fnr").asDouble(0));
                item.put("fpr", m.path("fpr").asDouble(0));
                item.put("accuracy", m.path("accuracy").asDouble(0));
                item.put("sqli_tp", cat.path("SQLi").path("tp").asInt(0));
                item.put("sqli_fn", cat.path("SQLi").path("fn").asInt(0));
                item.put("xss_tp", cat.path("XSS").path("tp").asInt(0));
                item.put("xss_fn", cat.path("XSS").path("fn").asInt(0));
                item.put("cc_first_block", r.path("cc").path("first_block_at").asInt(-1));
                item.put("samples_sha256", r.path("samples_sha256").asText(""));
                out.add(item);
            }
        }
        return out;
    }

    /** 单次跑次的完整报告（原样返回脚本写的那份 JSON）。 */
    @GetMapping("/{runId}")
    public JsonNode detail(@PathVariable String runId) throws IOException {
        if (!RUN_ID.matcher(runId).matches()) {
            throw new IllegalArgumentException("run_id 不合法");
        }
        Path f = root.resolve(runId).resolve("report.json");
        // resolve 之后再确认一遍父目录没被 ../ 带到别处，防符号链接与穿越
        if (!f.normalize().startsWith(root.normalize()) || !Files.isRegularFile(f)) {
            throw new EvaluationNotFoundException("找不到这次评估：" + runId);
        }
        return read(f);
    }

    private JsonNode read(Path f) throws IOException {
        try (var in = Files.newInputStream(f)) {
            return om.readTree(in);
        }
    }
}
