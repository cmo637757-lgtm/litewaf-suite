package com.litewaf.platform.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.litewaf.platform.engine.EngineClient;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 规则与 CC 配置的对外接口（S5 发布闭环）。
 *
 * <p>写路径只有两条：先 {@code /api/rules/check} 拿到 candidate_id，
 * 再 {@code /api/rules/publish} 用这个 id 发布。中间没有任何"直接改文件"的口子。
 *
 * <p>权限由 SecurityConfig 兜底：GET 需要登录（ADMIN/VIEWER 均可），
 * POST 一律 ADMIN，viewer 试发布会被 403 挡掉。
 */
@RestController
public class RulesController {

    private static final Logger log = LoggerFactory.getLogger(RulesController.class);

    private final EngineClient engine;
    private final JdbcTemplate jdbc;

    public RulesController(EngineClient engine, JdbcTemplate jdbc) {
        this.engine = engine;
        this.jdbc = jdbc;
    }

    /** 当前生效的规则文本 + CC 参数。 */
    @GetMapping("/api/rules")
    public RulesDtos.Current current() {
        JsonNode n = engine.currentRules();
        return new RulesDtos.Current(n.path("text").asText(), n.path("hash").asText(),
                toCc(n.path("cc")));
    }

    /** 执行器状态：版本指针、探测结果、nginx 是否活着。 */
    @GetMapping("/api/engine/status")
    public RulesDtos.EngineStatus status() {
        JsonNode n = engine.status();
        List<RulesDtos.VersionItem> versions = new ArrayList<>();
        for (JsonNode v : n.path("versions")) {
            versions.add(new RulesDtos.VersionItem(
                    v.path("version").asText(), v.path("kind").asText(""),
                    v.path("hash").asText(""), v.path("bytes").asInt(0),
                    toCc(v.path("cc")), v.path("created_at").asText(""),
                    v.path("previous").asText("")));
        }
        return new RulesDtos.EngineStatus(
                n.path("current").asText(""), n.path("previous").asText(""),
                toCc(n.path("cc")), n.path("nginx_alive").asBoolean(false),
                n.path("marker").asInt(0), n.path("normal").asInt(0), n.path("sqli").asInt(0),
                versions);
    }

    /** 语法校验。只校验，不动线上。 */
    @PostMapping("/api/rules/check")
    public RulesDtos.CheckResult check(@RequestBody RulesDtos.CheckRequest req,
                                       Authentication auth) {
        String opId = newOperation("check", auth);
        try {
            JsonNode n = engine.check(req.rules(), req.cc(), req.name());
            boolean ok = n.path("ok").asBoolean();
            String err = n.path("error").asText("");
            String lineNo = extractLine(n.path("engine_output").asText(""));
            finishOperation(opId, ok ? "ok" : "rejected",
                    ok ? "语法校验通过" : ("语法校验失败：" + (err.isEmpty() ? lineNo : err)));
            return new RulesDtos.CheckResult(ok,
                    n.hasNonNull("candidate_id") ? n.get("candidate_id").asText() : null,
                    n.path("hash").asText(""), n.path("bytes").asInt(0),
                    toCc(n.path("cc")), n.path("engine_output").asText(""), err, lineNo);
        } catch (RuntimeException e) {
            finishOperation(opId, "error", e.getMessage());
            throw e;
        }
    }

    /** 发布候选版本：原子替换 + reload + 探测，失败自动回退。 */
    @PostMapping("/api/rules/publish")
    public RulesDtos.PublishResult publish(@RequestBody Map<String, String> body,
                                           Authentication auth) {
        String candidateId = body.get("candidate_id");
        if (candidateId == null) {
            candidateId = "";
        }
        String opId = newOperation("publish", auth);
        try {
            JsonNode n = engine.publish(candidateId);
            boolean ok = n.path("ok").asBoolean();
            finishOperation(opId, ok ? "ok" : "failed",
                    ok ? ("发布 " + n.path("version").asText()) : n.path("error").asText("发布失败"));
            return new RulesDtos.PublishResult(ok, n.path("version").asText(""),
                    n.path("previous").asText(""), toCc(n.path("cc")),
                    toMap(n.path("probe")), n.path("reload_output").asText(""),
                    n.path("error").asText(""), opId);
        } catch (RuntimeException e) {
            finishOperation(opId, "error", e.getMessage());
            throw e;
        }
    }

    /** 回退到上一版本（规则 + CC 一起回退）。 */
    @PostMapping("/api/rules/rollback")
    public RulesDtos.PublishResult rollback(Authentication auth) {
        String opId = newOperation("rollback", auth);
        try {
            JsonNode n = engine.rollback();
            boolean ok = n.path("ok").asBoolean();
            finishOperation(opId, ok ? "ok" : "failed",
                    ok ? ("回退到 " + n.path("version").asText()) : n.path("error").asText("回退失败"));
            return new RulesDtos.PublishResult(ok, n.path("version").asText(""),
                    n.path("previous").asText(""), toCc(n.path("cc")),
                    toMap(n.path("probe")), "", n.path("error").asText(""), opId);
        } catch (RuntimeException e) {
            finishOperation(opId, "error", e.getMessage());
            throw e;
        }
    }

    // ---------------------------------------------------------------- 审计

    /**
     * 一个操作记一行：开始写 started，结束更新同一行。
     * 这样即使发布中途进程挂了，也能看到「有一条 started 没等到结果」。
     */
    private String newOperation(String action, Authentication auth) {
        String id = UUID.randomUUID().toString().substring(0, 12);
        String operator = auth != null ? auth.getName() : "anonymous";
        try {
            jdbc.update("INSERT INTO operations (op_id, action, status, operator, started_at_ms) "
                            + "VALUES (?,?,?,?,?)",
                    id, action, "started", operator, Instant.now().toEpochMilli());
        } catch (RuntimeException e) {
            log.warn("写操作审计失败（不影响主流程）：{}", e.getMessage());
        }
        return id;
    }

    private void finishOperation(String opId, String status, String detail) {
        try {
            jdbc.update("UPDATE operations SET status=?, detail=?, finished_at_ms=? WHERE op_id=?",
                    status, truncate(detail, 900), Instant.now().toEpochMilli(), opId);
        } catch (RuntimeException e) {
            log.warn("更新操作审计失败（不影响主流程）：{}", e.getMessage());
        }
    }

    /** 从 nginx 报错里抠出 "line 3:" 这种行号，前端好提示改哪一行。 */
    private static String extractLine(String output) {
        if (output == null) {
            return "";
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("line (\\d+):\\s*([^\\n]*)").matcher(output);
        return m.find() ? ("第 " + m.group(1) + " 行：" + m.group(2).trim()) : "";
    }

    private static String truncate(String s, int n) {
        return s == null ? "" : (s.length() <= n ? s : s.substring(0, n));
    }

    private static Map<String, Integer> toCc(JsonNode n) {
        Map<String, Integer> out = new HashMap<>();
        for (var e : Map.of("max_requests", 20, "window", 10, "block_duration", 60).entrySet()) {
            out.put(e.getKey(), n.path(e.getKey()).asInt(e.getValue()));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> toMap(JsonNode n) {
        if (n == null || n.isMissingNode() || n.isNull()) {
            return Map.of();
        }
        return new com.fasterxml.jackson.databind.ObjectMapper().convertValue(n, Map.class);
    }
}
