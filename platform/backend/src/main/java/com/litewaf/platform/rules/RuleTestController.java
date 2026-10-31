package com.litewaf.platform.rules;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * 规则试打沙箱（规则排错用）。
 *
 * <p>「这条规则会不会误伤我的 URL」是调规则时最常问的问题。与其发布到线上
 * 再观察，不如先打一发看结果：把待测 URI 原样发给正在运行的 WAF 实例
 * （127.0.0.1:18010），回读审计日志拿到命中的规则名与类别。
 *
 * <p><b>这是个只读试探，但有副作用</b>：试打请求会正常进访问日志、也会计入
 * CC 漏桶。所以界面要提示「短时间内别连续打超过容量」，否则会被自己的 CC 封掉。
 *
 * <p>为什么不自己实现一遍正则：卡片明确要求「规则必须用同 PCRE2 解析器校验」，
 * 用 Java 正则模拟出来的结论与线上不一致，等于没验证。
 */
@RestController
@RequestMapping("/api/rules")
public class RuleTestController {

    private static final String BROWSER_UA =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    @Value("${app.engine.target-base:http://127.0.0.1:18010}")
    private String targetBase;

    @Value("${app.engine.audit-log:/opt/litewaf/runtime/logs/waf_audit.log}")
    private String auditLog;

    public record TestRequest(String uri, String userAgent, String method) {
    }

    public record TestResult(int status, boolean blocked,
                             String reason, String ruleName, Integer ruleId,
                             String category, String categoryDisplay,
                             Integer score, long latencyMs, String note) {
    }

    @PostMapping("/test")
    public TestResult test(@RequestBody TestRequest req) {
        String uri = req.uri() == null ? "" : req.uri().trim();
        if (uri.isEmpty()) {
            throw new IllegalArgumentException("uri 不能为空，例如 /?id=1' OR 1=1--");
        }
        if (!uri.startsWith("/")) {
            throw new IllegalArgumentException("uri 必须以 / 开头");
        }
        String method = (req.method() == null || req.method().isBlank()) ? "GET" : req.method().toUpperCase();
        String ua = (req.userAgent() == null || req.userAgent().isBlank()) ? BROWSER_UA : req.userAgent();

        long t0 = System.currentTimeMillis();
        int status;
        try {
            HttpRequest r = HttpRequest.newBuilder(URI.create(targetBase + uri))
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", ua)
                    .header("X-LiteWAF-Test", "1")
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .build();
            status = http.send(r, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException("试打请求失败：" + e.getMessage());
        }
        long latency = System.currentTimeMillis() - t0;

        boolean blocked = status == 403;
        String note = blocked
                ? "被拦截：下面是从审计日志里读到的命中规则"
                : "未被拦截。注意这只说明当前规则集放行了它，不代表它是安全的";

        if (!blocked) {
            return new TestResult(status, false, "", "", null, "", "", null, latency, note);
        }

        // 被拦了就去审计日志尾巴里找「刚刚这一条」，拿规则名与得分
        String[] hit = tailMatch(uri);
        if (hit == null) {
            return new TestResult(status, true, "unknown", "", null, "", "", null, latency,
                    "被拦截，但审计日志里没找到对应记录（可能日志延迟写入）");
        }
        // 审计日志里存的是引擎内部类别（SQL/XSS/…），展示用的 SQLi/CC 由采集器映射；
        // 这里沿用同一套映射，避免同一个事件在两个页面显示成两个名字。
        String display = displayCategory(hit[3], hit[0]);
        return new TestResult(status, true, hit[0], hit[1],
                hit[2].isEmpty() ? null : Integer.valueOf(hit[2]),
                hit[3], display,
                hit[5].isEmpty() ? null : Integer.valueOf(hit[5]),
                latency, note);
    }

    /** 与 collector/lwaf_collect.py:display_category 保持一致。 */
    private static String displayCategory(String category, String reason) {
        String c = category == null ? "" : category.toUpperCase();
        if ("DYNAMIC_BLOCK".equals(c) || c.isEmpty()) {
            return "dynamic_block".equalsIgnoreCase(reason) ? "CC" : c.isEmpty() ? "CC" : c;
        }
        return switch (c) {
            case "SQL" -> "SQLi";
            case "TRAVERSAL" -> "TRAVERSAL";
            case "UPLOAD" -> "UPLOAD";
            case "SCAN" -> "SCAN";
            default -> c;
        };
    }

    /**
     * 从审计日志尾部读最近一条 uri 完全匹配的记录。
     * 只读最后 128 KB：日志可能已经几十万行，全读会拖慢接口。
     * 返回 [reason, rule_name, rule_id, category, category_display, score]。
     */
    private String[] tailMatch(String uri) {
        Path p = Path.of(auditLog);
        if (!Files.isRegularFile(p)) {
            return null;
        }
        try (RandomAccessFile raf = new RandomAccessFile(p.toFile(), "r")) {
            long size = raf.length();
            int read = (int) Math.min(size, 128 * 1024);
            byte[] buf = new byte[read];
            raf.seek(size - read);
            raf.readFully(buf);
            String text = new String(buf, StandardCharsets.UTF_8);
            String[] lines = text.split("\n");
            String want = "\"uri\":\"" + uri.replace("\"", "\\\"") + "\"";
            for (int i = lines.length - 1; i >= 0; i--) {
                String line = lines[i];
                if (!line.contains(want)) {
                    continue;
                }
                return new String[]{
                        field(line, "reason"),
                        field(line, "rule_name"),
                        field(line, "rule_id"),
                        field(line, "category"),
                        field(line, "category_display"),
                        field(line, "score")
                };
            }
        } catch (IOException ignored) {
            return null;
        }
        return null;
    }

    /** 从一行 JSON 里抠字段值（不引 Jackson，避免和 DTO 命名策略纠缠）。 */
    private static String field(String line, String key) {
        String needle = "\"" + key + "\":";
        int i = line.indexOf(needle);
        if (i < 0) {
            return "";
        }
        int j = i + needle.length();
        if (j < line.length() && line.charAt(j) == '"') {
            int k = line.indexOf('"', j + 1);
            return k < 0 ? "" : line.substring(j + 1, k);
        }
        int k = j;
        while (k < line.length() && ",}".indexOf(line.charAt(k)) < 0) {
            k++;
        }
        return line.substring(j, k).trim();
    }
}
