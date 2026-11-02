package com.litewaf.platform.alert;

import com.litewaf.platform.alert.AlertDtos.Alert;
import com.litewaf.platform.alert.AlertDtos.AlertDetail;
import com.litewaf.platform.alert.AlertDtos.ConsumerState;
import com.litewaf.platform.alert.AlertDtos.Rule;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 告警接口。读接口 viewer 也能用，写接口只有 admin（SecurityConfig 统一拦）。
 *
 * 路由按课件 3 的口径：资源用名词复数，动作用子路径。
 */
@RestController
@RequestMapping("/api")
public class AlertController {

    private final AlertService service;
    private final AlertRepository repo;

    public AlertController(AlertService service, AlertRepository repo) {
        this.service = service;
        this.repo = repo;
    }

    @GetMapping("/alert-rules")
    public List<Rule> rules() {
        return repo.rules();
    }

    /** 改阈值/窗口/抑制/Webhook/启停，以及 P5 新增的倍数/级别/渠道。约束在这里兜一层。 */
    @PostMapping("/alert-rules/{id}")
    public Map<String, Object> updateRule(@PathVariable int id, @RequestBody Map<String, Object> body) {
        int threshold = intOf(body.get("threshold"), 3);
        int windowS = intOf(body.get("window_s"), 60);
        int suppressS = intOf(body.get("suppress_s"), 300);
        double ratio = doubleOf(body.get("ratio"), 5.0);
        String severity = String.valueOf(body.getOrDefault("severity", "yellow"));
        String channel = String.valueOf(body.getOrDefault("channel", "webhook"));
        String url = String.valueOf(body.getOrDefault("webhook_url", ""));
        boolean enabled = !Boolean.FALSE.equals(body.get("enabled"));

        if (threshold < 1 || threshold > 10000) {
            throw new IllegalArgumentException("threshold 超出范围 1-10000");
        }
        if (windowS < 5 || windowS > 3600) {
            throw new IllegalArgumentException("window_s 超出范围 5-3600");
        }
        if (suppressS < windowS || suppressS > 86400) {
            throw new IllegalArgumentException("suppress_s 必须 ≥ window_s 且 ≤ 86400");
        }
        if (ratio < 1.0 || ratio > 100.0) {
            throw new IllegalArgumentException("ratio（突增倍数）必须是 1.0-100.0");
        }
        if (!"yellow".equals(severity) && !"red".equals(severity)) {
            throw new IllegalArgumentException("severity 只能是 yellow 或 red");
        }
        if (!"webhook".equals(channel) && !"inapp".equals(channel)) {
            throw new IllegalArgumentException("channel 只能是 webhook 或 inapp");
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("webhook_url 只允许 http/https");
        }
        repo.updateRule(id, threshold, ratio, windowS, suppressS, severity, channel, url, enabled);
        return Map.of("ok", true, "id", id);
    }

    @GetMapping("/alerts")
    public List<Alert> list(@RequestParam(required = false) Long from,
                            @RequestParam(required = false) Long to,
                            @RequestParam(required = false) Boolean handled,
                            @RequestParam(defaultValue = "50") int limit) {
        return repo.list(from, to, handled, Math.min(Math.max(limit, 1), 200));
    }

    @GetMapping("/alerts/state")
    public ConsumerState state() {
        return repo.cursor();
    }

    @GetMapping("/alerts/{id}")
    public AlertDetail detail(@PathVariable long id) {
        AlertDetail d = repo.detail(id);
        if (d == null) {
            throw new AlertNotFoundException(id);
        }
        return d;
    }

    /** 人工重试通知（复用原 delivery 记录）。 */
    @PostMapping("/alerts/{id}/retry")
    public Map<String, Object> retry(@PathVariable long id) {
        boolean ok = service.retryAlert(id);
        if (!ok) {
            throw new AlertNotFoundException(id);
        }
        return Map.of("ok", true, "id", id);
    }

    /** 标记已处理 / 撤销已处理。 */
    @PostMapping("/alerts/{id}/handled")
    public Map<String, Object> handled(@PathVariable long id, @RequestBody(required = false) Map<String, Object> body) {
        boolean handled = body == null || !Boolean.FALSE.equals(body.get("handled"));
        repo.setHandled(id, handled);
        return Map.of("ok", true, "id", id, "handled", handled);
    }

    private static int intOf(Object v, int dft) {
        if (v == null) {
            return dft;
        }
        try {
            return Integer.parseInt(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("参数必须是整数：" + v);
        }
    }

    private static double doubleOf(Object v, double dft) {
        if (v == null) {
            return dft;
        }
        try {
            return Double.parseDouble(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("参数必须是数字：" + v);
        }
    }

    /** 告警不存在 → 404 */
    public static class AlertNotFoundException extends RuntimeException {
        public AlertNotFoundException(long id) {
            super("告警不存在：" + id);
        }
    }
}
