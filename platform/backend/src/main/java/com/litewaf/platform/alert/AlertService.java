package com.litewaf.platform.alert;

import com.litewaf.platform.alert.AlertDtos.Alert;
import com.litewaf.platform.alert.AlertDtos.ConsumerState;
import com.litewaf.platform.alert.AlertDtos.Rule;
import com.litewaf.platform.alert.AlertDtos.WebhookPayload;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 告警核心逻辑：消费入库事件 → 固定时间桶计数 → 阈值触发 → 抑制合并 → 本地 Webhook 投递。
 *
 * 三条硬口径（对照需求卡片 R35-01 ~ R35-04）：
 * 1) 只消费"已提交入库"的事件（waf_events 是采集器单事务写入的，读到就是已提交）；
 *    游标 last_event_id 与处理同事务提交，崩溃重启不会重复计数。
 * 2) live 模式只对 event_time 距今 ≤ 120 秒的事件发通知，更旧的计入 historical_skipped，
 *    这是为了防止"导入一天前的日志时刷出一堆实时告警"。
 * 3) 抑制期不延长：首触发固定 suppressed_until = first_trigger + suppress_s，
 *    期间再有候选只累加 trigger_count / event_count，不再发通知。
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    /** live 窗口：事件时间距当前超过这个值就算历史数据，不发实时通知 */
    private static final long LIVE_WINDOW_MS = 120_000L;

    /** 单批最多消费多少条事件（卡片要求 ≤200） */
    private static final int BATCH = 200;

    /** Webhook 失败后的重试间隔（毫秒）：10 秒、30 秒、2 分钟，之后只留 failed 等人工重试 */
    private static final long[] RETRY_BACKOFF = {10_000L, 30_000L, 120_000L};

    private final AlertRepository repo;
    private final ObjectMapper json;

    /** 连接 2 秒、总超时 5 秒、不跟随重定向（R35-04） */
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public AlertService(AlertRepository repo, ObjectMapper json) {
        this.repo = repo;
        this.json = json;
    }

    /**
     * 消费一批事件。
     *
     * @return 本批处理的事件条数（0 表示没有新事件）
     */
    @Transactional
    public int consumeOnce() {
        ConsumerState cursor = repo.cursor();
        List<Map<String, Object>> events = repo.eventsAfter(cursor.lastEventId(), BATCH);
        if (events.isEmpty()) {
            return 0;
        }

        List<Rule> rules = repo.rules().stream().filter(Rule::enabled).toList();
        long now = System.currentTimeMillis();
        int skipped = 0;
        long lastId = cursor.lastEventId();

        for (Map<String, Object> e : events) {
            long eventId = ((Number) e.get("id")).longValue();
            lastId = eventId;
            long t = ((Number) e.get("event_time_ms")).longValue();
            String ip = String.valueOf(e.get("client_ip"));
            String cat = e.get("category_display") == null ? "" : String.valueOf(e.get("category_display"));

            if (t < now - LIVE_WINDOW_MS) {
                skipped++;
                continue;
            }

            for (Rule rule : rules) {
                if (!rule.category().isEmpty() && !rule.category().equals(cat)) {
                    continue;
                }
                long windowMs = rule.windowS() * 1000L;
                long bucketStart = (t / windowMs) * windowMs;
                int cnt = repo.countInBucket(ip, cat, bucketStart, t);
                if (cnt < rule.threshold()) {
                    continue;
                }
                // 到了这里说明"该桶内已经攒够阈值"，本条事件算一次候选触发
                Long active = repo.findActive(rule.id(), ip, cat, now);
                long alertId;
                if (active == null) {
                    alertId = repo.createAlert(rule.id(), ip, cat, bucketStart, t, t + rule.suppressS() * 1000L);
                    // 首次触发时，把桶内"到此刻为止"已经攒下的事件一并补进关联表，
                    // 否则 event_count 只从触发的那条算起，前面几条就丢了（A5 场景要求 5 条全在）
                    for (long eid : repo.eventIdsInBucket(ip, cat, bucketStart, t)) {
                        repo.linkEvent(alertId, eid);
                    }
                    repo.bumpTrigger(alertId, t);
                    deliver(alertId, rule);
                } else {
                    alertId = active;
                    repo.linkEvent(alertId, eventId);
                    repo.bumpTrigger(alertId, t);
                }
            }
        }

        repo.advanceCursor(lastId, skipped);
        return events.size();
    }

    /** 重试到期的失败投递（人工重试也走这里）。 */
    public void retryDue() {
        for (Map<String, Object> d : repo.dueRetries(20)) {
            long deliveryId = ((Number) d.get("id")).longValue();
            long alertId = ((Number) d.get("alert_id")).longValue();
            String url = String.valueOf(d.get("url"));
            doSend(deliveryId, alertId, url);
        }
    }

    /** 人工重试一条告警的通知（复用最近一次 delivery 记录，不新建）。 */
    public boolean retryAlert(long alertId) {
        var detail = repo.detail(alertId);
        if (detail == null) {
            return false;
        }
        if (detail.deliveries().isEmpty()) {
            // 从没投递过（比如当时就记录失败）：补一条
            Rule rule = ruleForAlert(alertId);
            if (rule == null) {
                return false;
            }
            deliver(alertId, rule);
            return true;
        }
        long deliveryId = detail.deliveries().get(detail.deliveries().size() - 1).id();
        doSend(deliveryId, alertId, detail.deliveries().get(detail.deliveries().size() - 1).url());
        return true;
    }

    /** 新建一条投递记录并立即发送。 */
    private void deliver(long alertId, Rule rule) {
        long deliveryId = repo.createDelivery(alertId, rule.webhookUrl());
        repo.bumpDeliveryCount(alertId);
        doSend(deliveryId, alertId, rule.webhookUrl());
    }

    /** 真正发 HTTP：2xx=成功；4xx/5xx=失败；超时/连接异常=unknown（重试后仍失败就留 FAILED）。 */
    private void doSend(long deliveryId, long alertId, String url) {
        var detail = repo.detail(alertId);
        if (detail == null) {
            return;
        }
        Alert a = detail.alert();
        WebhookPayload p = new WebhookPayload("1.0", deliveryId, alertId, a.ruleName(), a.clientIp(),
                a.category(), a.firstTriggerMs(), a.lastTriggerMs(), a.eventCount(), a.triggerCount());

        String status;
        Integer code = null;
        String err = null;
        long nextRetry = 0;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(p)))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            code = resp.statusCode();
            if (code >= 200 && code < 300) {
                status = "sent";
            } else {
                status = "failed";
                err = "HTTP " + code;
            }
        } catch (java.net.http.HttpTimeoutException e) {
            status = "unknown";
            err = "超时";
        } catch (Exception e) {                       // noqa: BLE001 —— 网络异常一律记 unknown，交给重试
            status = "unknown";
            err = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        if (!"sent".equals(status)) {
            nextRetry = System.currentTimeMillis() + RETRY_BACKOFF[0];
        }
        repo.updateDelivery(deliveryId, status, code, err, nextRetry);
        log.info("webhook alert={} delivery={} status={} code={}", alertId, deliveryId, status, code);
    }

    private Rule ruleForAlert(long alertId) {
        return repo.ruleOf(alertId);
    }
}
