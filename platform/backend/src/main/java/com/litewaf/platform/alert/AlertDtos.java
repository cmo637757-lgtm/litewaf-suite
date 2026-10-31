package com.litewaf.platform.alert;

import java.util.List;

/**
 * 告警模块的对外数据结构。
 *
 * 全部用 record：只读、无 setter，JdbcTemplate 手工映射，不引 JPA 那一套。
 */
public final class AlertDtos {

    private AlertDtos() {}

    /** 告警规则。threshold/window_s/suppress_s 是固定时间桶口径，见 alerts.sql 注释。 */
    public record Rule(
            int id,
            String name,
            String category,
            int threshold,
            int windowS,
            int suppressS,
            String webhookUrl,
            boolean enabled) {}

    /** 告警实例（列表行）。suppressed 是"此刻是否仍在抑制期内"，由 suppressed_until_ms 与当前时间算出来。 */
    public record Alert(
            long id,
            String ruleName,
            String clientIp,
            String category,
            long bucketStart,
            long firstTriggerMs,
            long lastTriggerMs,
            long suppressedUntilMs,
            int triggerCount,
            int eventCount,
            int deliveryCount,
            boolean suppressed,
            boolean handled,
            String deliveryStatus) {}

    /** 详情页里展开的关联事件（只带够看的四个字段，不把整条事件搬过来）。 */
    public record EventBrief(long id, long eventTimeMs, String uri, String ruleName) {}

    /** 投递记录。 */
    public record Delivery(
            long id,
            String url,
            String status,
            Integer httpCode,
            int attempts,
            String lastError,
            long updatedAt) {}

    /** 告警详情：实例 + 关联事件 + 投递记录。 */
    public record AlertDetail(Alert alert, List<Long> eventIds, List<EventBrief> events,
                              List<Delivery> deliveries) {}

    /** 消费器的运行状态，用于页面上显示"告警是否在跑"。 */
    public record ConsumerState(long lastEventId, long updatedAt, int skippedTotal) {}

    /** webhook 请求体（R35-04 固定字段）。 */
    public record WebhookPayload(
            String schema_version,
            long delivery_id,
            long alert_id,
            String rule_name,
            String client_ip,
            String category,
            long first_trigger_ms,
            long last_trigger_ms,
            int event_count,
            int trigger_count) {}
}
