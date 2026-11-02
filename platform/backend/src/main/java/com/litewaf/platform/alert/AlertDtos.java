package com.litewaf.platform.alert;

import java.util.List;

/**
 * 告警模块的对外数据结构。
 *
 * 全部用 record：只读、无 setter，JdbcTemplate 手工映射，不引 JPA 那一套。
 *
 * P5 起多了一层「监控项」概念：metric 决定这条规则数什么（见 alerts.sql 的字段注释），
 * metric=category 是原来的行为（按攻击类别计数），其余是新建的维度。
 */
public final class AlertDtos {

    private AlertDtos() {}

    /**
     * 告警规则。
     *
     * @param metric     监控项：category / ip / uri / rule / status
     * @param matchValue metric 的匹配值（uri 是 LIKE 模式，rule 是规则名关键字，status 是状态码）
     * @param ratio      突增倍数：当前窗口事件数 ÷ 过去 1 小时同维度每窗口均值的阈值
     * @param severity   基础级别：yellow / red
     * @param channel    通知渠道：webhook / inapp
     */
    public record Rule(
            int id,
            String name,
            String metric,
            String matchValue,
            String category,
            int threshold,
            double ratio,
            int windowS,
            int suppressS,
            String severity,
            String channel,
            String webhookUrl,
            boolean enabled) {}

    /**
     * 告警实例（列表行）。
     *
     * @param severity    本条告警判定的级别（yellow / red），由「达到阈值」或「突增」决定
     * @param burstRatio  触发时的突增倍数（1.0 表示全靠阈值触发，没有突增）
     */
    public record Alert(
            long id,
            String ruleName,
            String clientIp,
            String category,
            String metric,
            long bucketStart,
            long firstTriggerMs,
            long lastTriggerMs,
            long suppressedUntilMs,
            int triggerCount,
            int eventCount,
            int deliveryCount,
            String severity,
            double burstRatio,
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

    /**
     * 告警健康（P8 用，先留结构）：事件入库到告警触发的延迟分布 + 投递成功率。
     */
    public record AlertHealth(
            int eventsLast24h,
            int alertsLast24h,
            int yellow24h,
            int red24h,
            int deliveries24h,
            int failed24h,
            long p95DelayMs) {}

    /** webhook 请求体（R35-04 固定字段，P5 增补 severity/burst_ratio，老字段不动）。 */
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
            int trigger_count,
            String severity,
            double burst_ratio) {}
}
