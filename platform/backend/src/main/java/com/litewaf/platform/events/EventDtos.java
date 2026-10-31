package com.litewaf.platform.events;

import java.util.List;

/**
 * 事件查询的传输对象。
 *
 * <p>字段口径来自需求卡片 R33-03：固定 14 个字段，与脱敏后的输入一致；
 * 源日志里没有的字段（例如旧日志缺 rule_name）如实返回「日志未记录」，
 * 前端不需要自己编造。
 */
public final class EventDtos {

    private EventDtos() {
    }

    /**
     * 一条 WAF 拦截事件的展示形态（14 字段）。
     *
     * <p>{@code event_time} 用 ISO-8601 字符串回传（UTC），前端按 Asia/Shanghai 显示；
     * 库里存的是 UTC 毫秒整数，排序和窗口计算都靠它。
     */
    public record EventItem(
            long id,
            String event_time,
            String client_ip,
            String method,
            String uri,
            int status,
            String reason,
            int rule_id,
            String rule_name,
            String category,
            String category_display,
            String action,
            int cost_us,
            int score) {
    }

    /**
     * 统一列表返回体：{@code items/total/page/page_size/as_of}。
     *
     * <p>{@code as_of} 是本次查询的快照时间，前端画图表时以它为「数据截止」，
     * 避免用户误以为页面实时刷新。
     */
    public record PageResult<T>(
            List<T> items,
            long total,
            int page,
            int page_size,
            long as_of) {
    }
}
