package com.litewaf.platform.fp;

import java.util.List;

/**
 * 误报标记相关的数据结构（R34-10）。
 *
 * <p>命名注意：三个比率必须分开叫，别都写成 "误报率"——
 * {@code confirmedRatio}=已确认误拦占全部拦截；
 * {@code coverageRatio}=复核覆盖率；
 * {@code reviewedFpRatio}=已复核事件里误拦占比。
 * 离线误报率 FPR 属于 R34-11 的样本评估，不在这里。
 */
public final class FpDtos {

    private FpDtos() {
    }

    /** 一条标记（一个事件最多一条）。 */
    public record Mark(long eventId, String decision, String operator, String remark,
                       long createdAtMs, long updatedAtMs) {
    }

    /** 提交体：decision 只接受 confirmed / rejected，operator 由登录身份决定，不由前端传。 */
    public record MarkRequest(String decision, String remark) {
    }

    /** 列表行：标记 + 冗余一点事件信息，省得前端再 join。 */
    public record MarkItem(long eventId, long eventTime, String clientIp, String uri,
                           String categoryDisplay, String ruleName, String decision,
                           String operator, String remark, long updatedAtMs) {
    }

    public record MarkPage(List<MarkItem> items, long total, int page, int pageSize) {
    }

    /**
     * 指标快照。
     *
     * @param total           窗口内全部拦截事件数（waf_events 行数）
     * @param confirmed       其中被确认误报的
     * @param rejected        其中被驳回（判定为真攻击）的
     * @param unreviewed      还没人看的
     * @param confirmedRatio  confirmed / total
     * @param coverageRatio   (confirmed + rejected) / total
     * @param reviewedFpRatio confirmed / (confirmed + rejected)，无复核记录时为 0
     */
    public record Metrics(long from, long to, long total, long confirmed, long rejected,
                          long unreviewed, double confirmedRatio, double coverageRatio,
                          double reviewedFpRatio) {
    }
}
