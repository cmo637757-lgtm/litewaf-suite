-- R34-10 人工误报标记表
--
-- 口径（卡片 R34-10）：
--   * 一个事件最多一个标记，event_id 做主键就是唯一约束；
--   * 标记不修改 waf_events 本身（源事实永远保留），只在旁边记一个"这个拦截被判为误报/不是误报"；
--   * 三个指标分开算，绝不能混：
--       ① 已确认误拦占全部拦截比例 = confirmed / 全部拦截事件数
--       ② 复核覆盖率                 = (confirmed + rejected) / 全部拦截事件数
--       ③ 已复核事件误拦占比         = confirmed / (confirmed + rejected)
--     其中"全部拦截事件数"取所选时间窗内的 waf_events 条数；
--   * 离线误报率（FPR）不在这里算，属于 R34-11 的带标签样本评估。
CREATE TABLE IF NOT EXISTS false_positive_marks (
    event_id      BIGINT       NOT NULL COMMENT '被标记的 waf_events.id',
    decision      VARCHAR(16)  NOT NULL COMMENT 'confirmed=确认误报，rejected=驳回（是真攻击）',
    operator      VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '标记人（平台账号）',
    remark        VARCHAR(512) NOT NULL DEFAULT '' COMMENT '备注，可空',
    created_at_ms BIGINT       NOT NULL COMMENT '首次标记时间，UTC 毫秒',
    updated_at_ms BIGINT       NOT NULL COMMENT '最后一次更新时间，UTC 毫秒',
    PRIMARY KEY (event_id),
    KEY idx_fp_decision (decision),
    KEY idx_fp_updated (updated_at_ms)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COMMENT = '人工误报标记（R34-10）';
