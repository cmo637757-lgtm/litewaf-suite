-- ============================================================================
--  P5 告警监控项扩展（2026-11-02）
--
--  背景：原来的 alert_rules 只能「按攻击类别数事件」，监控维度太窄——
--  想抓「某个 IP 狂刷 403」「某个 URI 被反复打」「某条规则突然高频命中」
--  就得给每种需求加一列，没有尽头。
--
--  改法：把「数什么」抽象成 metric 一列，其余都是它的参数：
--    metric=category  数某类攻击（原行为，category 列就填 SQLi/XSS/CC）
--    metric=ip        数某个来源 IP 的全部拦截
--    metric=uri       数 URI 命中 LIKE 模式的请求（match_value 填 %union% 这种）
--    metric=rule      数规则名包含 match_value 的命中
--    metric=status    数某个 HTTP 状态码
--
--  另外加两个「告警分级」和「突增」需要的列：
--    ratio    突增倍数阈值（当前窗口 ÷ 过去 1 小时同维度每窗口均值）
--    severity 基础级别；实际级别由「≥2×阈值 或 突增 ≥10x」升级为 red
--    channel  通知渠道（webhook / inapp）
--
--  执行：mariadb --skip-ssl litewaf < alerts_p5.sql
--  幂等：全部用 ADD COLUMN IF NOT EXISTS，重复执行不报错。
-- ============================================================================

ALTER TABLE alert_rules
  ADD COLUMN IF NOT EXISTS metric      VARCHAR(16)  NOT NULL DEFAULT 'category' COMMENT '监控项：category/ip/uri/rule/status',
  ADD COLUMN IF NOT EXISTS match_value VARCHAR(128) NOT NULL DEFAULT ''         COMMENT 'metric 的匹配值',
  ADD COLUMN IF NOT EXISTS ratio       DECIMAL(4,1) NOT NULL DEFAULT 5.0        COMMENT '突增倍数阈值',
  ADD COLUMN IF NOT EXISTS severity    VARCHAR(8)   NOT NULL DEFAULT 'yellow'   COMMENT '基础级别 yellow/red',
  ADD COLUMN IF NOT EXISTS channel     VARCHAR(16)  NOT NULL DEFAULT 'webhook'  COMMENT '通知渠道 webhook/inapp';

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS metric     VARCHAR(16) NOT NULL DEFAULT 'category' COMMENT '触发时的监控项',
  ADD COLUMN IF NOT EXISTS severity   VARCHAR(8)  NOT NULL DEFAULT 'yellow'   COMMENT 'yellow/red',
  ADD COLUMN IF NOT EXISTS burst_ratio DOUBLE     NOT NULL DEFAULT 1.0        COMMENT '触发时的突增倍数';

-- 预置两条演示规则（与 S6 的两条错开，专门演示新维度）
INSERT IGNORE INTO alert_rules
  (name, metric, match_value, category, threshold, ratio, window_s, suppress_s, severity, channel, webhook_url, enabled, created_at)
VALUES
  ('单 IP 403 风暴', 'ip',   '',       '', 20, 5.0, 60, 120, 'yellow', 'webhook', 'http://127.0.0.1:18099/hook', 0, 0),
  ('URI 关键词监控', 'uri', '%union%', '', 5,  5.0, 60, 120, 'yellow', 'webhook', 'http://127.0.0.1:18099/hook', 0, 0);
