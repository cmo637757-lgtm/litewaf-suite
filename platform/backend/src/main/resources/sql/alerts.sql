-- ============================================================================
--  S6 告警模块建表脚本
--
--  设计要点（与需求卡片 R35-01 ~ R35-05 对齐）：
--  1. 告警只消费"已提交入库"的 waf_events，靠 alert_consumer_cursor 记 last_event_id，
--     崩溃重启后从游标继续，不会重复也不会漏。
--  2. 计数用"固定时间桶"：bucket_start = floor(event_time / window_s) * window_s，
--     不是"最近 N 秒滚动"。桶对齐到 UTC 整点，跨桶不累计。
--  3. trigger_count / event_count / delivery_count 三个数是不同东西：
--     trigger_count = 候选触发次数（每跨一次阈值 +1）
--     event_count   = 关联事件数（去重后的 event_id 个数）
--     delivery_count= 实际投递次数（含重试）
--  4. 通知状态（sent/failed/unknown）与处置状态（open/handled）分开两个字段，
--     重试不会改变处置状态。
--
--  执行：mariadb --skip-ssl litewaf < alerts.sql
-- ============================================================================

-- 告警规则：一条规则 = 某类攻击 + 阈值 + 窗口 + 抑制时长
CREATE TABLE IF NOT EXISTS alert_rules (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(64)  NOT NULL,
  category      VARCHAR(32)  NOT NULL,          -- SQLi / XSS / CC，空串表示不分类
  threshold     INT          NOT NULL,          -- 窗口内事件数达到多少触发
  window_s      INT          NOT NULL,          -- 固定桶大小（秒）
  suppress_s    INT          NOT NULL,          -- 首次触发后的静默期（秒）
  webhook_url   VARCHAR(255) NOT NULL,          -- 本地 webhook 地址
  enabled       TINYINT      NOT NULL DEFAULT 1,
  created_at    BIGINT       NOT NULL,
  UNIQUE KEY uk_rule_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警规则';

-- 告警实例
CREATE TABLE IF NOT EXISTS alerts (
  id                BIGINT AUTO_INCREMENT PRIMARY KEY,
  rule_id           INT          NOT NULL,
  client_ip         VARCHAR(64)  NOT NULL,
  category          VARCHAR(32)  NOT NULL,
  bucket_start      BIGINT       NOT NULL,       -- 首次候选所属的固定桶
  first_trigger_ms  BIGINT       NOT NULL,
  last_trigger_ms   BIGINT       NOT NULL,
  trigger_count     INT          NOT NULL DEFAULT 0,
  event_count       INT          NOT NULL DEFAULT 0,
  suppressed_until_ms BIGINT     NOT NULL DEFAULT 0,
  handled           TINYINT      NOT NULL DEFAULT 0,   -- 处置状态：0 未处理 / 1 已处理
  delivery_count    INT          NOT NULL DEFAULT 0,
  created_at        BIGINT       NOT NULL,
  KEY idx_alert_time (first_trigger_ms),
  KEY idx_alert_rule_ip (rule_id, client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警实例';

-- 告警与事件的多对多：event_count 就是这里 count(*)
CREATE TABLE IF NOT EXISTS alert_events (
  alert_id  BIGINT NOT NULL,
  event_id  BIGINT NOT NULL,
  PRIMARY KEY (alert_id, event_id),
  KEY idx_ae_event (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警关联事件';

-- 投递记录：状态= pending/sent/failed/unknown，重试复用同一行
CREATE TABLE IF NOT EXISTS alert_deliveries (
  id           BIGINT AUTO_INCREMENT PRIMARY KEY,
  alert_id     BIGINT       NOT NULL,
  url          VARCHAR(255) NOT NULL,
  status       VARCHAR(16)  NOT NULL DEFAULT 'pending',
  http_code    INT          NULL,
  attempts     INT          NOT NULL DEFAULT 0,
  last_error   VARCHAR(255) NULL,
  next_retry_ms BIGINT      NULL,
  created_at   BIGINT       NOT NULL,
  updated_at   BIGINT       NOT NULL,
  KEY idx_deliver_alert (alert_id),
  KEY idx_deliver_retry (status, next_retry_ms)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警投递记录';

-- 消费游标：单行（id=1），记录已消费到哪个 event_id
CREATE TABLE IF NOT EXISTS alert_consumer_cursor (
  id             INT PRIMARY KEY,
  last_event_id  BIGINT NOT NULL DEFAULT 0,
  updated_at     BIGINT NOT NULL,
  skipped_total  INT    NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警消费游标';

INSERT IGNORE INTO alert_consumer_cursor (id, last_event_id, updated_at, skipped_total)
VALUES (1, 0, 0, 0);

-- 预置两条演示规则：SQLi 3 次/60 秒触发、抑制 300 秒；CC 5 次/60 秒触发、抑制 120 秒
INSERT IGNORE INTO alert_rules (name, category, threshold, window_s, suppress_s, webhook_url, enabled, created_at)
VALUES ('SQLi 高频告警', 'SQLi', 3, 60, 300, 'http://127.0.0.1:18099/hook', 1, 0),
       ('CC 高频告警',  'CC',   5, 60, 120, 'http://127.0.0.1:18099/hook', 1, 0);
