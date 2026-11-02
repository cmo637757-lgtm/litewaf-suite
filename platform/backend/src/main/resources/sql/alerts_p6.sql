-- P6 站内消息：告警的第二种通知渠道（channel=inapp 时走这里，不发出网请求）
-- 与 alert_deliveries 的关系：投递记录仍然留一条（url='inapp://local'、状态直接 sent），
-- 这样「投递次数/成功率」在页面上口径一致，不用区分渠道。

CREATE TABLE IF NOT EXISTS inapp_messages (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  alert_id      BIGINT       NOT NULL,
  severity      VARCHAR(8)   NOT NULL DEFAULT 'yellow',
  title         VARCHAR(200) NOT NULL,
  body          VARCHAR(1000) DEFAULT NULL,
  created_at_ms BIGINT       NOT NULL,
  read_at_ms    BIGINT       DEFAULT NULL,
  KEY idx_created (created_at_ms),
  KEY idx_alert (alert_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
