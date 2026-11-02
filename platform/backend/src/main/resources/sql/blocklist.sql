-- P7：自动封禁名单（红色告警触发 → 平台调执行器写入引擎黑名单 → 这里留审计记录）
CREATE TABLE IF NOT EXISTS blocklist (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_ip      VARCHAR(45)  NOT NULL,
    reason         VARCHAR(64)  NOT NULL DEFAULT 'auto_alert',
    alert_id       BIGINT       NULL,
    rule_name      VARCHAR(64)  NULL,
    created_at_ms  BIGINT       NOT NULL,
    released_at_ms BIGINT       NULL,
    active         TINYINT(1)   NOT NULL DEFAULT 1,
    UNIQUE KEY uniq_active_ip (client_ip, active),
    KEY idx_created (created_at_ms)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
