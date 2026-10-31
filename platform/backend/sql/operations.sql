-- S5 发布闭环需要的表：操作审计 + 版本元数据（版本文件本身在引擎侧 /opt/litewaf/runtime/versions）
-- 用法：sudo mariadb --skip-ssl litewaf < /path/to/operations.sql

CREATE TABLE IF NOT EXISTS operations (
  id            BIGINT       NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  op_id         VARCHAR(32)  NOT NULL COMMENT '一个用户动作一个 id，前后端都能引用',
  action        VARCHAR(24)  NOT NULL COMMENT 'check / publish / rollback',
  status        VARCHAR(16)  NOT NULL COMMENT 'started / ok / rejected / failed / error',
  operator      VARCHAR(64)  NOT NULL COMMENT '谁点的，取自 JWT 用户名',
  detail        VARCHAR(1024) NOT NULL DEFAULT '' COMMENT '失败原因或版本号摘要',
  started_at_ms BIGINT       NOT NULL COMMENT '开始时间（UTC 毫秒）',
  finished_at_ms BIGINT       NULL COMMENT '结束时间；NULL 说明还没结束（可能中途崩了）',
  PRIMARY KEY (id),
  UNIQUE KEY uk_op_id (op_id),
  KEY idx_started (started_at_ms),
  KEY idx_action_status (action, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='平台侧操作审计（与 WAF 拒绝日志分离）';
