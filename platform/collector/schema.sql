-- schema.sql —— LiteWAF 平台最小数据表（S2，MariaDB 11.x）
--
-- 设计口径直接来自需求卡片第三章：
--   1. 游标唯一键 = 来源 + 文件身份 + 代次，崩溃重启后靠它续采，不会重复也不会丢行
--   2. 主去重键是「来源 + 文件身份 + 代次 + 字节偏移」，内容哈希只做校验不跨行去重
--   3. 时间统一存 UTC epoch 毫秒，查询用 [start, end) 闭开区间
--   4. 源日志字段原值另存（category），展示映射另开一列（category_display），不改写源文件
--
-- 执行：sudo mariadb < schema.sql

CREATE DATABASE IF NOT EXISTS litewaf
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE litewaf;

-- ---------------------------------------------------------------- 采集来源
-- 一个来源 = 一个被 tail 的日志文件。kind 决定解析成 requests 还是 waf_events。
CREATE TABLE IF NOT EXISTS ingest_sources (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(64)  NOT NULL COMMENT '来源名，如 waf_reject / nginx_access',
    path          VARCHAR(512) NOT NULL COMMENT '文件绝对路径（必须是完整路径，禁止相对路径）',
    kind          ENUM('waf','access') NOT NULL COMMENT 'waf=审计日志，access=访问日志',
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uq_source_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='采集来源注册表';

-- ---------------------------------------------------------------- 采集游标
-- 每个 (来源, 文件身份, 代次) 一条记录。file_identity 用 "st_dev:st_ino"：
-- 日志 rename+create 轮转后 inode 变化 → 自动开新代次从 0 读，旧文件尾部也能读完。
CREATE TABLE IF NOT EXISTS ingest_cursors (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    source_id      INT          NOT NULL,
    file_identity  VARCHAR(128) NOT NULL COMMENT 'st_dev:st_ino，识别同一物理文件',
    generation     INT          NOT NULL DEFAULT 1 COMMENT '同一来源换了文件就 +1',
    byte_offset    BIGINT       NOT NULL DEFAULT 0 COMMENT '已成功入库的字节偏移（下次从这里读）',
    inode_size     BIGINT       NOT NULL DEFAULT 0 COMMENT '上次读到的文件大小，用于检测截断',
    updated_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uq_cursor (source_id, file_identity, generation),
    KEY idx_source (source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='采集游标（提交事务时才推进）';

-- ---------------------------------------------------------------- 访问日志
CREATE TABLE IF NOT EXISTS requests (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time_ms   BIGINT      NOT NULL COMMENT 'UTC epoch 毫秒',
    client_ip       VARCHAR(45) NOT NULL,
    method          VARCHAR(16) NOT NULL,
    uri             TEXT        NOT NULL,
    status          SMALLINT    NOT NULL,
    body_bytes_sent INT         NOT NULL DEFAULT 0,
    request_time_ms DECIMAL(12,3) NOT NULL DEFAULT 0 COMMENT '源日志 request_time 秒 ×1000',
    source_id       INT         NOT NULL,
    KEY idx_etime (event_time_ms),
    KEY idx_ip (client_ip),
    KEY idx_status (status),
    KEY idx_time_ip (event_time_ms, client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='访问记录（N 的来源）';

-- ---------------------------------------------------------------- WAF 事件
-- category 保留引擎原值，category_display 是展示映射：SQL→SQLi、dynamic_block→CC、blacklist→ACL。
CREATE TABLE IF NOT EXISTS waf_events (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time_ms    BIGINT       NOT NULL COMMENT 'UTC epoch 毫秒（源日志 time）',
    client_ip        VARCHAR(45)  NOT NULL,
    method           VARCHAR(16)  NOT NULL,
    uri              TEXT         NOT NULL,
    reason           VARCHAR(32)  NOT NULL COMMENT 'score_threshold / rule_block / dynamic_block / blacklist',
    rule_id          INT          NOT NULL DEFAULT 0,
    rule_name        VARCHAR(128) NOT NULL DEFAULT '',
    zone             VARCHAR(32)  NOT NULL DEFAULT '',
    category         VARCHAR(32)  NOT NULL DEFAULT '' COMMENT '引擎原值：SQL/XSS/SCAN/...，(dynamic_block 为空)',
    category_display VARCHAR(16)  NOT NULL COMMENT '展示值：SQLi/XSS/CC/Scanner/...',
    score            INT          NOT NULL DEFAULT 0,
    total_score      INT          NOT NULL DEFAULT 0,
    action           VARCHAR(16)  NOT NULL,
    status           SMALLINT     NOT NULL,
    cost_us          INT          NOT NULL DEFAULT 0 COMMENT '拦截处理耗时（含异步 BODY 等待）',
    source_id        INT          NOT NULL,
    KEY idx_etime (event_time_ms),
    KEY idx_ip (client_ip),
    KEY idx_cat (category_display, event_time_ms),
    KEY idx_rule (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='WAF 拒绝事件（B 的来源）';

-- ---------------------------------------------------------------- 采集错误
-- 畸形行不阻塞主流程：原样留 raw_line，够 60 秒排查一次即可。
CREATE TABLE IF NOT EXISTS ingest_errors (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    source_id  INT          NOT NULL,
    raw_line   MEDIUMTEXT   NOT NULL,
    error      VARCHAR(255) NOT NULL,
    created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='解析失败的行（可人工重放）';
