-- =====================================================================
-- 平台账号表（S3）
-- 只做两级角色：ADMIN（能改配置、发布、标误报）/ VIEWER（只读）
-- 口令只存 BCrypt 哈希，源码与库中均不出现明文
--
-- 初始账号（部署后请立即修改）：
--   admin  / LiteWaf@2026   → 角色 ADMIN
--   viewer / Viewer@2026    → 角色 VIEWER
-- =====================================================================

CREATE TABLE IF NOT EXISTS users (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(64)  NOT NULL UNIQUE,
    password_hash  VARCHAR(100) NOT NULL,
    role           VARCHAR(16)  NOT NULL,
    enabled        TINYINT(1)   NOT NULL DEFAULT 1,
    -- 令牌版本：登出或禁用时 +1，旧 token 里的 ver 对不上即失效
    token_version  INT          NOT NULL DEFAULT 0,
    created_at_ms  BIGINT       NOT NULL,
    last_login_ms  BIGINT       NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

INSERT INTO users (username, password_hash, role, enabled, token_version, created_at_ms)
VALUES ('admin', '$2b$10$SaUbUnIFz.uiviaNWK5QFuK6IuiDaFzedl3pWdPq/WuKAlWd01.fG', 'ADMIN', 1, 0, 1789862400000),
       ('viewer', '$2b$10$IYYjJ6en2gDdlSt8c6h1C.9WQkJPBdMcNSF/9caO8DL4ql4MU0mD.', 'VIEWER', 1, 0, 1789862400000)
ON DUPLICATE KEY UPDATE username = username;
