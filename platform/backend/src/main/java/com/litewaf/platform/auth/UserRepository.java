package com.litewaf.platform.auth;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 账号读写。
 *
 * <p>角色只有两个：{@code ADMIN} / {@code VIEWER}。
 * 不做注册接口（需求卡片 R34-06 要求移除公开注册），账号由 SQL 脚本初始化。
 */
@Repository
public class UserRepository {

    /** 账号行；passwordHash 只在登录时用，不往外返回 */
    public record UserRow(int id, String username, String passwordHash,
                          String role, boolean enabled, int tokenVersion) {
    }

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public UserRow findByUsername(String username) {
        List<UserRow> rows = jdbc.query(
                "SELECT id, username, password_hash, role, enabled, token_version "
                        + "FROM users WHERE username = ?",
                (rs, i) -> new UserRow(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password_hash"),
                        rs.getString("role"),
                        rs.getBoolean("enabled"),
                        rs.getInt("token_version")),
                username);
        return rows.isEmpty() ? null : rows.get(0);
    }

    public void touchLogin(String username) {
        jdbc.update("UPDATE users SET last_login_ms = ? WHERE username = ?",
                System.currentTimeMillis(), username);
    }

    /** 登出：版本 +1，此前签发的所有 token 立即失效 */
    public void bumpTokenVersion(String username) {
        jdbc.update("UPDATE users SET token_version = token_version + 1 WHERE username = ?", username);
    }
}
