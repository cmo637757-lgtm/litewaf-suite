package com.litewaf.platform.blocklist;

import com.fasterxml.jackson.databind.JsonNode;
import com.litewaf.platform.engine.EngineClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 自动封禁：红色告警触发后，把来源 IP 写进引擎黑名单（执行器 /blocklist → blacklist.conf → reload）。
 *
 * <p>三层数据结构：
 * <ul>
 *   <li>引擎侧 blacklist.conf：真正生效的名单，由执行器原子写 + reload 生效；</li>
 *   <li>仓库表 blocklist：谁、什么时候、因为哪条告警被封的审计记录；</li>
 *   <li>解封：删表记录（active=0）+ 调执行器 remove。</li>
 * </ul>
 *
 * <p>失败一律吞掉记日志：告警本身比封禁重要，不能因为引擎不在线把告警链路带崩。
 */
@Service
public class BlocklistService {

    private static final Logger log = LoggerFactory.getLogger(BlocklistService.class);

    private final JdbcTemplate jdbc;
    private final EngineClient engine;

    public BlocklistService(JdbcTemplate jdbc, EngineClient engine) {
        this.jdbc = jdbc;
        this.engine = engine;
    }

    /** 列表项：封禁中 + 最近解除的（各取一部分，前端合起来展示）。 */
    public record Entry(long id, String clientIp, String reason, Long alertId, String ruleName,
                        long createdAtMs, Long releasedAtMs, boolean active) {}

    public List<Entry> list(int limit) {
        return jdbc.query(
                "SELECT id, client_ip, reason, alert_id, rule_name, created_at_ms, released_at_ms, active "
                        + "FROM blocklist ORDER BY active DESC, created_at_ms DESC LIMIT ?",
                (rs, i) -> new Entry(
                        rs.getLong("id"), rs.getString("client_ip"), rs.getString("reason"),
                        (Long) rs.getObject("alert_id"), rs.getString("rule_name"),
                        rs.getLong("created_at_ms"),
                        (Long) rs.getObject("released_at_ms"),
                        rs.getInt("active") == 1),
                Math.max(1, Math.min(limit, 200)));
    }

    public int activeCount() {
        Integer n = jdbc.queryForObject("SELECT COUNT(*) FROM blocklist WHERE active = 1", Integer.class);
        return n == null ? 0 : n;
    }

    public boolean isActive(String ip) {
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM blocklist WHERE client_ip = ? AND active = 1", Integer.class, ip);
        return n != null && n > 0;
    }

    /** 红色告警触发时调用。已经封过就直接返回 false（不重复写）。 */
    public boolean block(String ip, String reason, Long alertId, String ruleName) {
        if (ip == null || ip.isBlank() || isActive(ip)) {
            return false;
        }
        long now = System.currentTimeMillis();
        try {
            jdbc.update("INSERT INTO blocklist (client_ip, reason, alert_id, rule_name, created_at_ms, active) "
                            + "VALUES (?, ?, ?, ?, ?, 1)",
                    ip, reason, alertId, ruleName, now);
        } catch (org.springframework.dao.DuplicateKeyException e) {
            // 并发下别人刚插过，视为已封
            return false;
        }
        try {
            JsonNode resp = engine.post("/blocklist", Map.of("ip", ip, "action", "add"));
            log.info("blocked {} -> {}", ip, resp);
        } catch (RuntimeException e) {
            log.warn("写引擎黑名单失败（保留审计记录，稍后可重试）：{} {}", ip, e.getMessage());
        }
        return true;
    }

    /** 解封：引擎侧先删，成功后再改表；引擎不可用也允许改表（下次启动以表为准可补写）。 */
    public boolean unblock(String ip) {
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM blocklist WHERE client_ip = ? AND active = 1", Integer.class, ip);
        if (n == null || n == 0) {
            return false;
        }
        try {
            engine.post("/blocklist", Map.of("ip", ip, "action", "remove"));
        } catch (RuntimeException e) {
            log.warn("解封时调执行器失败（仍标记解除）：{} {}", ip, e.getMessage());
        }
        jdbc.update("UPDATE blocklist SET active = 0, released_at_ms = ? WHERE client_ip = ? AND active = 1",
                System.currentTimeMillis(), ip);
        return true;
    }

    /** 启动时把表里仍 active 的 IP 重新写回引擎（引擎黑名单文件丢了/被清空时自愈）。 */
    public void resyncOnStartup() {
        List<String> ips = jdbc.queryForList(
                "SELECT client_ip FROM blocklist WHERE active = 1", String.class);
        if (ips.isEmpty()) {
            return;
        }
        try {
            for (String ip : ips) {
                engine.post("/blocklist", Map.of("ip", ip, "action", "add"));
            }
            log.info("启动同步黑名单 {} 条", ips.size());
        } catch (RuntimeException e) {
            log.warn("启动同步黑名单失败：{}", e.getMessage());
        }
    }
}
