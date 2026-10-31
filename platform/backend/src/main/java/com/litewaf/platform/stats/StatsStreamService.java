package com.litewaf.platform.stats;

import com.litewaf.platform.events.EventDtos.EventItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * SSE 推送：把「最近拦截事件」实时推给页面，替掉 10 秒一次的轮询。
 *
 * <p>为什么只推 recent 而不是整页数据：
 * <ul>
 *   <li>KPI/趋势要按用户选的窗口算，服务端不知道每个页面选了什么窗口</li>
 *   <li>推「最新事件 id」当信号，变了前端才去拉一次全量，没变化就零开销</li>
 * </ul>
 *
 * <p>连接管理：{@link SseEmitter} 不设超时（客户端断开靠 onError/onCompletion 清理），
 * 每次 tick 推一个 {@code tick} 事件；发送失败的 emitter 立刻移除，避免死连接堆积。
 */
@Service
public class StatsStreamService {

    private static final Logger log = LoggerFactory.getLogger(StatsStreamService.class);

    private final StatsService stats;
    private final JdbcTemplate jdbc;
    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public StatsStreamService(StatsService stats, JdbcTemplate jdbc) {
        this.stats = stats;
        this.jdbc = jdbc;
    }

    /** 新连接：立刻推一帧，前端不用等第一个 tick 就有数据。 */
    public SseEmitter subscribe() {
        SseEmitter emitter = new SseEmitter(0L);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(ex -> emitters.remove(emitter));
        emitters.add(emitter);
        try {
            emitter.send(SseEmitter.event().name("tick").data(snapshot()));
        } catch (Exception ex) {
            emitters.remove(emitter);
        }
        log.debug("SSE 连接建立，当前连接数 {}", emitters.size());
        return emitter;
    }

    /** 每 2 秒推一帧；没有连接时直接返回，不查库。 */
    @Scheduled(fixedDelayString = "${app.stream.interval-ms:2000}")
    public void tick() {
        if (emitters.isEmpty()) {
            return;
        }
        Map<String, Object> payload = snapshot();
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name("tick").data(payload));
            } catch (Exception ex) {
                emitters.remove(emitter);
            }
        }
    }

    public int connections() {
        return emitters.size();
    }

    private Map<String, Object> snapshot() {
        List<EventItem> recent = stats.recent(8);
        Long latestId = recent.isEmpty() ? null : recent.get(0).id();
        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM waf_events", Long.class);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("as_of", System.currentTimeMillis());
        data.put("latest_id", latestId);
        data.put("total_events", total);
        data.put("recent", recent);
        return data;
    }
}
