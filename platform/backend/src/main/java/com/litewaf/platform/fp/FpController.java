package com.litewaf.platform.fp;

import com.litewaf.platform.fp.FpDtos.Mark;
import com.litewaf.platform.fp.FpDtos.MarkPage;
import com.litewaf.platform.fp.FpDtos.MarkRequest;
import com.litewaf.platform.fp.FpDtos.Metrics;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 误报标记与调优闭环的读接口（R34-10）。
 *
 * <p>权限：读接口 viewer 也能看；写接口（POST/DELETE /api/events/{id}/mark）
 * 统一落在 SecurityConfig 的 "POST/DELETE 一律 ADMIN" 规则下，不需要单独声明。
 */
@RestController
@RequestMapping("/api")
public class FpController {

    private final FpRepository repo;

    public FpController(FpRepository repo) {
        this.repo = repo;
    }

    /**
     * 给一条拦截事件打标记。
     *
     * <p>body: {@code {"decision":"confirmed"|"rejected","remark":"..."}}
     * <p>同一个事件重复提交只覆盖判定，不新增记录（卡片要求"重复提交返回同标记"）。
     */
    @PostMapping("/events/{id}/mark")
    public Mark mark(@PathVariable long id, @RequestBody MarkRequest body, Authentication auth) {
        String decision = body == null ? null : body.decision();
        if (!"confirmed".equals(decision) && !"rejected".equals(decision)) {
            throw new IllegalArgumentException("decision 只能是 confirmed 或 rejected");
        }
        if (!repo.eventExists(id)) {
            throw new EventNotFoundException(id);
        }
        String remark = body.remark() == null ? "" : body.remark().trim();
        if (remark.length() > 500) {
            throw new IllegalArgumentException("remark 不能超过 500 字");
        }
        String operator = auth != null ? auth.getName() : "anonymous";
        return repo.upsert(id, decision, operator, remark);
    }

    /** 撤销标记（标记错了可以退回"未复核"），返回 204。 */
    @DeleteMapping("/events/{id}/mark")
    public ResponseEntity<Void> clear(@PathVariable long id) {
        repo.clear(id);
        return ResponseEntity.noContent().build();
    }

    /** 查某个事件当前标记；没有标记时返回 204，前端不必区分 null 与空对象。 */
    @GetMapping("/events/{id}/mark")
    public ResponseEntity<Mark> get(@PathVariable long id) {
        Mark m = repo.byEvent(id);
        return m == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(m);
    }

    /** 三个指标。from/to 缺省表示全量。 */
    @GetMapping("/fp/metrics")
    public Metrics metrics(@RequestParam(required = false) Long from,
                           @RequestParam(required = false) Long to) {
        if (from != null && to != null && from >= to) {
            throw new IllegalArgumentException("窗口起点必须小于终点（闭开区间 [from, to)）");
        }
        return repo.metrics(from, to);
    }

    /** 标记列表，最近更新的在前。 */
    @GetMapping("/fp/marks")
    public MarkPage marks(@RequestParam(required = false) Long from,
                          @RequestParam(required = false) Long to,
                          @RequestParam(required = false) String decision,
                          @RequestParam(defaultValue = "1") int page,
                          @RequestParam(name = "page_size", defaultValue = "20") int pageSize) {
        int p = Math.max(page, 1);
        int s = Math.min(Math.max(pageSize, 1), 200);
        return repo.list(from, to, decision, p, s);
    }

    /** 标记一个不存在的事件时给 404，而不是静默写一条悬空记录。 */
    public static class EventNotFoundException extends RuntimeException {
        public EventNotFoundException(long id) {
            super("事件不存在：" + id);
        }
    }
}
