package com.litewaf.platform.events;

import com.litewaf.platform.events.EventDtos.EventItem;
import com.litewaf.platform.events.EventDtos.PageResult;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 事件检索接口（需求卡片第六章）。
 *
 * <p>示例：
 * <pre>
 * GET /api/events?from=1789862400000&amp;to=1789862460000
 * GET /api/events?ip=10.0.0.10&amp;category=SQLi&amp;page=1&amp;page_size=20
 * GET /api/events/1
 * </pre>
 *
 * <p>URI 里带 {@code <script>} 也只是文本——查询本身参数化，返回 JSON 由 Jackson 转义，
 * 页面渲染时必须用 textContent 而不是 innerHTML（这条在前端同样要求）。
 */
@RestController
@RequestMapping("/api/events")
public class EventsController {

    private final EventsService events;

    public EventsController(EventsService events) {
        this.events = events;
    }

    @GetMapping
    public PageResult<EventItem> list(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String uri,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(name = "page_size", defaultValue = "20") @Min(1) @Max(200) int pageSize,
            @RequestParam(defaultValue = "time") String sortby,
            @RequestParam(defaultValue = "desc") String order) {

        if (from != null && to != null && from >= to) {
            throw new IllegalArgumentException("窗口起点必须小于终点（闭开区间 [from, to)）");
        }
        String sort = EventsService.isSortable(sortby) ? sortby : "time";
        return events.search(from, to, ip, category, uri, page, pageSize, sort, order);
    }

    @GetMapping("/{id}")
    public ResponseEntity<EventItem> detail(@PathVariable long id) {
        EventItem item = events.byId(id);
        return (item == null) ? ResponseEntity.notFound().build() : ResponseEntity.ok(item);
    }
}
