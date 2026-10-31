package com.litewaf.platform.alert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 告警后台线程：每 2 秒消费一批新事件，每 10 秒重试失败的 Webhook。
 *
 * 为什么用 @Scheduled 而不是独立进程：单机部署、事件量小（10 万行级别），
 * 一个线程足够；好处是随平台一起启停，不用额外维护守护进程。
 */
@Component
public class AlertWorker {

    private static final Logger log = LoggerFactory.getLogger(AlertWorker.class);

    private final AlertService service;

    public AlertWorker(AlertService service) {
        this.service = service;
    }

    /** 消费新事件。fixedDelay 保证上一批跑完再等 2 秒，不会堆积。 */
    @Scheduled(fixedDelay = 2000L, initialDelay = 3000L)
    public void consume() {
        try {
            int n = service.consumeOnce();
            if (n > 0) {
                log.debug("消费了 {} 条事件", n);
            }
        } catch (Exception e) {                       // noqa: BLE001 —— 消费失败不能让调度线程挂掉
            log.warn("告警消费失败：{}", e.toString());
        }
    }

    /** 重试失败投递。 */
    @Scheduled(fixedDelay = 10_000L, initialDelay = 12_000L)
    public void retry() {
        try {
            service.retryDue();
        } catch (Exception e) {                       // noqa: BLE001
            log.warn("告警重试失败：{}", e.toString());
        }
    }
}
