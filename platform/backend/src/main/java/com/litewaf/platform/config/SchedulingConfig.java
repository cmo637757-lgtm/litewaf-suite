package com.litewaf.platform.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * 调度线程池。
 *
 * 默认 @Scheduled 只有一个线程：告警消费（每 2 秒）和投递重试（每 10 秒）会互相排队，
 * 一次 webhook 重试最长要 5 秒（连接 2 秒 + 总 5 秒），期间消费被卡住，
 * 页面上表现就是"事件进来了但告警迟迟不触发"。
 *
 * 这里固定 2 个线程：一个管消费、一个管重试，互不影响。
 */
@Configuration
public class SchedulingConfig implements SchedulingConfigurer {

    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(2);
        scheduler.setThreadNamePrefix("lwaf-sched-");
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        scheduler.setAwaitTerminationSeconds(5);
        scheduler.initialize();
        registrar.setTaskScheduler(scheduler);
    }
}
