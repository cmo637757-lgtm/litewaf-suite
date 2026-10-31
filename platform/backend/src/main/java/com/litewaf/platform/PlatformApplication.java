package com.litewaf.platform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * LiteWAF 平台后端入口。
 *
 * <p>职责边界（S3）：只读统计 + 配置管理 + 操作审计，**不做**请求检测——
 * 检测由 C 模块在 nginx 里完成，线上流量不经过这里。
 *
 * <p>S6 起开启定时任务：告警消费（2 秒）/ 失败投递重试（10 秒），见 alert.AlertWorker。
 */
@SpringBootApplication
@EnableScheduling
public class PlatformApplication {

    public static void main(String[] args) {
        SpringApplication.run(PlatformApplication.class, args);
    }
}
