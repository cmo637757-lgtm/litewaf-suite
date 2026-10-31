package com.litewaf.platform.perf;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** 把耗时拦截器挂到 /api/** 上；静态资源与 /api/health 不统计（探活太频繁会稀释样本）。 */
@Configuration
public class PerfWebConfig implements WebMvcConfigurer {

    private final ApiTimingInterceptor timing;

    public PerfWebConfig(ApiTimingInterceptor timing) {
        this.timing = timing;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(timing)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/health");
    }
}
