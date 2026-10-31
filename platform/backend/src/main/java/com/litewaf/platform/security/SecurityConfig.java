package com.litewaf.platform.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;

/**
 * 安全规则：两级角色 + Bearer Token。
 *
 * <p>权限矩阵（对应需求卡片 R34-06）：
 * <ul>
 *   <li>未登录 → 401，任何业务接口都进不来</li>
 *   <li>VIEWER → 只读：统计、事件列表与详情</li>
 *   <li>ADMIN  → 读写：所有 POST（改规则、CC 参数、发布、回退、标误报、告警处置）</li>
 * </ul>
 *
 * <p>写操作全部收敛到 POST /api/** 一条规则下，新加的写接口默认就是 ADMIN，
 * 不会因为忘了配置而裸奔——这比逐个接口授权更安全。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtFilter;
    private final ObjectMapper json;

    public SecurityConfig(JwtAuthFilter jwtFilter, ObjectMapper json) {
        this.jwtFilter = jwtFilter;
        this.json = json;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 纯 API、无 Cookie 会话，CSRF 无意义
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/logout").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/auth/me").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/stats/**", "/api/events/**",
                                "/api/alerts/**", "/api/alert-rules/**", "/api/fp/**",
                                "/api/evaluations/**", "/api/collector/**", "/api/perf/**")
                        .hasAnyRole("ADMIN", "VIEWER")
                        .requestMatchers(HttpMethod.POST, "/api/rules/test")
                        .hasAnyRole("ADMIN", "VIEWER")
                        .requestMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN")
                        // 写操作不止 POST：撤销误报标记走 DELETE，同样只有 ADMIN 能点
                        .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) ->
                                writeError(res, 401, "UNAUTHORIZED", "未登录或 token 已失效"))
                        .accessDeniedHandler((req, res, ex) ->
                                writeError(res, 403, "FORBIDDEN", "当前账号没有该操作权限")))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private void writeError(HttpServletResponse res, int status, String code, String message) {
        res.setStatus(status);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.setCharacterEncoding("UTF-8");
        try {
            json.writeValue(res.getWriter(), Map.of(
                    "error_code", code,
                    "message", message,
                    "request_id", Integer.toHexString((int) (System.nanoTime() & 0xffffff))));
        } catch (Exception ignored) {
            // 响应流已关闭时无能为力，交给容器
        }
    }

    /** 口令哈希用 BCrypt，10 轮（与 sql/users.sql 里的哈希一致） */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
