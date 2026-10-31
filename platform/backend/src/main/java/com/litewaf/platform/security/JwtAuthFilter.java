package com.litewaf.platform.security;

import com.litewaf.platform.auth.UserRepository;
import com.litewaf.platform.auth.UserRepository.UserRow;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Bearer Token 鉴权过滤器。
 *
 * <p>流程：取 {@code Authorization: Bearer xxx} → 验签与过期 → 查库确认账号仍启用、
 * token 版本未变 → 放进 SecurityContext。任何一步失败都只是「没登录」，
 * 由 SecurityConfig 的 entryPoint 统一回 401，不在这里直接写响应。
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwt;
    private final UserRepository users;

    public JwtAuthFilter(JwtService jwt, UserRepository users) {
        this.jwt = jwt;
        this.users = users;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = bearerToken(request);
        if (token == null) {
            token = queryToken(request);
        }
        if (token != null) {
            authenticate(token);
        }
        chain.doFilter(request, response);
    }

    private String bearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /**
     * SSE 兜底：浏览器 {@code EventSource} 不能设请求头，只能 {@code ?token=}。
     *
     * <p>只对 {@code /api/stats/stream} 生效——不要全局放开，否则 token 会进各种
     * 访问日志和 Referer，等于把凭据散出去。
     */
    private String queryToken(HttpServletRequest request) {
        if (!"/api/stats/stream".equals(request.getRequestURI())) {
            return null;
        }
        String token = request.getParameter("token");
        if (token == null) {
            return null;
        }
        token = token.trim();
        return token.isEmpty() ? null : token;
    }

    private void authenticate(String token) {
        try {
            Claims claims = jwt.parse(token);
            String username = claims.getSubject();
            Integer ver = claims.get("ver", Integer.class);

            UserRow user = users.findByUsername(username);
            if (user == null || !user.enabled() || ver == null || ver != user.tokenVersion()) {
                return; // 账号被禁用 / 已登出 / 不存在 → 保持未认证
            }

            var auth = new UsernamePasswordAuthenticationToken(
                    username, null, List.of(new SimpleGrantedAuthority("ROLE_" + user.role())));
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception ex) {
            // 过期、签名不对、格式错都走这里；debug 级别，避免被刷日志
            log.debug("token 校验失败：{}", ex.getMessage());
        }
    }
}
