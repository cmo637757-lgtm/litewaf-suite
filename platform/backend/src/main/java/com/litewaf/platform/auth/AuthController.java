package com.litewaf.platform.auth;

import com.litewaf.platform.auth.UserRepository.UserRow;
import com.litewaf.platform.security.JwtService;
import com.litewaf.platform.security.LoginRateLimiter;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 登录与登出。
 *
 * <p>用 Bearer Token 而不是 Cookie：Cookie 会自动带上，得额外防 CSRF；
 * Token 放请求头，前端自己保管，攻击面更小（需求卡片 R34-06 的取舍）。
 *
 * <p>初始账号见 {@code sql/users.sql} 顶部注释；口令是哈希，源码里没有明文。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }

    public record LoginResponse(String token, String role, long expires_in) {
    }

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final LoginRateLimiter limiter;

    public AuthController(UserRepository users, PasswordEncoder encoder,
                          JwtService jwt, LoginRateLimiter limiter) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.limiter = limiter;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest req) {
        String name = req.username().trim();
        limiter.ensureAllowed(name);

        UserRow user = users.findByUsername(name);
        // 用户不存在也走一次假校验，避免用响应时间判断账号是否存在
        boolean ok = (user != null)
                && user.enabled()
                && encoder.matches(req.password(), user.passwordHash());

        if (!ok) {
            limiter.onFailure(name);
            log.info("登录失败 username={}", name);
            throw new BadCredentialsException("用户名或口令不正确");
        }

        limiter.onSuccess(name);
        users.touchLogin(name);
        log.info("登录成功 username={} role={}", name, user.role());
        return new LoginResponse(jwt.issue(user.username(), user.role(), user.tokenVersion()),
                user.role(), jwt.ttlSeconds());
    }

    /**
     * 登出：把 token_version +1。
     *
     * <p>不是「把 token 加黑名单」——那样要存一份表还得清理过期项；
     * 版本号一句话就让该账号所有旧 token 作废，也顺带支持「禁用账号」。
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(Authentication auth) {
        if (auth != null && auth.getName() != null) {
            users.bumpTokenVersion(auth.getName());
        }
        return ResponseEntity.ok(Map.of("result", "logged_out"));
    }

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        String name = (auth == null) ? null : auth.getName();
        String role = (auth == null) ? null : auth.getAuthorities().stream()
                .findFirst().map(a -> a.getAuthority().replace("ROLE_", "")).orElse(null);
        return Map.of("username", name, "role", role);
    }

    /** 凭证错误（控制器内抛，由全局异常处理映射成 401） */
    public static class BadCredentialsException extends RuntimeException {
        public BadCredentialsException(String message) {
            super(message);
        }
    }
}
