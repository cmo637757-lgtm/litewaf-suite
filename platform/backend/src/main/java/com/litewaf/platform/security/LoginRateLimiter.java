package com.litewaf.platform.security;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录失败限流：同一账号连续失败 5 次，锁 15 分钟。
 *
 * <p>为什么按账号而不是按 IP：本机演示场景下 IP 都是同一条回环，
 * 按 IP 会把正常用户一起锁掉；按账号更贴近「撞库」的真实威胁。
 *
 * <p>状态放内存：单实例部署，重启清零是可接受的——重启本身就需要管理员操作。
 */
@Component
public class LoginRateLimiter {

    private static final int MAX_FAILS = 5;
    private static final long LOCK_MS = 15 * 60_000L;

    private record State(int fails, long lockedUntilMs) {
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();

    /** 登录前调用：还在锁定期就抛异常（由控制器转 429） */
    public void ensureAllowed(String username) {
        State s = states.get(username);
        if (s == null) {
            return;
        }
        if (s.lockedUntilMs() > System.currentTimeMillis()) {
            long left = (s.lockedUntilMs() - System.currentTimeMillis()) / 1000L;
            throw new RateLimitedException("登录失败次数过多，请 " + (left + 1) + " 秒后再试");
        }
    }

    /** 登录失败：累计到 5 次就锁定 */
    public void onFailure(String username) {
        states.compute(username, (k, old) -> {
            int fails = (old == null) ? 0 : old.fails();
            fails += 1;
            long until = (fails >= MAX_FAILS) ? System.currentTimeMillis() + LOCK_MS : 0L;
            return new State(fails, until);
        });
    }

    /** 登录成功：清零计数 */
    public void onSuccess(String username) {
        states.remove(username);
    }

    /** 限流命中（控制器映射成 429 Too Many Requests） */
    public static class RateLimitedException extends RuntimeException {
        public RateLimitedException(String message) {
            super(message);
        }
    }
}
