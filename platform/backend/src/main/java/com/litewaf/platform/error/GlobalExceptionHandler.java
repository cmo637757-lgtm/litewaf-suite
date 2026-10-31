package com.litewaf.platform.error;

import jakarta.servlet.http.HttpServletRequest;
import com.litewaf.platform.auth.AuthController;
import com.litewaf.platform.engine.EngineClient;
import com.litewaf.platform.security.LoginRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.util.Map;
import java.util.UUID;

/**
 * 统一错误体：{@code {"error_code": "...", "message": "...", "request_id": "..."}}。
 *
 * <p>为什么要 request_id：报错时用户只截一张图，靠这个 id 能在日志里把整条请求捞出来，
 * 不然「500 了」根本没法查。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException ex) {
        return body(HttpStatus.BAD_REQUEST, "BAD_REQUEST", ex.getMessage());
    }

    /** 账号或口令错误：统一 401，不区分「用户不存在」和「口令错」，避免账号探测 */
    @ExceptionHandler(AuthController.BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> badCredentials(AuthController.BadCredentialsException ex) {
        return body(HttpStatus.UNAUTHORIZED, "BAD_CREDENTIALS", ex.getMessage());
    }

    /** 连续失败 5 次后的 15 分钟锁定 */
    @ExceptionHandler(LoginRateLimiter.RateLimitedException.class)
    public ResponseEntity<Map<String, Object>> rateLimited(LoginRateLimiter.RateLimitedException ex) {
        return body(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_ATTEMPTS", ex.getMessage());
    }

    /** 函数参数上的 @Min/@Max 校验失败（如 bucket_s=5 低于下限） */
    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<Map<String, Object>> methodValidation(HandlerMethodValidationException ex) {
        String msg = ex.getAllErrors().stream()
                .map(MessageSourceResolvable::getDefaultMessage)
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElse("参数超出允许范围");
        return body(HttpStatus.BAD_REQUEST, "INVALID_PARAM", msg);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> missingParam(MissingServletRequestParameterException ex) {
        return body(HttpStatus.BAD_REQUEST, "MISSING_PARAM", ex.getParameterName() + " 是必填参数");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalid(MethodArgumentNotValidException ex) {
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(e -> e.getField() + " " + e.getDefaultMessage())
                .orElse("参数校验失败");
        return body(HttpStatus.BAD_REQUEST, "INVALID_PARAM", msg);
    }

    /** 执行器没起来 / 令牌不对 / 调用超时：503，让前端提示「引擎通道不可用」而不是 500 */
    @ExceptionHandler(EngineClient.EngineUnavailableException.class)
    public ResponseEntity<Map<String, Object>> engineDown(EngineClient.EngineUnavailableException ex) {
        return body(HttpStatus.SERVICE_UNAVAILABLE, "ENGINE_UNAVAILABLE", ex.getMessage());
    }

    /** 告警 id 不存在 */
    @ExceptionHandler(com.litewaf.platform.alert.AlertController.AlertNotFoundException.class)
    public ResponseEntity<Map<String, Object>> alertNotFound(
            com.litewaf.platform.alert.AlertController.AlertNotFoundException ex) {
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", ex.getMessage());
    }

    /** 打标记的事件 id 不存在 */
    @ExceptionHandler(com.litewaf.platform.fp.FpController.EventNotFoundException.class)
    public ResponseEntity<Map<String, Object>> eventNotFound(
            com.litewaf.platform.fp.FpController.EventNotFoundException ex) {
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", ex.getMessage());
    }

    /** 评估跑次不存在（目录被删或 run_id 写错） */
    @ExceptionHandler(com.litewaf.platform.evaluation.EvaluationNotFoundException.class)
    public ResponseEntity<Map<String, Object>> evaluationNotFound(
            com.litewaf.platform.evaluation.EvaluationNotFoundException ex) {
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception ex, HttpServletRequest req) {
        String rid = UUID.randomUUID().toString().substring(0, 8);
        log.error("未捕获异常 request_id={} uri={}", rid, req.getRequestURI(), ex);
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR",
                "服务内部错误，请把 request_id 报给管理员", rid);
    }

    private ResponseEntity<Map<String, Object>> body(HttpStatus status, String code, String message) {
        return body(status, code, message, UUID.randomUUID().toString().substring(0, 8));
    }

    private ResponseEntity<Map<String, Object>> body(HttpStatus status, String code,
                                                     String message, String requestId) {
        return ResponseEntity.status(status).body(Map.of(
                "error_code", code,
                "message", message == null ? "" : message,
                "request_id", requestId));
    }
}
