package com.litewaf.platform.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 引擎执行器客户端。
 *
 * <p>平台后端本身**不碰 nginx、不碰配置文件**：所有「动手」都转发给 engine-exec，
 * 由它做参数白名单校验、原子替换和发布后探测。这样即使后端被拿下，
 * 攻击者也只能发出 check / publish / rollback 三个受限动作，拿不到 shell。
 *
 * <p>令牌从文件读取（600 权限，只有 root 可读；后端以 root 或同组用户运行），
 * 每次调用现读，避免改了令牌还需要重启后端。
 */
@Component
public class EngineClient {

    private static final Logger log = LoggerFactory.getLogger(EngineClient.class);

    private final String baseUrl;
    private final Path tokenFile;
    private final Duration timeout;
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public EngineClient(@Value("${app.engine.base-url}") String baseUrl,
                        @Value("${app.engine.token-file}") String tokenFile,
                        @Value("${app.engine.timeout-seconds:30}") long timeoutSeconds) {
        this.baseUrl = baseUrl;
        this.tokenFile = Path.of(tokenFile);
        this.timeout = Duration.ofSeconds(timeoutSeconds);
    }

    /** 读执行器令牌；读不到就抛出，让上层返回 503 而不是静默跳过。 */
    private String token() {
        try {
            return Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new EngineUnavailableException("读取执行器令牌失败：" + e.getMessage());
        }
    }

    /** GET 请求，返回解析后的 JSON 树。 */
    public JsonNode get(String path) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("X-Engine-Token", token())
                .GET()
                .build();
        return send(req);
    }

    /** POST 请求，body 为可序列化对象。 */
    public JsonNode post(String path, Object body) {
        String json;
        try {
            json = mapper.writeValueAsString(body);
        } catch (Exception e) {
            throw new IllegalStateException("请求体序列化失败", e);
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("X-Engine-Token", token())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();
        return send(req);
    }

    private JsonNode send(HttpRequest req) {
        try {
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() == 401) {
                throw new EngineUnavailableException("执行器拒绝令牌（401），检查 engine.token 是否一致");
            }
            if (resp.statusCode() >= 400) {
                log.warn("执行器返回 {}：{}", resp.statusCode(), resp.body());
                throw new EngineUnavailableException("执行器返回 HTTP " + resp.statusCode());
            }
            return mapper.readTree(resp.body());
        } catch (EngineUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new EngineUnavailableException("调用执行器失败：" + e.getMessage());
        }
    }

    /** 执行器状态：当前/上一版本、CC 参数、存活与探测结果。 */
    public JsonNode status() {
        return get("/status");
    }

    /** 当前生效的规则全文。 */
    public JsonNode currentRules() {
        return get("/rules");
    }

    /** 语法校验（只校验，不生效）。cc 可为 null。 */
    public JsonNode check(String rules, Map<String, Integer> cc, String name) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("rules", rules);
        body.put("name", name);
        if (cc != null) {
            body.put("cc", cc);
        }
        return post("/check", body);
    }

    /** 发布候选版本。 */
    public JsonNode publish(String candidateId) {
        return post("/publish", Map.of("candidate_id", candidateId));
    }

    /** 回退到上一版本。 */
    public JsonNode rollback() {
        return post("/rollback", Map.of());
    }

    /** 执行器不可用（未启动、令牌错、超时）。 */
    public static class EngineUnavailableException extends RuntimeException {
        public EngineUnavailableException(String message) {
            super(message);
        }
    }
}
