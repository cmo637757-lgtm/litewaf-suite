package com.litewaf.platform.rules;

import java.util.List;
import java.util.Map;

/**
 * 规则与发布相关的 DTO。
 *
 * <p>字段全部用 record，Jackson 统一输出 snake_case（见 application.yml），
 * 与前端和需求卡片里的字段名保持一致。
 */
public final class RulesDtos {

    private RulesDtos() {
    }

    /** 当前生效规则 + CC 参数 + hash。 */
    public record Current(String text, String hash, Map<String, Integer> cc) {
    }

    /** 检查请求：规则全文 + 可选 CC 参数。 */
    public record CheckRequest(String rules, Map<String, Integer> cc, String name) {
    }

    /** 检查结果。candidate_id 只在 ok=true 时有效，发布时要用它。 */
    public record CheckResult(boolean ok, String candidateId, String hash, Integer bytes,
                              Map<String, Integer> cc, String engineOutput, String error,
                              String lineNo) {
    }

    /** 发布/回退结果。 */
    public record PublishResult(boolean ok, String version, String previous,
                                Map<String, Integer> cc, Map<String, Object> probe,
                                String reloadOutput, String error,
                                String operationId) {
    }

    /** 版本列表项。 */
    public record VersionItem(String version, String kind, String hash, Integer bytes,
                              Map<String, Integer> cc, String createdAt, String previous) {
    }

    /** 执行器整体状态。 */
    public record EngineStatus(String current, String previous, Map<String, Integer> cc,
                               boolean nginxAlive, int marker, int normal, int sqli,
                               List<VersionItem> versions) {
    }
}
