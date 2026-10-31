/**
 * @file lwaf_rule_engine.h
 * @brief LiteWAF-NGX member-B rule engine public API.
 *
 * This header contains the modules owned by member B in the design documents:
 * rule syntax parsing, request-zone extraction helpers, string/regular
 * expression matching, score accumulation, and final score-threshold decision.
 *
 * The API intentionally avoids direct Nginx types so it can be compiled and
 * tested as a normal C library. Member A can adapt Nginx request fields into
 * ::lwaf_request_context_t, while member C can serialize ::lwaf_score_result_t
 * into JSON audit logs.
 */

#ifndef LWAF_RULE_ENGINE_H
#define LWAF_RULE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of detection zones attached to one rule. */
#define LWAF_MAX_RULE_ZONES 8u

/** Maximum number of per-request rule matches kept for logging. */
#define LWAF_MAX_MATCHES 64u

/** Maximum length of a normalized request-zone buffer. */
#define LWAF_MAX_ZONE_TEXT 4096u

/**
 * @brief 单条规则在一次请求里最多按几次命中计分。
 *
 * 为什么需要这个上限：打分器原来「一条规则命中一次」只加一份分，
 * 于是 `SELECT * FROM users` 虽然同时含 select 和 from，却可能刚好卡在
 * 阈值下面被放行。改成按命中次数计分后，既要让重复命中真正累加分，
 * 又不能让攻击者用 1000 个关键字把分数刷到溢出——所以封顶 3 次。
 */
#define LWAF_MAX_HITS_PER_RULE 3u

/**
 * @brief Detection zones supported by the MVP rule engine.
 */
typedef enum lwaf_zone_e {
    LWAF_ZONE_URL = 0,        /**< Normalized URI path, without query string. */
    LWAF_ZONE_ARGS,           /**< Normalized query string. */
    LWAF_ZONE_BODY,           /**< Optional normalized form body. */
    LWAF_ZONE_HEADERS,        /**< Concatenated normalized selected headers. */
    LWAF_ZONE_COOKIE,         /**< Normalized Cookie header. */
    LWAF_ZONE_USER_AGENT,     /**< Normalized User-Agent header. */
    LWAF_ZONE_FILE_EXT,       /**< Lowercase file extension derived from URI. */
    LWAF_ZONE_UNKNOWN         /**< Sentinel for parser validation failures. */
} lwaf_zone_t;

/**
 * @brief Rule matching algorithm.
 */
typedef enum lwaf_match_type_e {
    LWAF_MATCH_STR = 0,       /**< Case-insensitive substring match. */
    LWAF_MATCH_RX             /**< PCRE2 regular expression match. */
} lwaf_match_type_t;

/**
 * @brief Rule action executed when a match is found.
 */
typedef enum lwaf_action_e {
    LWAF_ACT_SCORE = 0,       /**< Add score and decide after all rules run. */
    LWAF_ACT_BLOCK,           /**< Block immediately on first hit. */
    LWAF_ACT_LOG              /**< Record hit without blocking or scoring. */
} lwaf_action_t;

/**
 * @brief Score categories inspired by NAXSI and CRS anomaly scoring.
 */
typedef enum lwaf_score_category_e {
    LWAF_SQL = 0,             /**< SQL injection indicators. */
    LWAF_XSS,                 /**< Cross-site scripting indicators. */
    LWAF_RFI,                 /**< Remote file inclusion indicators. */
    LWAF_TRAVERSAL,           /**< Path traversal indicators. */
    LWAF_EVADE,               /**< Encoding/evasion indicators. */
    LWAF_UPLOAD,              /**< Dangerous upload indicators. */
    LWAF_SCAN,                /**< Scanner or automation indicators. */
    LWAF_TOTAL,               /**< Aggregate score bucket. */
    LWAF_SCORE_CATEGORY_COUNT /**< Number of score buckets. */
} lwaf_score_category_t;

/**
 * @brief Rule definition loaded from litewaf_rules.conf.
 */
typedef struct lwaf_rule_s {
    uint32_t id;                                  /**< Unique rule ID. */
    char name[128];                              /**< Human-readable name. */
    lwaf_match_type_t type;                      /**< str or rx matching. */
    char pattern[512];                           /**< Raw pattern text. */
    void *compiled_regex;                        /**< PCRE2 code pointer. */
    lwaf_zone_t zones[LWAF_MAX_RULE_ZONES];      /**< Zones searched by rule. */
    size_t zone_count;                           /**< Number of valid zones. */
    lwaf_score_category_t category;              /**< Score category. */
    uint32_t score;                              /**< Score added per hit. */
    lwaf_action_t action;                        /**< score/block/log. */
} lwaf_rule_t;

/**
 * @brief Dynamic array of parsed rules.
 */
typedef struct lwaf_rule_set_s {
    lwaf_rule_t *items;                          /**< Heap-owned rule array. */
    size_t count;                                /**< Number of parsed rules. */
    size_t capacity;                             /**< Allocated rule slots. */
} lwaf_rule_set_t;

/**
 * @brief Normalized request data consumed by the rule engine.
 *
 * Member A should fill raw fields from Nginx and then call
 * ::lwaf_normalize_request_context before running the engine.
 */
typedef struct lwaf_request_context_s {
    const char *raw_url;                         /**< Original URI path. */
    const char *raw_args;                        /**< Original query string. */
    const char *raw_headers;                     /**< Selected headers blob. */
    const char *raw_cookie;                      /**< Cookie header. */
    const char *raw_user_agent;                  /**< User-Agent header. */
    const char *raw_body;                        /**< Optional request body. */

    char url[LWAF_MAX_ZONE_TEXT];                /**< Decoded lowercase URI. */
    char args[LWAF_MAX_ZONE_TEXT];               /**< Decoded lowercase args. */
    char headers[LWAF_MAX_ZONE_TEXT];            /**< Decoded lowercase headers. */
    char cookie[LWAF_MAX_ZONE_TEXT];             /**< Decoded lowercase cookie. */
    char user_agent[LWAF_MAX_ZONE_TEXT];         /**< Lowercase User-Agent. */
    char body[LWAF_MAX_ZONE_TEXT];               /**< Decoded lowercase body. */
    char file_ext[32];                           /**< Lowercase URI extension. */
} lwaf_request_context_t;

/**
 * @brief One rule-hit record for audit logging.
 */
typedef struct lwaf_match_s {
    uint32_t rule_id;                            /**< Matched rule ID. */
    char rule_name[128];                         /**< Matched rule name. */
    lwaf_zone_t zone;                            /**< Zone where hit occurred. */
    lwaf_score_category_t category;              /**< Score category. */
    uint32_t score;                              /**< Score contributed (already multiplied). */
    uint32_t hit_count;                          /**< 该规则本次命中几次（已封顶 LWAF_MAX_HITS_PER_RULE）. */
    lwaf_action_t action;                        /**< Matched rule action. */
} lwaf_match_t;

/**
 * @brief Thresholds used after rule traversal.
 */
typedef struct lwaf_thresholds_s {
    uint32_t sql;                                /**< SQL category threshold. */
    uint32_t xss;                                /**< XSS category threshold. */
    uint32_t rfi;                                /**< RFI category threshold. */
    uint32_t traversal;                          /**< Traversal threshold. */
    uint32_t evade;                              /**< Evasion threshold. */
    uint32_t upload;                             /**< Upload threshold. */
    uint32_t scan;                               /**< Scanner threshold. */
    uint32_t total;                              /**< Aggregate score threshold. */
} lwaf_thresholds_t;

/**
 * @brief Final rule-engine result passed to logging/audit code.
 */
typedef struct lwaf_score_result_s {
    uint32_t scores[LWAF_SCORE_CATEGORY_COUNT];  /**< Per-category scores. */
    lwaf_match_t matches[LWAF_MAX_MATCHES];      /**< Bounded hit list. */
    size_t match_count;                          /**< Number of kept hits. */
    int blocked;                                 /**< Non-zero when denied. */
    uint32_t status;                             /**< HTTP status, usually 403. */
    uint32_t decisive_rule_id;                   /**< Immediate/blocking rule ID. */
    char reason[64];                             /**< block, threshold, or pass. */
} lwaf_score_result_t;

/**
 * @brief Initialize a rule set.
 *
 * @param set Rule set to initialize.
 */
void lwaf_rule_set_init(lwaf_rule_set_t *set);

/**
 * @brief Release all memory and compiled regex objects owned by a rule set.
 *
 * @param set Rule set to destroy.
 */
void lwaf_rule_set_destroy(lwaf_rule_set_t *set);

/**
 * @brief Load and compile rules from a LiteWAF rule file.
 *
 * @param path Rule file path.
 * @param set Output rule set. It must be initialized by caller.
 * @param errbuf Buffer receiving a human-readable error on failure.
 * @param errbuf_len Length of @p errbuf.
 * @return 0 on success, -1 on parse/IO/compile failure.
 */
int lwaf_rule_set_load_file(const char *path, lwaf_rule_set_t *set,
                            char *errbuf, size_t errbuf_len);

/**
 * @brief Parse one `lwaf_rule ...` line and append it to a rule set.
 *
 * @param line Rule line. Comments and empty lines are ignored.
 * @param set Output rule set.
 * @param errbuf Buffer receiving parse details on failure.
 * @param errbuf_len Length of @p errbuf.
 * @return 1 when a rule was added, 0 when ignored, -1 on error.
 */
int lwaf_rule_parse_line(const char *line, lwaf_rule_set_t *set,
                         char *errbuf, size_t errbuf_len);

/**
 * @brief Normalize request fields for matching.
 *
 * URL, ARGS, COOKIE, HEADERS, and BODY are URL-decoded once, converted to
 * lowercase, and truncated safely into fixed buffers. `+` becomes a space in
 * ARGS and BODY to match HTML form encoding behavior.
 *
 * @param ctx Request context with raw fields already assigned.
 */
void lwaf_normalize_request_context(lwaf_request_context_t *ctx);

/**
 * @brief Test whether one rule matches a normalized request context.
 *
 * @param ctx Normalized request context.
 * @param rule Rule to evaluate.
 * @param matched_zone Output zone for the first matching zone.
 * @return 1 if matched, 0 if not matched.
 */
int lwaf_rule_match(const lwaf_request_context_t *ctx,
                    const lwaf_rule_t *rule,
                    lwaf_zone_t *matched_zone);

/**
 * @brief 统计一条规则在一次请求里命中了几次（用于按次数计分）。
 *
 * 与 lwaf_rule_match 的区别：那个函数只回答「命中没命中」，这个函数回答
 * 「命中了几次」，并且遇到 LWAF_MAX_HITS_PER_RULE 就停手——既够用于打分，
 * 又不会在超长参数上退化成一趟昂贵扫描。
 *
 * @param ctx Normalized request context.
 * @param rule Rule to evaluate.
 * @param matched_zone Output zone for the first matching zone (可传 NULL).
 * @return 命中次数，0 表示未命中；最大返回 LWAF_MAX_HITS_PER_RULE。
 */
int lwaf_rule_match_count(const lwaf_request_context_t *ctx,
                          const lwaf_rule_t *rule,
                          lwaf_zone_t *matched_zone);

/**
 * @brief Evaluate a rule set and produce scores, matches, and block decision.
 *
 * @param ctx Normalized request context.
 * @param set Parsed rule set.
 * @param thresholds Blocking thresholds.
 * @param deny_status HTTP status written when blocked.
 * @param result Output result.
 */
void lwaf_evaluate_request(const lwaf_request_context_t *ctx,
                           const lwaf_rule_set_t *set,
                           const lwaf_thresholds_t *thresholds,
                           uint32_t deny_status,
                           lwaf_score_result_t *result);

/** @brief Return a stable string for a zone enum. */
const char *lwaf_zone_name(lwaf_zone_t zone);

/** @brief Return a stable string for a score category enum. */
const char *lwaf_category_name(lwaf_score_category_t category);

/** @brief Return a stable string for an action enum. */
const char *lwaf_action_name(lwaf_action_t action);

#ifdef __cplusplus
}
#endif

#endif /* LWAF_RULE_ENGINE_H */
