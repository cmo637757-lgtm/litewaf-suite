/**
 * @file lwaf_eval.c
 * @brief Small command-line evaluator for the LiteWAF-NGX member-B engine.
 *
 * This tool is intentionally simple: it loads a rule file, normalizes one
 * synthetic request, runs the B rule engine, and prints a JSON-like result that
 * can be pasted into reports or used during quick manual checks.
 */

#include "lwaf_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Print command usage.
 *
 * @param prog Program name.
 */
static void
usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <rules.conf> <url> [args] [user-agent] [cookie] [body] [headers]\n"
            "example: %s conf/litewaf_rules.conf /api "
            "'query=1%%20UNION%%20SELECT' 'Mozilla/5.0' '' '' ''\n",
            prog, prog);
}

/**
 * @brief Print all kept rule matches in JSON-array form.
 *
 * @param result Evaluated rule result.
 */
static void
print_matches(const lwaf_score_result_t *result)
{
    printf("  \"matches\": [");
    for (size_t i = 0; i < result->match_count; i++) {
        const lwaf_match_t *m = &result->matches[i];
        printf("%s{\"rule_id\":%u,\"rule_name\":\"%s\",\"zone\":\"%s\","
               "\"category\":\"%s\",\"score\":%u,\"action\":\"%s\"}",
               i == 0 ? "" : ",",
               m->rule_id,
               m->rule_name,
               lwaf_zone_name(m->zone),
               lwaf_category_name(m->category),
               m->score,
               lwaf_action_name(m->action));
    }
    printf("]\n");
}

/**
 * @brief Program entry point.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 when evaluation succeeds, 1 on user or runtime error.
 */
int
main(int argc, char **argv)
{
    lwaf_rule_set_t rules;
    lwaf_request_context_t ctx;
    lwaf_thresholds_t thresholds = {
        .sql = 8,
        .xss = 8,
        .rfi = 8,
        .traversal = 8,
        .evade = 8,
        .upload = 8,
        .scan = 8,
        .total = 12,
    };
    lwaf_score_result_t result;
    char errbuf[512];

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    lwaf_rule_set_init(&rules);
    if (lwaf_rule_set_load_file(argv[1], &rules, errbuf, sizeof(errbuf)) != 0) {
        fprintf(stderr, "failed to load rules: %s\n", errbuf);
        return 1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.raw_url = argv[2];
    ctx.raw_args = argc > 3 ? argv[3] : "";
    ctx.raw_user_agent = argc > 4 ? argv[4] : "";
    ctx.raw_cookie = argc > 5 ? argv[5] : "";
    ctx.raw_headers = argc > 7 ? argv[7] : "";
    /* 第六个位置参数是请求体：CRS 回归里大量样本是 POST body，不给它就没法测
     * BODY zone；空串表示没有 body。第七个是 headers 块（"Name: value\n" 拼接），
     * 只拼线上模块也会扫的那几个头（UA/Referer/Content-Type/Cookie），
     * 否则评估结果会比真实实例虚高。 */
    ctx.raw_body = argc > 6 ? argv[6] : "";
    lwaf_normalize_request_context(&ctx);

    lwaf_evaluate_request(&ctx, &rules, &thresholds, 403, &result);

    printf("{\n");
    printf("  \"blocked\": %s,\n", result.blocked ? "true" : "false");
    printf("  \"status\": %u,\n", result.status);
    printf("  \"reason\": \"%s\",\n", result.reason);
    printf("  \"scores\": {\"SQL\":%u,\"XSS\":%u,\"RFI\":%u,"
           "\"TRAVERSAL\":%u,\"EVADE\":%u,\"UPLOAD\":%u,"
           "\"SCAN\":%u,\"TOTAL\":%u},\n",
           result.scores[LWAF_SQL],
           result.scores[LWAF_XSS],
           result.scores[LWAF_RFI],
           result.scores[LWAF_TRAVERSAL],
           result.scores[LWAF_EVADE],
           result.scores[LWAF_UPLOAD],
           result.scores[LWAF_SCAN],
           result.scores[LWAF_TOTAL]);
    print_matches(&result);
    printf("}\n");

    lwaf_rule_set_destroy(&rules);
    return result.blocked ? 2 : 0;
}
