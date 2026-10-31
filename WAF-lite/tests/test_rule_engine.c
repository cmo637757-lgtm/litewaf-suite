/**
 * @file test_rule_engine.c
 * @brief Executable regression tests for the LiteWAF-NGX member-B modules.
 */

#include "lwaf_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Abort the test process when a condition is false.
 *
 * @param condition Non-zero means the assertion passed.
 * @param message Failure message printed to stderr.
 */
static void
expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

/**
 * @brief Build and normalize a request context for tests.
 *
 * @param url URI path.
 * @param args Query string.
 * @param ua User-Agent header.
 * @param cookie Cookie header.
 * @return Normalized request context.
 */
static lwaf_request_context_t
make_ctx(const char *url, const char *args, const char *ua, const char *cookie)
{
    lwaf_request_context_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.raw_url = url;
    ctx.raw_args = args;
    ctx.raw_user_agent = ua;
    ctx.raw_cookie = cookie;
    ctx.raw_headers = "referer: https://example.test/\ncontent-type: text/plain";
    lwaf_normalize_request_context(&ctx);
    return ctx;
}

/**
 * @brief Run one request through the engine.
 *
 * @param rules Parsed rules.
 * @param ctx Normalized request context.
 * @return Rule-engine result.
 */
static lwaf_score_result_t
eval(const lwaf_rule_set_t *rules, const lwaf_request_context_t *ctx)
{
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

    lwaf_evaluate_request(ctx, rules, &thresholds, 403, &result);
    return result;
}

/**
 * @brief Test default sample traffic from the product design.
 *
 * @return Process exit code.
 */
int
main(void)
{
    lwaf_rule_set_t rules;
    char errbuf[512];

    lwaf_rule_set_init(&rules);
    expect(lwaf_rule_set_load_file("conf/litewaf_rules.conf", &rules,
                                   errbuf, sizeof(errbuf)) == 0,
           errbuf);
    expect(rules.count >= 15, "default rule file should load many rules");

    {
        lwaf_request_context_t ctx = make_ctx("/api", "query=hello", "Mozilla/5.0", "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(!result.blocked, "normal request should pass");
        expect(result.match_count == 0, "normal request should not match rules");
    }

    {
        lwaf_request_context_t ctx = make_ctx(
            "/api",
            "query=1%20UNION%20SELECT%20username,password%20FROM%20users",
            "Mozilla/5.0",
            "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "UNION SELECT should be blocked by SQL threshold");
        expect(result.scores[LWAF_SQL] >= 8, "SQL score should reach threshold");
    }

    {
        lwaf_request_context_t ctx = make_ctx(
            "/api",
            "query=%3Cscript%3Ealert(1)%3C/script%3E",
            "Mozilla/5.0",
            "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "encoded script tag should be blocked");
        expect(result.scores[LWAF_XSS] >= 8, "XSS score should reach threshold");
    }

    {
        lwaf_request_context_t ctx = make_ctx(
            "/api",
            "file=../../etc/passwd",
            "Mozilla/5.0",
            "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "path traversal should be blocked");
        expect(result.scores[LWAF_TRAVERSAL] >= 8,
               "traversal score should reach threshold");
    }

    {
        lwaf_request_context_t ctx = make_ctx(
            "/api",
            "url=http://evil.example/shell.txt",
            "Mozilla/5.0",
            "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "RFI URL should be blocked");
        expect(result.scores[LWAF_RFI] >= 8, "RFI score should reach threshold");
    }

    {
        lwaf_request_context_t ctx = make_ctx("/", "", "sqlmap/1.7", "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "scanner UA should be blocked immediately");
        expect(strcmp(result.reason, "block_rule") == 0,
               "scanner UA should use immediate block action");
        expect(result.decisive_rule_id == 2001,
               "scanner UA should report the decisive rule ID");
    }

    {
        lwaf_request_context_t ctx = make_ctx("/upload.php", "", "Mozilla/5.0", "");
        lwaf_score_result_t result = eval(&rules, &ctx);
        expect(result.blocked, "dangerous extension should be blocked");
        expect(result.scores[LWAF_UPLOAD] >= 8,
               "upload score should reach threshold");
    }

    printf("PASS: %zu rules loaded; B rule engine matched and scored sample traffic\n",
           rules.count);
    lwaf_rule_set_destroy(&rules);
    return 0;
}
