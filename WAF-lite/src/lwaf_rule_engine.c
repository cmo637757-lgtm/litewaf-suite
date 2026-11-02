/**
 * @file lwaf_rule_engine.c
 * @brief LiteWAF-NGX rule parsing, normalization, matching, and scoring.
 */

#define _POSIX_C_SOURCE 200809L
#define PCRE2_CODE_UNIT_WIDTH 8

#include "lwaf_rule_engine.h"

#include <ctype.h>
#include <errno.h>
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "libinjection_sqli.h"
#include "libinjection_xss.h"

/** Initial number of rule slots allocated for a rule file. */
#define LWAF_INITIAL_RULE_CAPACITY 16u

/**
 * @brief Copy a formatted error message into a caller-owned buffer.
 *
 * @param errbuf Destination buffer, may be NULL.
 * @param errbuf_len Destination buffer length.
 * @param message Null-terminated error text.
 */
static void
lwaf_set_error(char *errbuf, size_t errbuf_len, const char *message)
{
    if (errbuf == NULL || errbuf_len == 0) {
        return;
    }
    snprintf(errbuf, errbuf_len, "%s", message);
}

/**
 * @brief Copy a NUL-terminated string only when it fits completely.
 *
 * GCC builds Nginx with `-Werror`, so parser code should reject overlong rule
 * fields explicitly instead of relying on formatting calls that may truncate.
 *
 * @param dst Destination buffer.
 * @param dst_len Destination buffer length including the NUL byte.
 * @param src Source string.
 * @return 0 on success, -1 when the source does not fit.
 */
static int
lwaf_copy_cstr(char *dst, size_t dst_len, const char *src)
{
    size_t len;

    if (dst == NULL || dst_len == 0 || src == NULL) {
        return -1;
    }

    len = strlen(src);
    if (len >= dst_len) {
        dst[0] = '\0';
        return -1;
    }

    memcpy(dst, src, len + 1);
    return 0;
}

/**
 * @brief Check whether a character is valid hexadecimal.
 *
 * @param c Character to inspect.
 * @return Non-zero when the character is 0-9, a-f, or A-F.
 */
static int
lwaf_is_hex(char c)
{
    return isxdigit((unsigned char)c) != 0;
}

/**
 * @brief Convert one hexadecimal character to its numeric value.
 *
 * @param c Hexadecimal character.
 * @return Value from 0 to 15.
 */
static unsigned char
lwaf_hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return (unsigned char)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (unsigned char)(10 + c - 'a');
    }
    return (unsigned char)(10 + c - 'A');
}

/**
 * @brief Decode URL percent-encoding once, lowercase text, and truncate safely.
 *
 * This is intentionally conservative for course MVP behavior. It does not try
 * to recursively decode evasive payloads; instead, rules such as `%[23].` can
 * detect remaining encoded markers.
 *
 * @param src Source text, may be NULL.
 * @param dst Destination buffer.
 * @param dst_len Destination buffer length.
 * @param plus_as_space Whether `+` should become a space.
 */
static void
lwaf_decode_lower_copy(const char *src, char *dst, size_t dst_len,
                       int plus_as_space)
{
    size_t di = 0;

    if (dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (size_t si = 0; src[si] != '\0' && di + 1 < dst_len; si++) {
        unsigned char out;

        if (src[si] == '%' && lwaf_is_hex(src[si + 1]) &&
            lwaf_is_hex(src[si + 2])) {
            out = (unsigned char)((lwaf_hex_value(src[si + 1]) << 4) |
                                  lwaf_hex_value(src[si + 2]));
            si += 2;
        } else if (plus_as_space && src[si] == '+') {
            out = ' ';
        } else {
            out = (unsigned char)src[si];
        }

        dst[di++] = (char)tolower(out);
    }
    dst[di] = '\0';
}

/**
 * @brief 解析一个 HTML 实体（&lt; &#60; &#x3c;）。
 *
 * @param s 指向 '&' 的位置。
 * @param out 解析出的字节。
 * @return 消费的字节数；0 表示不是实体。
 */
static size_t
lwaf_decode_entity(const char *s, char *out)
{
    const char *p;

    if (s[0] != '&') {
        return 0;
    }
    if (strncmp(s, "&lt;", 4) == 0) {
        *out = '<';
        return 4;
    }
    if (strncmp(s, "&gt;", 4) == 0) {
        *out = '>';
        return 4;
    }
    if (strncmp(s, "&amp;", 5) == 0) {
        *out = '&';
        return 5;
    }
    if (strncmp(s, "&quot;", 6) == 0) {
        *out = '"';
        return 6;
    }
    if (strncmp(s, "&#x", 3) == 0 || strncmp(s, "&#X", 3) == 0) {
        unsigned int v = 0;
        size_t n = 0;
        for (p = s + 3; n < 6 && lwaf_is_hex(*p); p++, n++) {
            v = v * 16u + lwaf_hex_value(*p);
        }
        if (n == 0) {
            return 0;
        }
        *out = (char)(v & 0xFFu);
        return (size_t)(p - s) + (*p == ';' ? 1u : 0u);
    }
    if (strncmp(s, "&#", 2) == 0) {
        unsigned int v = 0;
        size_t n = 0;
        for (p = s + 2; n < 5 && *p >= '0' && *p <= '9'; p++, n++) {
            v = v * 10u + (unsigned int)(*p - '0');
        }
        if (n == 0) {
            return 0;
        }
        *out = (char)(v & 0xFFu);
        return (size_t)(p - s) + (*p == ';' ? 1u : 0u);
    }
    return 0;
}

/**
 * @brief 解析 \uXXXX 转义（U+00XX 范围内的字符）。
 *
 * @param s 指向 '\\' 的位置。
 * @param out 解析出的字节。
 * @return 消费的字节数；0 表示不是转义。
 */
static size_t
lwaf_decode_unicode_escape(const char *s, char *out)
{
    unsigned int v = 0;
    size_t n = 0;
    const char *p;

    if (s[0] != '\\' || (s[1] != 'u' && s[1] != 'U')) {
        return 0;
    }
    for (p = s + 2; n < 4 && lwaf_is_hex(*p); p++, n++) {
        v = v * 16u + lwaf_hex_value(*p);
    }
    if (n != 4) {
        return 0;
    }
    if (v <= 0xFFu) {
        *out = (char)v;
        return (size_t)(p - s);
    }
    /* U+0100 以上按 UTF-8 编成两字节，覆盖 <>() 之类的异体字就够用。 */
    if (v <= 0x7FFu) {
        char buf[2];
        buf[0] = (char)(0xC0u | (v >> 6));
        buf[1] = (char)(0x80u | (v & 0x3Fu));
        *out = buf[0];
        return (size_t)(p - s);
    }
    return 0;
}

/**
 * @brief 全角标点转半角（UTF-8 的 U+FF00 区）。
 *
 * 攻击者常用 `＜script＞` 绕过 `<script>` 规则，这里统一折成半角。
 *
 * @return 1 表示识别并转换，0 表示不是全角标点。
 */
static int
lwaf_decode_wide(const char *s, char *out, size_t *used)
{
    const unsigned char *p = (const unsigned char *) s;

    if (p[0] != 0xEFu || p[1] != 0xBCu) {
        return 0;
    }
    switch (p[2]) {
    case 0x9Cu: *out = '<'; break;
    case 0x9Eu: *out = '>'; break;
    case 0x88u: *out = '('; break;
    case 0x89u: *out = ')'; break;
    case 0x9Bu: *out = '['; break;
    case 0x9Du: *out = ']'; break;
    case 0x87u: *out = ';'; break;
    case 0x9Au: *out = ':'; break;
    case 0x8Fu: *out = '/'; break;
    case 0xBCu: *out = '\\'; break;
    default:
        return 0;
    }
    *used = 3;
    return 1;
}

/**
 * @brief 解码一轮：URL 百分号、HTML 实体、\uXXXX、全角标点，并转小写。
 *
 * @return 1 表示本轮发生了编码还原（还需要再解一轮）；0 表示已经是明文。
 */
static int
lwaf_decode_pass(const char *src, char *dst, size_t dst_len, int plus_as_space)
{
    size_t di = 0;
    size_t si = 0;
    int changed = 0;

    if (dst_len == 0) {
        return 0;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return 0;
    }

    while (src[si] != '\0' && di + 1 < dst_len) {
        unsigned char out;
        char tmp = 0;
        size_t used = 0;

        if (src[si] == '%' && lwaf_is_hex(src[si + 1]) && lwaf_is_hex(src[si + 2])) {
            out = (unsigned char)((lwaf_hex_value(src[si + 1]) << 4) |
                                  lwaf_hex_value(src[si + 2]));
            si += 3;
            changed = 1;

        } else if ((used = lwaf_decode_entity(src + si, &tmp)) > 0) {
            out = (unsigned char) tmp;
            si += used;
            changed = 1;

        } else if ((used = lwaf_decode_unicode_escape(src + si, &tmp)) > 0) {
            out = (unsigned char) tmp;
            si += used;
            changed = 1;

        } else if (lwaf_decode_wide(src + si, &tmp, &used)) {
            out = (unsigned char) tmp;
            si += used;
            changed = 1;

        } else if (plus_as_space && src[si] == '+') {
            out = ' ';
            si++;

        } else {
            out = (unsigned char) src[si];
            si++;
        }

        dst[di++] = (char) tolower(out);
    }
    dst[di] = '\0';
    return changed;
}

/**
 * @brief 多轮规范化：反复解码直到没有编码残留（最多 3 轮）。
 *
 * 与 lwaf_decode_lower_copy 的区别：那个只解一轮，供规则 pattern 解析使用；
 * 这个给请求字段用，能吃掉双重编码（`%2527`）、HTML 实体、`\u003c`、全角标点。
 * 三次以上还解不开的形态极少，且再解容易误伤正常文本（比如字面 `%25`）。
 */
/**
 * @brief 把非法 UTF-8 字节替换成 '?'，保证 subject 始终是合法 UTF-8。
 *
 * pcre2 以 PCRE2_UTF 编译规则，subject 里混进非法序列时整段匹配返回错误，
 * 于是"所有正则规则都没命中"——宽字节注入（%bf%27）、overlong（%c0%ae）
 * 解码后正是这种字节。换成 '?' 后，后面的 AND 1=1 / UNION SELECT 照样能匹配。
 *
 * @param s 原地修改的字符串
 */
static void
lwaf_utf8_sanitize(char *s)
{
    unsigned char *p = (unsigned char *) s;
    unsigned char *w = p;

    while (*p != '\0') {
        unsigned char c = *p;
        size_t need;
        size_t i;
        unsigned int cp;
        int ok = 1;

        if (c < 0x80) {
            *w++ = c;
            p++;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            need = 1;
            cp = c & 0x1Fu;
        } else if ((c & 0xF0) == 0xE0) {
            need = 2;
            cp = c & 0x0Fu;
        } else if ((c & 0xF8) == 0xF0) {
            need = 3;
            cp = c & 0x07u;
        } else {
            *w++ = '?';
            p++;
            continue;
        }
        if (p[need] == '\0') {
            *w++ = '?';
            p++;
            continue;
        }
        for (i = 1; i <= need; i++) {
            if ((p[i] & 0xC0) != 0x80) {
                ok = 0;
                break;
            }
            cp = (cp << 6) | (p[i] & 0x3Fu);
        }
        /* overlong（cp < 0x80）与超出 U+10FFFF 的都算非法 */
        if (!ok || cp < 0x80 || cp > 0x10FFFF) {
            *w++ = '?';
            p++;
            continue;
        }
        for (i = 0; i <= need; i++) {
            *w++ = p[i];
        }
        p += need + 1;
    }
    *w = '\0';
}

static void
lwaf_normalize_copy(const char *src, char *dst, size_t dst_len, int plus_as_space)
{
    /* worker 是单线程的，静态缓冲比在栈上开 8KB 安全。 */
    static char buf_a[LWAF_MAX_ZONE_TEXT];
    static char buf_b[LWAF_MAX_ZONE_TEXT];
    char *cur = buf_a;
    char *nxt = buf_b;
    int rounds = 0;

    if (dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(cur, sizeof(buf_a), "%s", src);

    while (rounds < 3) {
        int changed = lwaf_decode_pass(cur, nxt, LWAF_MAX_ZONE_TEXT, plus_as_space);
        char *tmp = cur;
        cur = nxt;
        nxt = tmp;
        rounds++;
        if (!changed) {
            break;
        }
    }

    lwaf_utf8_sanitize(cur);
    snprintf(dst, dst_len, "%s", cur);
}

/**
 * @brief Extract lowercase file extension from a normalized URI.
 *
 * @param url Normalized URL.
 * @param dst Destination extension buffer.
 * @param dst_len Destination extension buffer length.
 */
static void
lwaf_extract_file_ext(const char *url, char *dst, size_t dst_len)
{
    const char *slash;
    const char *dot;

    if (dst_len == 0) {
        return;
    }
    dst[0] = '\0';
    if (url == NULL) {
        return;
    }

    slash = strrchr(url, '/');
    dot = strrchr(url, '.');
    if (dot == NULL || (slash != NULL && dot < slash) || dot[1] == '\0') {
        return;
    }
    snprintf(dst, dst_len, "%s", dot);
}

/**
 * @brief Trim leading and trailing ASCII whitespace in place.
 *
 * @param text Mutable string.
 * @return Pointer to first non-space character within @p text.
 */
static char *
lwaf_trim(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }
    if (*text == '\0') {
        return text;
    }
    end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return text;
}

/**
 * @brief Parse an unsigned integer field.
 *
 * @param value Text to parse.
 * @param out Parsed integer destination.
 * @return 0 on success, -1 on invalid input.
 */
static int
lwaf_parse_u32(const char *value, uint32_t *out)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)parsed;
    return 0;
}

/**
 * @brief Parse a zone token.
 *
 * @param value Zone name such as URL, ARGS, COOKIE, or USER_AGENT.
 * @return Parsed zone or ::LWAF_ZONE_UNKNOWN.
 */
static lwaf_zone_t
lwaf_parse_zone(const char *value)
{
    if (strcasecmp(value, "URL") == 0) {
        return LWAF_ZONE_URL;
    }
    if (strcasecmp(value, "ARGS") == 0) {
        return LWAF_ZONE_ARGS;
    }
    if (strcasecmp(value, "BODY") == 0) {
        return LWAF_ZONE_BODY;
    }
    if (strcasecmp(value, "HEADERS") == 0 || strcasecmp(value, "HEADER") == 0) {
        return LWAF_ZONE_HEADERS;
    }
    if (strcasecmp(value, "COOKIE") == 0) {
        return LWAF_ZONE_COOKIE;
    }
    if (strcasecmp(value, "USER_AGENT") == 0 || strcasecmp(value, "UA") == 0) {
        return LWAF_ZONE_USER_AGENT;
    }
    if (strcasecmp(value, "FILE_EXT") == 0) {
        return LWAF_ZONE_FILE_EXT;
    }
    return LWAF_ZONE_UNKNOWN;
}

/**
 * @brief Parse a score category token.
 *
 * @param value Category name.
 * @return Parsed category or ::LWAF_SCORE_CATEGORY_COUNT on error.
 */
static lwaf_score_category_t
lwaf_parse_category(const char *value)
{
    if (strcasecmp(value, "SQL") == 0) {
        return LWAF_SQL;
    }
    if (strcasecmp(value, "XSS") == 0) {
        return LWAF_XSS;
    }
    if (strcasecmp(value, "RFI") == 0) {
        return LWAF_RFI;
    }
    if (strcasecmp(value, "TRAVERSAL") == 0) {
        return LWAF_TRAVERSAL;
    }
    if (strcasecmp(value, "EVADE") == 0) {
        return LWAF_EVADE;
    }
    if (strcasecmp(value, "UPLOAD") == 0) {
        return LWAF_UPLOAD;
    }
    if (strcasecmp(value, "SCAN") == 0) {
        return LWAF_SCAN;
    }
    if (strcasecmp(value, "TOTAL") == 0) {
        return LWAF_TOTAL;
    }
    return LWAF_SCORE_CATEGORY_COUNT;
}

/**
 * @brief Append a rule to a growable rule set.
 *
 * @param set Rule set.
 * @param rule Rule value copied into the set.
 * @param errbuf Error output buffer.
 * @param errbuf_len Error output buffer length.
 * @return 0 on success, -1 on allocation failure.
 */
static int
lwaf_rule_set_append(lwaf_rule_set_t *set, const lwaf_rule_t *rule,
                     char *errbuf, size_t errbuf_len)
{
    lwaf_rule_t *next;
    size_t next_capacity;

    if (set->count == set->capacity) {
        next_capacity = set->capacity == 0 ? LWAF_INITIAL_RULE_CAPACITY :
                                             set->capacity * 2;
        next = (lwaf_rule_t *)realloc(set->items,
                                      next_capacity * sizeof(*set->items));
        if (next == NULL) {
            lwaf_set_error(errbuf, errbuf_len, "out of memory while growing rules");
            return -1;
        }
        set->items = next;
        set->capacity = next_capacity;
    }

    set->items[set->count++] = *rule;
    return 0;
}

/**
 * @brief Compile a PCRE2 expression for a rule.
 *
 * @param rule Rule whose pattern should be compiled.
 * @param errbuf Error output buffer.
 * @param errbuf_len Error output buffer length.
 * @return 0 on success, -1 on PCRE2 compilation failure.
 */
static int
lwaf_compile_regex(lwaf_rule_t *rule, char *errbuf, size_t errbuf_len)
{
    int error_number;
    PCRE2_SIZE error_offset;
    PCRE2_UCHAR error_message[256];

    if (rule->type != LWAF_MATCH_RX) {
        return 0;
    }

    rule->compiled_regex = pcre2_compile((PCRE2_SPTR)rule->pattern,
                                         PCRE2_ZERO_TERMINATED,
                                         PCRE2_CASELESS | PCRE2_UTF,
                                         &error_number,
                                         &error_offset,
                                         NULL);
    if (rule->compiled_regex == NULL) {
        pcre2_get_error_message(error_number, error_message,
                                sizeof(error_message));
        snprintf(errbuf, errbuf_len,
                 "regex compile failed near offset %zu for rule %u: %s",
                 (size_t)error_offset, rule->id, (char *)error_message);
        return -1;
    }
    return 0;
}

/**
 * @brief Parse key=value tokens while preserving quoted values.
 *
 * The grammar is intentionally small:
 * `key=value`, `key="quoted value"`, tokens separated by ASCII whitespace.
 *
 * @param cursor In/out parse cursor.
 * @param key Key output buffer.
 * @param key_len Key output buffer length.
 * @param value Value output buffer.
 * @param value_len Value output buffer length.
 * @return 1 when a token is read, 0 at end, -1 on malformed token.
 */
static int
lwaf_next_kv(const char **cursor, char *key, size_t key_len,
             char *value, size_t value_len)
{
    const char *p = *cursor;
    size_t ki = 0;
    size_t vi = 0;

    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '\0' || *p == '#') {
        *cursor = p;
        return 0;
    }

    while (*p != '\0' && *p != '=' && !isspace((unsigned char)*p)) {
        if (ki + 1 < key_len) {
            key[ki++] = *p;
        }
        p++;
    }
    key[ki] = '\0';
    if (*p != '=') {
        return -1;
    }
    p++;

    if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"') {
            if (*p == '\\' && p[1] != '\0') {
                p++;
            }
            if (vi + 1 < value_len) {
                value[vi++] = *p;
            }
            p++;
        }
        if (*p != '"') {
            return -1;
        }
        p++;
    } else {
        while (*p != '\0' && !isspace((unsigned char)*p)) {
            if (vi + 1 < value_len) {
                value[vi++] = *p;
            }
            p++;
        }
    }
    value[vi] = '\0';
    *cursor = p;
    return 1;
}

/**
 * @brief Parse a comma-separated zone list into a rule.
 *
 * @param value Comma-separated zone names.
 * @param rule Rule being populated.
 * @param errbuf Error output buffer.
 * @param errbuf_len Error output buffer length.
 * @return 0 on success, -1 on invalid zone or excessive zones.
 */
static int
lwaf_parse_zones(const char *value, lwaf_rule_t *rule,
                 char *errbuf, size_t errbuf_len)
{
    char local[256];
    char *save = NULL;
    char *token;

    if (lwaf_copy_cstr(local, sizeof(local), value) != 0) {
        lwaf_set_error(errbuf, errbuf_len, "zones value is too long");
        return -1;
    }
    token = strtok_r(local, ",", &save);
    while (token != NULL) {
        lwaf_zone_t zone;
        token = lwaf_trim(token);
        zone = lwaf_parse_zone(token);
        if (zone == LWAF_ZONE_UNKNOWN) {
            snprintf(errbuf, errbuf_len, "unknown zone: %s", token);
            return -1;
        }
        if (rule->zone_count >= LWAF_MAX_RULE_ZONES) {
            lwaf_set_error(errbuf, errbuf_len, "too many zones in rule");
            return -1;
        }
        rule->zones[rule->zone_count++] = zone;
        token = strtok_r(NULL, ",", &save);
    }
    return 0;
}

/**
 * @brief Parse CATEGORY:VALUE score syntax.
 *
 * @param value Score expression.
 * @param rule Rule being populated.
 * @param errbuf Error output buffer.
 * @param errbuf_len Error output buffer length.
 * @return 0 on success, -1 on invalid category or score value.
 */
static int
lwaf_parse_score(const char *value, lwaf_rule_t *rule,
                 char *errbuf, size_t errbuf_len)
{
    char local[128];
    char *colon;

    if (lwaf_copy_cstr(local, sizeof(local), value) != 0) {
        lwaf_set_error(errbuf, errbuf_len, "score value is too long");
        return -1;
    }
    colon = strchr(local, ':');
    if (colon == NULL) {
        lwaf_set_error(errbuf, errbuf_len, "score must use CATEGORY:VALUE");
        return -1;
    }
    *colon = '\0';
    rule->category = lwaf_parse_category(local);
    if (rule->category == LWAF_SCORE_CATEGORY_COUNT ||
        rule->category == LWAF_TOTAL) {
        snprintf(errbuf, errbuf_len, "invalid score category: %s", local);
        return -1;
    }
    if (lwaf_parse_u32(colon + 1, &rule->score) != 0 || rule->score == 0) {
        snprintf(errbuf, errbuf_len, "invalid score value: %s", colon + 1);
        return -1;
    }
    return 0;
}

/**
 * @brief Select normalized text for a detection zone.
 *
 * @param ctx Normalized request context.
 * @param zone Zone requested by a rule.
 * @return Null-terminated zone text, never NULL.
 */
static const char *
lwaf_zone_text(const lwaf_request_context_t *ctx, lwaf_zone_t zone)
{
    switch (zone) {
    case LWAF_ZONE_URL:
        return ctx->url;
    case LWAF_ZONE_ARGS:
        return ctx->args;
    case LWAF_ZONE_BODY:
        return ctx->body;
    case LWAF_ZONE_HEADERS:
        return ctx->headers;
    case LWAF_ZONE_COOKIE:
        return ctx->cookie;
    case LWAF_ZONE_USER_AGENT:
        return ctx->user_agent;
    case LWAF_ZONE_FILE_EXT:
        return ctx->file_ext;
    default:
        return "";
    }
}

/**
 * @brief Record one match and update bounded match count.
 *
 * @param result Evaluation result.
 * @param rule Matched rule.
 * @param zone Zone where the hit occurred.
 * @param hit_count 该规则本次共命中几次（已封顶），用于通过次数贡献分数。
 */
static void
lwaf_add_match(lwaf_score_result_t *result, const lwaf_rule_t *rule,
               lwaf_zone_t zone, uint32_t hit_count)
{
    lwaf_match_t *match;

    if (result->match_count >= LWAF_MAX_MATCHES) {
        return;
    }

    match = &result->matches[result->match_count++];
    memset(match, 0, sizeof(*match));
    match->rule_id = rule->id;
    snprintf(match->rule_name, sizeof(match->rule_name), "%s", rule->name);
    match->zone = zone;
    match->category = rule->category;
    match->hit_count = hit_count;
    match->score = rule->score * hit_count;
    match->action = rule->action;
}

/**
 * @brief Decide whether accumulated scores exceed configured thresholds.
 *
 * @param result Current score result.
 * @param thresholds Configured thresholds.
 * @return Non-zero when the request should be blocked by score.
 */
static int
lwaf_scores_exceed_threshold(const lwaf_score_result_t *result,
                             const lwaf_thresholds_t *thresholds)
{
    if (result->scores[LWAF_SQL] >= thresholds->sql) {
        return 1;
    }
    if (result->scores[LWAF_XSS] >= thresholds->xss) {
        return 1;
    }
    if (result->scores[LWAF_RFI] >= thresholds->rfi) {
        return 1;
    }
    if (result->scores[LWAF_TRAVERSAL] >= thresholds->traversal) {
        return 1;
    }
    if (result->scores[LWAF_EVADE] >= thresholds->evade) {
        return 1;
    }
    if (result->scores[LWAF_UPLOAD] >= thresholds->upload) {
        return 1;
    }
    if (result->scores[LWAF_SCAN] >= thresholds->scan) {
        return 1;
    }
    return result->scores[LWAF_TOTAL] >= thresholds->total;
}

void
lwaf_rule_set_init(lwaf_rule_set_t *set)
{
    if (set == NULL) {
        return;
    }
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

void
lwaf_rule_set_destroy(lwaf_rule_set_t *set)
{
    if (set == NULL) {
        return;
    }
    for (size_t i = 0; i < set->count; i++) {
        if (set->items[i].compiled_regex != NULL) {
            pcre2_code_free((pcre2_code *)set->items[i].compiled_regex);
        }
    }
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

int
lwaf_rule_set_load_file(const char *path, lwaf_rule_set_t *set,
                        char *errbuf, size_t errbuf_len)
{
    FILE *fp;
    char line[2048];
    size_t line_no = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        snprintf(errbuf, errbuf_len, "cannot open rule file %s: %s",
                 path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int rc;
        line_no++;
        rc = lwaf_rule_parse_line(line, set, errbuf, errbuf_len);
        if (rc < 0) {
            char detail[512];
            snprintf(detail, sizeof(detail), "line %zu: %s", line_no,
                     errbuf != NULL ? errbuf : "parse error");
            lwaf_set_error(errbuf, errbuf_len, detail);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int
lwaf_rule_parse_line(const char *line, lwaf_rule_set_t *set,
                     char *errbuf, size_t errbuf_len)
{
    char local[2048];
    char *trimmed;
    const char *cursor;
    lwaf_rule_t rule;
    int have_id = 0;
    int have_name = 0;
    int have_type = 0;
    int have_pattern = 0;
    int have_score = 0;
    int have_action = 0;

    if (line == NULL || set == NULL) {
        lwaf_set_error(errbuf, errbuf_len, "invalid parser argument");
        return -1;
    }

    if (lwaf_copy_cstr(local, sizeof(local), line) != 0) {
        lwaf_set_error(errbuf, errbuf_len, "rule line is too long");
        return -1;
    }
    trimmed = lwaf_trim(local);
    if (trimmed[0] == '\0' || trimmed[0] == '#') {
        return 0;
    }
    /* S5 加固：以前这里对「不是 lwaf_rule 开头」的行直接 return 0 跳过，
     * 于是把 lwaf_rule 误写成 rule、或者整行写坏，规则文件会"加载成功但
     * 一条规则都没生效"，WAF 静默放行所有请求——这比直接报错危险得多。
     * 现在只允许空行、注释行和 lwaf_rule 行，其余一律拒绝。 */
    if (strncmp(trimmed, "lwaf_rule", strlen("lwaf_rule")) != 0
        || (trimmed[strlen("lwaf_rule")] != '\0'
            && trimmed[strlen("lwaf_rule")] != ' '
            && trimmed[strlen("lwaf_rule")] != '\t')) {
        lwaf_set_error(errbuf, errbuf_len,
                       "unexpected line: only blank lines, '#' comments and "
                       "'lwaf_rule ...' rules are allowed");
        return -1;
    }

    memset(&rule, 0, sizeof(rule));
    rule.category = LWAF_SCORE_CATEGORY_COUNT;
    rule.action = LWAF_ACT_SCORE;
    cursor = trimmed + strlen("lwaf_rule");

    for (;;) {
        char key[64];
        char value[768];
        int rc = lwaf_next_kv(&cursor, key, sizeof(key), value, sizeof(value));
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            lwaf_set_error(errbuf, errbuf_len, "malformed key=value token");
            return -1;
        }

        if (strcasecmp(key, "id") == 0) {
            if (lwaf_parse_u32(value, &rule.id) != 0 || rule.id == 0) {
                snprintf(errbuf, errbuf_len, "invalid rule id: %s", value);
                return -1;
            }
            have_id = 1;
        } else if (strcasecmp(key, "name") == 0) {
            if (lwaf_copy_cstr(rule.name, sizeof(rule.name), value) != 0) {
                lwaf_set_error(errbuf, errbuf_len, "rule name is too long");
                return -1;
            }
            have_name = 1;
        } else if (strcasecmp(key, "type") == 0) {
            if (strcasecmp(value, "str") == 0) {
                rule.type = LWAF_MATCH_STR;
            } else if (strcasecmp(value, "rx") == 0) {
                rule.type = LWAF_MATCH_RX;
            } else {
                snprintf(errbuf, errbuf_len, "invalid match type: %s", value);
                return -1;
            }
            have_type = 1;
        } else if (strcasecmp(key, "pattern") == 0) {
            lwaf_decode_lower_copy(value, rule.pattern, sizeof(rule.pattern), 0);
            have_pattern = 1;
        } else if (strcasecmp(key, "zones") == 0) {
            if (lwaf_parse_zones(value, &rule, errbuf, errbuf_len) != 0) {
                return -1;
            }
        } else if (strcasecmp(key, "score") == 0) {
            if (lwaf_parse_score(value, &rule, errbuf, errbuf_len) != 0) {
                return -1;
            }
            have_score = 1;
        } else if (strcasecmp(key, "action") == 0) {
            if (strcasecmp(value, "score") == 0) {
                rule.action = LWAF_ACT_SCORE;
            } else if (strcasecmp(value, "block") == 0) {
                rule.action = LWAF_ACT_BLOCK;
            } else if (strcasecmp(value, "log") == 0) {
                rule.action = LWAF_ACT_LOG;
            } else {
                snprintf(errbuf, errbuf_len, "invalid action: %s", value);
                return -1;
            }
            have_action = 1;
        } else {
            snprintf(errbuf, errbuf_len, "unknown rule key: %s", key);
            return -1;
        }
    }

    if (!have_id || !have_name || !have_type || !have_pattern ||
        rule.zone_count == 0 || !have_score || !have_action) {
        lwaf_set_error(errbuf, errbuf_len,
                       "rule requires id, name, type, pattern, zones, score, action");
        return -1;
    }
    if (lwaf_compile_regex(&rule, errbuf, errbuf_len) != 0) {
        return -1;
    }
    if (lwaf_rule_set_append(set, &rule, errbuf, errbuf_len) != 0) {
        if (rule.compiled_regex != NULL) {
            pcre2_code_free((pcre2_code *)rule.compiled_regex);
        }
        return -1;
    }
    return 1;
}

void
lwaf_normalize_request_context(lwaf_request_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    /* 请求字段用多轮规范化（能吃掉双重编码、HTML 实体、\u003c、全角标点）；
     * 规则 pattern 那边仍走单次 lwaf_decode_lower_copy，避免 pattern 里的
     * `%2e` 被还原成 `.` 之后语义跑偏。 */
    lwaf_normalize_copy(ctx->raw_url, ctx->url, sizeof(ctx->url), 0);
    lwaf_normalize_copy(ctx->raw_args, ctx->args, sizeof(ctx->args), 1);
    lwaf_normalize_copy(ctx->raw_headers, ctx->headers,
                        sizeof(ctx->headers), 0);
    lwaf_normalize_copy(ctx->raw_cookie, ctx->cookie,
                        sizeof(ctx->cookie), 1);
    lwaf_normalize_copy(ctx->raw_user_agent, ctx->user_agent,
                        sizeof(ctx->user_agent), 0);
    lwaf_normalize_copy(ctx->raw_body, ctx->body, sizeof(ctx->body), 1);
    lwaf_extract_file_ext(ctx->url, ctx->file_ext, sizeof(ctx->file_ext));
}

int
lwaf_rule_match(const lwaf_request_context_t *ctx, const lwaf_rule_t *rule,
                lwaf_zone_t *matched_zone)
{
    /* 布尔语义直接复用计数版本，避免两套匹配逻辑各自演化时改漏一处。
     * 计数版本最多只数 LWAF_MAX_HITS_PER_RULE 次，代价可控。 */
    return lwaf_rule_match_count(ctx, rule, matched_zone) > 0;
}

/**
 * @brief 统计一条规则在一次请求里的命中次数（按次数计分的输入）。
 *
 * 为什么要单独一个函数：lwaf_rule_match 是布尔语义，改造它会牵动探针、
 * 单测和 module 里的调用点；新增一个「数次数」的入口风险最小。
 *
 * 计数策略：
 * - STR 类型用 strstr 逐段前进来数，命中数达到上限立刻返回；
 * - RX 类型用 pcre2_match 带 startoffset 重新匹配，同样到上限即停。
 *   这样即使参数里有几万个字符，最多也只做 LWAF_MAX_HITS_PER_RULE 次匹配。
 *
 * pcre2_match_data 用进程内静态缓存复用：nginx worker 是单线程的，没有
 * 并发访问；原来每条规则、每个 zone 都 create/free 一次，一个请求下来
 * 至少 38 次 malloc/free，是 P95 变差的主要来源之一。
 *
 * @param ctx Normalized request context.
 * @param rule Rule to evaluate.
 * @param matched_zone 第一次命中的 zone（可传 NULL）.
 * @return 命中次数，0 = 未命中，上限 LWAF_MAX_HITS_PER_RULE。
 */
static pcre2_match_data *g_match_data;

static pcre2_match_data *
lwaf_match_data_get(void)
{
    if (g_match_data == NULL) {
        /* 32 对 ovector 足够覆盖现有规则（最多 3 个捕获组），
         * 不够时 pcre2_match 会返回 PCRE2_ERROR_NOMEMORY 而不会越界。 */
        g_match_data = pcre2_match_data_create(32, NULL);
    }
    return g_match_data;
}

int
lwaf_rule_match_count(const lwaf_request_context_t *ctx,
                      const lwaf_rule_t *rule,
                      lwaf_zone_t *matched_zone)
{
    int best = 0;

    if (ctx == NULL || rule == NULL) {
        return 0;
    }

    for (size_t i = 0; i < rule->zone_count; i++) {
        const char *target = lwaf_zone_text(ctx, rule->zones[i]);
        int hits = 0;

        if (target[0] == '\0') {
            continue;
        }

        if (rule->type == LWAF_MATCH_STR) {
            const char *cursor = target;

            if (rule->pattern[0] == '\0') {
                continue;
            }
            while (hits < (int) LWAF_MAX_HITS_PER_RULE) {
                const char *found = strstr(cursor, rule->pattern);
                if (found == NULL) {
                    break;
                }
                hits++;
                cursor = found + 1;
            }
        } else if (rule->compiled_regex != NULL) {
            pcre2_match_data *match_data = lwaf_match_data_get();
            PCRE2_SIZE offset = 0;
            size_t target_len = strlen(target);

            if (match_data == NULL) {
                continue;
            }
            while (hits < (int) LWAF_MAX_HITS_PER_RULE && offset <= target_len) {
                int rc = pcre2_match((pcre2_code *)rule->compiled_regex,
                                     (PCRE2_SPTR) target,
                                     target_len,
                                     offset,
                                     /* 宽字节注入（`%bf%27`）解码后是非法 UTF-8，
                                      * 以前整段被判非法、直接匹配失败、规则全漏。
                                      * MATCH_INVALID_UTF 让这类非法字节按单字符处理，
                                      * 后面的 `AND 1=1` 照样能匹配到。 */
                                     0,
                                     match_data,
                                     NULL);
                if (rc < 0 || rc == 0) {
                    break;
                }
                hits++;
                {
                    /* 从本次命中的末尾继续，避免同一位置反复计数。 */
                    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
                    PCRE2_SIZE end = ovector[1];
                    offset = (end > offset) ? end : offset + 1;
                }
            }
        }

        if (hits > best) {
            best = hits;
            if (matched_zone != NULL) {
                *matched_zone = rule->zones[i];
            }
            if (best >= (int) LWAF_MAX_HITS_PER_RULE) {
                return best;
            }
        }
    }

    return best;
}


/* ---------------------------------------------------------------------------
 * P2 libinjection 语义检测
 *
 * 正则黑名单看得懂"关键字"，看不懂"结构"。`1 AND 1=1`、`1 OR 2>1` 这类合法
 * SQL 语法拆成关键字后全是普通词，正则怎么补都会漏。libinjection 做的是
 * SQL/XSS 词法分析（把 payload 拆成 token 再看指纹），正好补这块。
 *
 * 命中直接记 8 分（等于单条规则到达阈值），不再叠加：它的误判率很低，
 * 但一旦判错就是整类请求被拦，所以分值不设 4 分那种半吊子档。
 * ------------------------------------------------------------------------ */

static const lwaf_rule_t g_li_sqli_rule = {
    .id = 9001,
    .name = "libinjection sqli",
    .type = LWAF_MATCH_STR,
    .category = LWAF_SQL,
    .score = 8,
    .action = LWAF_ACT_SCORE
};

static const lwaf_rule_t g_li_xss_rule = {
    .id = 9002,
    .name = "libinjection xss",
    .type = LWAF_MATCH_STR,
    .category = LWAF_XSS,
    .score = 8,
    .action = LWAF_ACT_SCORE
};

/**
 * @brief 对 args / body / cookie / url 各跑一次 libinjection。
 *
 * 只跑已规范化的字段（编码已在 lwaf_normalize_copy 里还原过），
 * 这样 `%27%20OR%201=1` 走到这里已经是 `' or 1=1`，词法分析才有效。
 *
 * @param ctx     请求上下文
 * @param sql_hit 命中 SQLi 时置 1
 * @param xss_hit 命中 XSS 时置 1
 */
static void
lwaf_semantic_scan(const lwaf_request_context_t *ctx, int *sql_hit, int *xss_hit)
{
    const char *zones[4];
    size_t i;

    zones[0] = ctx->args;
    zones[1] = ctx->body;
    zones[2] = ctx->cookie;
    zones[3] = ctx->url;

    for (i = 0; i < 4; i++) {
        const char *s = zones[i];
        size_t len;
        struct libinjection_sqli_state sf;

        if (s == NULL || s[0] == '\0') {
            continue;
        }
        len = strlen(s);
        /* libinjection 官方建议 >= 5 字节才判断，太短只会制造噪声 */
        if (len < 5 || len > LWAF_MAX_ZONE_TEXT) {
            continue;
        }

        if (*sql_hit == 0) {
            libinjection_sqli_init(&sf, s, len, FLAG_NONE);
            if (libinjection_is_sqli(&sf) == LIBINJECTION_RESULT_TRUE) {
                *sql_hit = 1;
            }
        }
        if (*xss_hit == 0) {
            if (libinjection_is_xss(s, len, FLAG_NONE) == LIBINJECTION_RESULT_TRUE) {
                *xss_hit = 1;
            }
        }
        if (*sql_hit && *xss_hit) {
            return;
        }
    }
}

void
lwaf_evaluate_request(const lwaf_request_context_t *ctx,
                      const lwaf_rule_set_t *set,
                      const lwaf_thresholds_t *thresholds,
                      uint32_t deny_status,
                      lwaf_score_result_t *result)
{
    lwaf_thresholds_t local_thresholds;

    if (result == NULL) {
        return;
    }
    memset(result, 0, sizeof(*result));
    result->status = 0;
    snprintf(result->reason, sizeof(result->reason), "pass");

    if (ctx == NULL || set == NULL) {
        return;
    }

    if (thresholds == NULL) {
        memset(&local_thresholds, 0, sizeof(local_thresholds));
        local_thresholds.sql = 8;
        local_thresholds.xss = 8;
        local_thresholds.rfi = 8;
        local_thresholds.traversal = 8;
        local_thresholds.evade = 8;
        local_thresholds.upload = 8;
        local_thresholds.scan = 8;
        local_thresholds.total = 12;
        thresholds = &local_thresholds;
    }

    /* 先跑语义检测：它比正则更"看得懂"，命中就直接到阈值，不用再跑 82 条规则 */
    {
        int sql_hit = 0;
        int xss_hit = 0;

        lwaf_semantic_scan(ctx, &sql_hit, &xss_hit);

        if (sql_hit) {
            lwaf_add_match(result, &g_li_sqli_rule, LWAF_ZONE_ARGS, 1);
            result->scores[LWAF_SQL] += g_li_sqli_rule.score;
            result->scores[LWAF_TOTAL] += g_li_sqli_rule.score;
        }
        if (xss_hit) {
            lwaf_add_match(result, &g_li_xss_rule, LWAF_ZONE_ARGS, 1);
            result->scores[LWAF_XSS] += g_li_xss_rule.score;
            result->scores[LWAF_TOTAL] += g_li_xss_rule.score;
        }
        if ((sql_hit || xss_hit) && lwaf_scores_exceed_threshold(result, thresholds)) {
            result->blocked = 1;
            result->status = deny_status;
            snprintf(result->reason, sizeof(result->reason), "score_threshold");
            return;
        }
    }

    for (size_t i = 0; i < set->count; i++) {
        lwaf_zone_t zone = LWAF_ZONE_UNKNOWN;
        const lwaf_rule_t *rule = &set->items[i];
        int hits;

        /* 按命中次数计分：同一条规则在同一个请求里命中 N 次，就贡献 N 份分
         * （N 封顶 LWAF_MAX_HITS_PER_RULE，防止被刷分）。
         * 改这里之前是「命中一次就算一次分」，所以 `SELECT * FROM users`
         * 这种一句里带多个关键字的裸 SQL 会卡在阈值下面被放行。 */
        hits = lwaf_rule_match_count(ctx, rule, &zone);
        if (hits <= 0) {
            continue;
        }

        if (rule->action == LWAF_ACT_BLOCK) {
            lwaf_add_match(result, rule, zone, (uint32_t) hits);
            result->blocked = 1;
            result->status = deny_status;
            result->decisive_rule_id = rule->id;
            snprintf(result->reason, sizeof(result->reason), "block_rule");
            return;
        }

        lwaf_add_match(result, rule, zone, (uint32_t) hits);

        if (rule->action == LWAF_ACT_SCORE) {
            uint32_t gained = rule->score * (uint32_t) hits;
            result->scores[rule->category] += gained;
            result->scores[LWAF_TOTAL] += gained;

            /* 超阈值就立刻收工：剩下的规则再匹配也没有意义，只会在攻击流量上
             * 白烧 CPU（打得越狠、跑得越慢，等于给攻击者递了一个放大器）。
             * 已经记账的 matches 保留，日志照常写。 */
            if (lwaf_scores_exceed_threshold(result, thresholds)) {
                result->blocked = 1;
                result->status = deny_status;
                snprintf(result->reason, sizeof(result->reason),
                         "score_threshold");
                return;
            }
        }
    }
}

const char *
lwaf_zone_name(lwaf_zone_t zone)
{
    switch (zone) {
    case LWAF_ZONE_URL:
        return "URL";
    case LWAF_ZONE_ARGS:
        return "ARGS";
    case LWAF_ZONE_BODY:
        return "BODY";
    case LWAF_ZONE_HEADERS:
        return "HEADERS";
    case LWAF_ZONE_COOKIE:
        return "COOKIE";
    case LWAF_ZONE_USER_AGENT:
        return "USER_AGENT";
    case LWAF_ZONE_FILE_EXT:
        return "FILE_EXT";
    default:
        return "UNKNOWN";
    }
}

const char *
lwaf_category_name(lwaf_score_category_t category)
{
    switch (category) {
    case LWAF_SQL:
        return "SQL";
    case LWAF_XSS:
        return "XSS";
    case LWAF_RFI:
        return "RFI";
    case LWAF_TRAVERSAL:
        return "TRAVERSAL";
    case LWAF_EVADE:
        return "EVADE";
    case LWAF_UPLOAD:
        return "UPLOAD";
    case LWAF_SCAN:
        return "SCAN";
    case LWAF_TOTAL:
        return "TOTAL";
    default:
        return "UNKNOWN";
    }
}

const char *
lwaf_action_name(lwaf_action_t action)
{
    switch (action) {
    case LWAF_ACT_SCORE:
        return "score";
    case LWAF_ACT_BLOCK:
        return "block";
    case LWAF_ACT_LOG:
        return "log";
    default:
        return "unknown";
    }
}
