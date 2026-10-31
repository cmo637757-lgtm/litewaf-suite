/**
 * @file ngx_http_lite_waf_module.c
 * @brief LiteWAF-NGX integrated Nginx HTTP module.
 *
 * This file is the integration point for the three project roles:
 *
 * - Member A: Nginx module skeleton, location configuration, CIDR access
 *   control, and trusted X-Forwarded-For client IP extraction.
 * - Member B: external rule-file loading, request-zone extraction, str/rx
 *   matching, anomaly scoring, and block decision via lwaf_rule_engine.
 * - Member C: shared-memory leaky-bucket dynamic blocking and JSON Lines audit
 *   logging.
 *
 * The handler is registered in NGX_HTTP_ACCESS_PHASE so malicious requests are
 * denied before they reach proxy_pass or static content handlers.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/time.h>

#include "lwaf_rule_engine.h"

/** Maximum IP records kept by the shared dynamic block table. */
#define LWAF_MAX_IP_STATS 4096u

/** Shared memory zone name used by all Nginx worker processes. */
#define LWAF_SHM_ZONE_NAME "lite_waf_dynamic_block"

/** Shared memory size reserved for leaky-bucket dynamic blocking. */
#define LWAF_SHM_ZONE_SIZE (1024u * 1024u)

/** Fixed-point scale used by leaky-bucket water accounting. */
#define LWAF_LEAK_SCALE 1000u

/** Maximum raw body bytes copied into the member-B rule context. */
#define LWAF_MAX_CAPTURE_BODY (LWAF_MAX_ZONE_TEXT * 2u)

/**
 * @brief 请求体硬上限（字节），超过直接拒绝而不是"截断后只查前 8KB"。
 *
 * 之前的行为：body 超过 8KB 就截断，只把前 8KB 交给规则引擎，后面的内容
 * 完全不看也不报错。攻击者只要在 payload 前面垫 8KB 填充就能整段绕过检测。
 * 现在默认拒绝（413），需要放行大表单的 location 可以显式调大这个值。
 */
#define LWAF_DEFAULT_MAX_BODY_BYTES (8u * 1024u)

/** Unset marker for uint32_t thresholds in Nginx configuration merging. */
#define LWAF_UNSET_THRESHOLD UINT32_MAX

/**
 * @brief IP/CIDR entry stored in whitelist and blacklist arrays.
 *
 * Address and mask use host byte order, which makes matching a cheap integer
 * bit operation during ACCESS_PHASE.
 */
typedef struct {
    in_addr_t addr; /**< Network address in host byte order. */
    in_addr_t mask; /**< Network mask in host byte order. */
} lwaf_access_cidr_t;

/**
 * @brief Per-IP leaky-bucket dynamic block state.
 */
typedef struct {
    in_addr_t ip;             /**< Client IP in host byte order. */
    time_t last_seen;         /**< Last timestamp used for leakage. */
    ngx_uint_t water_level;   /**< Fixed-point bucket fill level. */
    time_t block_expire;      /**< Timestamp when the current block expires. */
    ngx_flag_t used;          /**< Whether this slot has been initialized. */
    /**
     * 毫秒级 last_seen（追加在结构体末尾，reload 继承旧共享内存时这块是 0，
     * 会自动回退到秒级的 last_seen）。原来的泄漏计算只有秒精度：两次请求只要
     * 跨了秒边界，就白送整整 1 秒的排水量（capacity/window），攻击者每 0.9 秒
     * 打一次就能让水位永远涨不起来。
     */
    uint64_t last_seen_ms;
} lwaf_ip_stat_t;

/**
 * @brief Shared dynamic block store placed in an Nginx slab pool.
 */
typedef struct {
    ngx_uint_t stat_count;                         /**< Initialized slots. */
    lwaf_ip_stat_t stats[LWAF_MAX_IP_STATS];       /**< Fixed-size IP table. */
} lwaf_shm_store_t;

/**
 * @brief Per-cycle pointer bundle for LiteWAF shared memory.
 */
typedef struct {
    ngx_slab_pool_t *shpool;       /**< Nginx shared-memory slab pool. */
    lwaf_shm_store_t *store;       /**< Shared dynamic block table. */
} lwaf_shm_ctx_t;

/**
 * @brief Runtime audit event passed to the JSON logger.
 */
typedef struct {
    const char *reason;       /**< blacklist, dynamic_block, block_rule, etc. */
    const char *action;       /**< deny for blocked requests. */
    ngx_uint_t status;        /**< HTTP status returned to the client. */
    ngx_uint_t rule_id;       /**< Matched rule ID, or 0 for non-rule blocks. */
    const char *rule_name;    /**< Matched rule name, or empty string. */
    const char *zone;         /**< Matched zone, or empty string. */
    const char *category;     /**< Score category, or empty string. */
    ngx_uint_t score;         /**< Rule score or category score. */
    ngx_uint_t total_score;   /**< Total anomaly score. */
    ngx_uint_t cost_us;       /**< 拦截处理耗时（微秒）：从 ACCESS_PHASE 进入 handler 起，到审计日志写出止（含异步 BODY 等待）；不是纯规则匹配耗时。 */
} lwaf_log_event_t;

/**
 * @brief Location configuration shared by A/B/C modules.
 */
typedef struct {
    ngx_flag_t enable;             /**< lite_waf on/off. */
    ngx_flag_t trust_proxy;        /**< Whether to trust X-Forwarded-For. */
    ngx_uint_t deny_status;        /**< Status code for denied requests. */

    ngx_array_t *whitelist;        /**< Array of ::lwaf_access_cidr_t. */
    ngx_array_t *blacklist;        /**< Array of ::lwaf_access_cidr_t. */

    ngx_str_t rule_file;           /**< External B rule file path. */
    lwaf_rule_set_t *rules;        /**< Parsed and compiled B rule set. */
    lwaf_thresholds_t thresholds;  /**< B score thresholds. */

    ngx_flag_t dynamic_block;      /**< Enable C leaky-bucket blocking. */
    ngx_uint_t max_requests;       /**< Leaky-bucket capacity in requests. */
    ngx_uint_t window;             /**< Seconds for a full bucket to leak out. */
    ngx_uint_t block_duration;     /**< Block duration in seconds. */

    ngx_uint_t max_body_bytes;     /**< 请求体硬上限，超过直接 413；0 表示不检查. */

    ngx_str_t log_path;            /**< JSON Lines audit log path. */
    ngx_str_t log_path_full;       /**< 配置期解析好的绝对路径；请求路径里不再调 ngx_conf_full_name. */
    ngx_fd_t log_fd;               /**< 复用的审计日志 fd（O_APPEND 写），NGX_INVALID_FILE = 未打开. */
} lwaf_loc_conf_t;

/**
 * @brief Per-request module context used for asynchronous request-body reads.
 */
typedef struct {
    ngx_flag_t precheck_done;      /**< IP lists and dynamic block already ran. */
    ngx_flag_t body_done;          /**< Request body has been captured or skipped. */
    ngx_flag_t waiting_body;       /**< Body read has been submitted to Nginx. */
    in_addr_t client_ip;           /**< Client IP resolved during precheck. */
    ngx_uint_t started_us;         /**< First handler entry timestamp. */
    ngx_str_t body;                /**< Pool-owned raw body snapshot. */
} lwaf_request_state_t;

/** Current-cycle shared-memory context visible in worker processes. */
static lwaf_shm_ctx_t *lwaf_shared_ctx;

static void *ngx_http_lite_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_lite_waf_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                              void *child);
static ngx_int_t ngx_http_lite_waf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_lite_waf_init_shm_zone(ngx_shm_zone_t *shm_zone,
                                                 void *data);
static ngx_int_t ngx_http_lite_waf_handler(ngx_http_request_t *r);
static void ngx_http_lite_waf_body_handler(ngx_http_request_t *r);

static char *ngx_http_lite_waf_blacklist_cmd(ngx_conf_t *cf,
                                             ngx_command_t *cmd, void *conf);
static char *ngx_http_lite_waf_whitelist_cmd(ngx_conf_t *cf,
                                             ngx_command_t *cmd, void *conf);
static char *ngx_http_lite_waf_rule_file_cmd(ngx_conf_t *cf,
                                             ngx_command_t *cmd, void *conf);
static char *ngx_http_lite_waf_score_threshold_cmd(ngx_conf_t *cf,
                                                   ngx_command_t *cmd,
                                                   void *conf);
static char *ngx_http_lite_waf_uint_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);

static ngx_int_t lwaf_parse_ip_cidr(ngx_str_t *text, lwaf_access_cidr_t *cidr);
static ngx_int_t lwaf_ip_match_cidr(in_addr_t ip, lwaf_access_cidr_t *cidr);
static ngx_int_t lwaf_get_client_ip(ngx_http_request_t *r,
                                    lwaf_loc_conf_t *conf, in_addr_t *ip);
static ngx_int_t lwaf_dynamic_check_and_update(lwaf_loc_conf_t *conf,
                                               in_addr_t client_ip);
static ngx_int_t lwaf_request_needs_body(ngx_http_request_t *r);
static ngx_int_t lwaf_capture_request_body(ngx_http_request_t *r,
                                           lwaf_request_state_t *state);
static u_char *lwaf_json_escape(u_char *p, u_char *last, const u_char *data,
                                size_t len);
static ngx_int_t lwaf_log_write(ngx_http_request_t *r, lwaf_loc_conf_t *conf,
                                in_addr_t client_ip, lwaf_log_event_t *event);

extern ngx_module_t ngx_http_lite_waf_module;

/**
 * @brief Compute current wall-clock time in microseconds.
 *
 * @return Microsecond timestamp suitable for request-cost calculation.
 */
static ngx_uint_t
lwaf_now_us(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (ngx_uint_t)(tv.tv_sec * 1000000u + tv.tv_usec);
}

/**
 * @brief Convert an IPv4 address from host byte order to dotted text.
 *
 * @param ip IPv4 address in host byte order.
 * @param buf Destination buffer.
 * @param len Destination buffer length.
 */
static void
lwaf_ip_to_text(in_addr_t ip, u_char *buf, size_t len)
{
    struct in_addr in;

    in.s_addr = htonl(ip);
    if (inet_ntop(AF_INET, &in, (char *)buf, (socklen_t)len) == NULL) {
        ngx_cpystrn(buf, (u_char *)"0.0.0.0", len);
    }
}

/**
 * @brief Copy an ngx_str_t into a null-terminated request-pool string.
 *
 * @param r HTTP request whose pool owns the result.
 * @param value Source string.
 * @return Null-terminated copy, or an empty string on allocation failure.
 */
static char *
lwaf_pstrdup0(ngx_http_request_t *r, ngx_str_t value)
{
    u_char *dst;

    dst = ngx_pnalloc(r->pool, value.len + 1);
    if (dst == NULL) {
        return "";
    }
    ngx_memcpy(dst, value.data, value.len);
    dst[value.len] = '\0';
    return (char *)dst;
}

/**
 * @brief Append one header as "key: value\n" into a bounded buffer.
 *
 * @param r HTTP request whose pool owns the buffer.
 * @param buf Buffer pointer, allocated lazily.
 * @param len Current buffer length.
 * @param cap Total buffer capacity.
 * @param h Header to append.
 */
static void
lwaf_append_header(ngx_http_request_t *r, u_char **buf, size_t *len,
                   size_t cap, ngx_table_elt_t *h)
{
    size_t need;

    if (h == NULL || h->hash == 0 || *len + 1 >= cap) {
        return;
    }
    if (*buf == NULL) {
        *buf = ngx_pcalloc(r->pool, cap);
        if (*buf == NULL) {
            return;
        }
    }

    need = h->key.len + h->value.len + 3;
    if (*len + need + 1 >= cap) {
        return;
    }

    *len += ngx_snprintf(*buf + *len, cap - *len, "%V: %V\n",
                         &h->key, &h->value) - (*buf + *len);
}

/**
 * @brief Build the B request context from Nginx request fields.
 *
 * @param r HTTP request.
 * @param ctx Output B request context.
 */
static void
lwaf_build_request_context(ngx_http_request_t *r, lwaf_request_state_t *state,
                           lwaf_request_context_t *ctx)
{
    u_char *headers = NULL;
    size_t headers_len = 0;
    static const size_t headers_cap = 2048;

    ngx_memzero(ctx, sizeof(*ctx));
    ctx->raw_url = lwaf_pstrdup0(r, r->uri);
    ctx->raw_args = lwaf_pstrdup0(r, r->args);

    if (r->headers_in.user_agent != NULL) {
        ctx->raw_user_agent = lwaf_pstrdup0(r, r->headers_in.user_agent->value);
        lwaf_append_header(r, &headers, &headers_len, headers_cap,
                           r->headers_in.user_agent);
    }
    if (r->headers_in.referer != NULL) {
        lwaf_append_header(r, &headers, &headers_len, headers_cap,
                           r->headers_in.referer);
    }
    if (r->headers_in.content_type != NULL) {
        lwaf_append_header(r, &headers, &headers_len, headers_cap,
                           r->headers_in.content_type);
    }
    if (r->headers_in.cookie != NULL) {
        ctx->raw_cookie = lwaf_pstrdup0(r, r->headers_in.cookie->value);
        lwaf_append_header(r, &headers, &headers_len, headers_cap,
                           r->headers_in.cookie);
    }

    ctx->raw_headers = headers != NULL ? (char *)headers : "";
    ctx->raw_body = state != NULL && state->body.data != NULL
                        ? (char *)state->body.data
                        : "";
    lwaf_normalize_request_context(ctx);
}

/**
 * @brief Create a location configuration with unset values.
 *
 * @param cf Nginx configuration context.
 * @return Newly allocated location configuration, or NULL on allocation error.
 */
static void *
ngx_http_lite_waf_create_loc_conf(ngx_conf_t *cf)
{
    lwaf_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(lwaf_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->trust_proxy = NGX_CONF_UNSET;
    conf->deny_status = NGX_CONF_UNSET_UINT;
    conf->dynamic_block = NGX_CONF_UNSET;
    conf->max_requests = NGX_CONF_UNSET_UINT;
    conf->window = NGX_CONF_UNSET_UINT;
    conf->block_duration = NGX_CONF_UNSET_UINT;
    conf->max_body_bytes = NGX_CONF_UNSET_UINT;
    /* pcalloc 清零后 fd == 0 会被误当成 stdin，必须显式置无效 */
    conf->log_fd = NGX_INVALID_FILE;

    conf->thresholds.sql = LWAF_UNSET_THRESHOLD;
    conf->thresholds.xss = LWAF_UNSET_THRESHOLD;
    conf->thresholds.rfi = LWAF_UNSET_THRESHOLD;
    conf->thresholds.traversal = LWAF_UNSET_THRESHOLD;
    conf->thresholds.evade = LWAF_UNSET_THRESHOLD;
    conf->thresholds.upload = LWAF_UNSET_THRESHOLD;
    conf->thresholds.scan = LWAF_UNSET_THRESHOLD;
    conf->thresholds.total = LWAF_UNSET_THRESHOLD;

    return conf;
}

/**
 * @brief Merge inherited http/server/location configuration values.
 *
 * @param cf Nginx configuration context.
 * @param parent Parent location configuration.
 * @param child Child location configuration.
 * @return NGX_CONF_OK.
 */
static char *
ngx_http_lite_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    lwaf_loc_conf_t *prev = parent;
    lwaf_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->trust_proxy, prev->trust_proxy, 0);
    ngx_conf_merge_uint_value(conf->deny_status, prev->deny_status, 403);

    ngx_conf_merge_ptr_value(conf->whitelist, prev->whitelist, NULL);
    ngx_conf_merge_ptr_value(conf->blacklist, prev->blacklist, NULL);
    ngx_conf_merge_str_value(conf->rule_file, prev->rule_file, "");
    ngx_conf_merge_ptr_value(conf->rules, prev->rules, NULL);

    if (conf->thresholds.sql == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.sql = prev->thresholds.sql == LWAF_UNSET_THRESHOLD
                                   ? 8
                                   : prev->thresholds.sql;
    }
    if (conf->thresholds.xss == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.xss = prev->thresholds.xss == LWAF_UNSET_THRESHOLD
                                   ? 8
                                   : prev->thresholds.xss;
    }
    if (conf->thresholds.rfi == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.rfi = prev->thresholds.rfi == LWAF_UNSET_THRESHOLD
                                   ? 8
                                   : prev->thresholds.rfi;
    }
    if (conf->thresholds.traversal == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.traversal =
            prev->thresholds.traversal == LWAF_UNSET_THRESHOLD
                ? 8
                : prev->thresholds.traversal;
    }
    if (conf->thresholds.evade == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.evade = prev->thresholds.evade == LWAF_UNSET_THRESHOLD
                                     ? 8
                                     : prev->thresholds.evade;
    }
    if (conf->thresholds.upload == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.upload = prev->thresholds.upload == LWAF_UNSET_THRESHOLD
                                      ? 8
                                      : prev->thresholds.upload;
    }
    if (conf->thresholds.scan == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.scan = prev->thresholds.scan == LWAF_UNSET_THRESHOLD
                                    ? 8
                                    : prev->thresholds.scan;
    }
    if (conf->thresholds.total == LWAF_UNSET_THRESHOLD) {
        conf->thresholds.total = prev->thresholds.total == LWAF_UNSET_THRESHOLD
                                     ? 12
                                     : prev->thresholds.total;
    }

    ngx_conf_merge_value(conf->dynamic_block, prev->dynamic_block, 1);
    ngx_conf_merge_uint_value(conf->max_requests, prev->max_requests, 20);
    ngx_conf_merge_uint_value(conf->window, prev->window, 10);
    ngx_conf_merge_uint_value(conf->block_duration, prev->block_duration, 60);
    ngx_conf_merge_uint_value(conf->max_body_bytes, prev->max_body_bytes,
                              LWAF_DEFAULT_MAX_BODY_BYTES);
    ngx_conf_merge_str_value(conf->log_path, prev->log_path, "logs/waf_audit.log");

    /* 审计日志路径在配置期就解析成绝对路径。原实现把 ngx_conf_full_name()
     * 放在 lwaf_log_write() 里，等于每写一条日志做一次路径拼接——那是配置期
     * 函数，不该出现在请求路径上。fd 先置无效，等 worker 第一次写时再打开。 */
    conf->log_fd = NGX_INVALID_FILE;
    if (conf->log_path.len > 0) {
        ngx_str_t full = conf->log_path;

        if (ngx_conf_full_name((ngx_cycle_t *) cf->cycle, &full, 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        conf->log_path_full = full;

    } else {
        conf->log_path_full.len = 0;
        conf->log_path_full.data = NULL;
    }

    return NGX_CONF_OK;
}

/**
 * @brief Parse an IPv4/CIDR configuration token.
 *
 * @param text Input token, e.g. "192.168.1.0/24".
 * @param cidr Output CIDR structure.
 * @return NGX_OK on success, NGX_ERROR on invalid format.
 */
static ngx_int_t
lwaf_parse_ip_cidr(ngx_str_t *text, lwaf_access_cidr_t *cidr)
{
    struct in_addr in;
    ngx_int_t mask_bits = 32;
    u_char ip_buf[64];
    u_char mask_buf[8];
    size_t ip_len = 0;
    size_t mask_len = 0;

    ngx_memzero(ip_buf, sizeof(ip_buf));
    ngx_memzero(mask_buf, sizeof(mask_buf));

    for (ngx_uint_t i = 0; i < text->len; i++) {
        if (text->data[i] == '/') {
            for (i++; i < text->len && text->data[i] >= '0' &&
                      text->data[i] <= '9'; i++) {
                if (mask_len + 1 < sizeof(mask_buf)) {
                    mask_buf[mask_len++] = text->data[i];
                }
            }
            break;
        }
        if (ip_len + 1 < sizeof(ip_buf)) {
            ip_buf[ip_len++] = text->data[i];
        }
    }

    if (mask_len > 0) {
        mask_bits = ngx_atoi(mask_buf, mask_len);
        if (mask_bits < 0 || mask_bits > 32) {
            return NGX_ERROR;
        }
    }

    if (inet_pton(AF_INET, (char *)ip_buf, &in) != 1) {
        return NGX_ERROR;
    }

    cidr->addr = ntohl(in.s_addr);
    cidr->mask = mask_bits == 0 ? 0u : (0xffffffffu << (32 - mask_bits));
    return NGX_OK;
}

/**
 * @brief Test whether an IPv4 address belongs to a CIDR entry.
 *
 * @param ip Client IP in host byte order.
 * @param cidr CIDR entry.
 * @return NGX_OK when matched, NGX_DECLINED when not matched.
 */
static ngx_int_t
lwaf_ip_match_cidr(in_addr_t ip, lwaf_access_cidr_t *cidr)
{
    return (ip & cidr->mask) == (cidr->addr & cidr->mask)
               ? NGX_OK
               : NGX_DECLINED;
}

/**
 * @brief Add one CIDR token to a whitelist or blacklist array.
 *
 * @param cf Nginx configuration context.
 * @param list Target array pointer.
 * @param value CIDR token.
 * @return NGX_CONF_OK or an Nginx configuration error string.
 */
static char *
lwaf_access_list_add(ngx_conf_t *cf, ngx_array_t **list, ngx_str_t *value)
{
    lwaf_access_cidr_t *cidr;

    if (*list == NULL) {
        *list = ngx_array_create(cf->pool, 4, sizeof(lwaf_access_cidr_t));
        if (*list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(*list);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }
    if (lwaf_parse_ip_cidr(value, cidr) != NGX_OK) {
        return "invalid IPv4/CIDR value";
    }
    return NGX_CONF_OK;
}

/**
 * @brief Handle the `lite_waf_blacklist` directive.
 */
static char *
ngx_http_lite_waf_blacklist_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    lwaf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;

    (void)cmd;
    return lwaf_access_list_add(cf, &lcf->blacklist, &value[1]);
}

/**
 * @brief Handle the `lite_waf_whitelist` directive.
 */
static char *
ngx_http_lite_waf_whitelist_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    lwaf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;

    (void)cmd;
    return lwaf_access_list_add(cf, &lcf->whitelist, &value[1]);
}

/**
 * @brief Handle the `lite_waf_rule_file` directive.
 *
 * The rule file is parsed at configuration load/reload time so request handling
 * only traverses already compiled rules.
 */
static char *
ngx_http_lite_waf_rule_file_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    lwaf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;
    char errbuf[512];
    char *path;

    (void)cmd;

    if (lcf->rules != NULL) {
        return "is duplicate";
    }

    lcf->rule_file = value[1];
    if (ngx_conf_full_name(cf->cycle, &lcf->rule_file, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    lcf->rules = ngx_pcalloc(cf->pool, sizeof(lwaf_rule_set_t));
    if (lcf->rules == NULL) {
        return NGX_CONF_ERROR;
    }
    lwaf_rule_set_init(lcf->rules);

    path = ngx_pnalloc(cf->pool, lcf->rule_file.len + 1);
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(path, lcf->rule_file.data, lcf->rule_file.len);
    path[lcf->rule_file.len] = '\0';

    if (lwaf_rule_set_load_file(path, lcf->rules, errbuf, sizeof(errbuf)) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "lite_waf_rule_file failed: %s", errbuf);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 * @brief Handle `lite_waf_score_threshold CATEGORY VALUE`.
 */
static char *
ngx_http_lite_waf_score_threshold_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf)
{
    lwaf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_int_t threshold;

    (void)cmd;

    threshold = ngx_atoi(value[2].data, value[2].len);
    if (threshold < 0) {
        return "invalid score threshold";
    }

    if (value[1].len == 3 &&
        ngx_strncasecmp(value[1].data, (u_char *)"SQL", 3) == 0) {
        lcf->thresholds.sql = (ngx_uint_t)threshold;
    } else if (value[1].len == 3 &&
               ngx_strncasecmp(value[1].data, (u_char *)"XSS", 3) == 0) {
        lcf->thresholds.xss = (ngx_uint_t)threshold;
    } else if (value[1].len == 3 &&
               ngx_strncasecmp(value[1].data, (u_char *)"RFI", 3) == 0) {
        lcf->thresholds.rfi = (ngx_uint_t)threshold;
    } else if (value[1].len == 9 &&
               ngx_strncasecmp(value[1].data, (u_char *)"TRAVERSAL", 9) == 0) {
        lcf->thresholds.traversal = (ngx_uint_t)threshold;
    } else if (value[1].len == 5 &&
               ngx_strncasecmp(value[1].data, (u_char *)"EVADE", 5) == 0) {
        lcf->thresholds.evade = (ngx_uint_t)threshold;
    } else if (value[1].len == 6 &&
               ngx_strncasecmp(value[1].data, (u_char *)"UPLOAD", 6) == 0) {
        lcf->thresholds.upload = (ngx_uint_t)threshold;
    } else if (value[1].len == 4 &&
               ngx_strncasecmp(value[1].data, (u_char *)"SCAN", 4) == 0) {
        lcf->thresholds.scan = (ngx_uint_t)threshold;
    } else if (value[1].len == 5 &&
               ngx_strncasecmp(value[1].data, (u_char *)"TOTAL", 5) == 0) {
        lcf->thresholds.total = (ngx_uint_t)threshold;
    } else {
        return "unknown score category";
    }

    return NGX_CONF_OK;
}

/**
 * @brief Parse a one-argument unsigned integer directive into loc_conf.
 *
 * This avoids relying on signed-slot helper behavior for fields declared as
 * ngx_uint_t.
 */
static char *
ngx_http_lite_waf_uint_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *base = conf;
    ngx_uint_t *slot = (ngx_uint_t *)(base + cmd->offset);
    ngx_str_t *value = cf->args->elts;
    ngx_int_t parsed;

    if (*slot != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    parsed = ngx_atoi(value[1].data, value[1].len);
    if (parsed < 0) {
        return "invalid unsigned integer value";
    }

    *slot = (ngx_uint_t)parsed;
    return NGX_CONF_OK;
}

/**
 * @brief Extract client IP, honoring trusted X-Forwarded-For when enabled.
 *
 * @param r HTTP request.
 * @param conf Location configuration.
 * @param ip Output client IP in host byte order.
 * @return NGX_OK on success, NGX_DECLINED for non-IPv4 clients.
 */
static ngx_int_t
lwaf_get_client_ip(ngx_http_request_t *r, lwaf_loc_conf_t *conf, in_addr_t *ip)
{
    struct sockaddr_in *sin;

    if (r->connection->sockaddr->sa_family != AF_INET) {
        return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *)r->connection->sockaddr;
    *ip = ntohl(sin->sin_addr.s_addr);

    if (conf->trust_proxy && r->headers_in.x_forwarded_for != NULL) {
        ngx_table_elt_t *xff = r->headers_in.x_forwarded_for;
        u_char ip_buf[64];
        u_char *start = xff->value.data;
        u_char *end = start + xff->value.len;
        u_char *comma = ngx_strlchr(start, end, ',');
        struct in_addr in;
        size_t len;

        if (comma != NULL) {
            end = comma;
        }
        while (start < end && *start == ' ') {
            start++;
        }
        while (end > start && *(end - 1) == ' ') {
            end--;
        }

        len = (size_t)(end - start);
        if (len > 0 && len < sizeof(ip_buf)) {
            ngx_memcpy(ip_buf, start, len);
            ip_buf[len] = '\0';
            if (inet_pton(AF_INET, (char *)ip_buf, &in) == 1) {
                *ip = ntohl(in.s_addr);
            }
        }
    }

    return NGX_OK;
}

/**
 * @brief Check and update the shared leaky-bucket dynamic block table.
 *
 * Each request adds ::LWAF_LEAK_SCALE units of water. The bucket capacity is
 * `lite_waf_max_requests * LWAF_LEAK_SCALE`, and the leak rate is derived from
 * `lite_waf_window`: a full bucket drains over that many seconds. This keeps
 * the original configuration names compatible while avoiding fixed-window
 * boundary bursts.
 *
 * @param conf Location configuration.
 * @param client_ip Client IP in host byte order.
 * @return NGX_HTTP_FORBIDDEN when currently blocked, otherwise NGX_DECLINED.
 */
static ngx_int_t
lwaf_dynamic_check_and_update(lwaf_loc_conf_t *conf, in_addr_t client_ip)
{
    lwaf_ip_stat_t *stat = NULL;
    lwaf_shm_ctx_t *shm_ctx = lwaf_shared_ctx;
    lwaf_shm_store_t *store;
    ngx_time_t *tp;
    time_t now;
    uint64_t now_ms;
    ngx_int_t rc = NGX_DECLINED;
    ngx_uint_t capacity;
    ngx_uint_t window;

    if (!conf->dynamic_block) {
        return NGX_DECLINED;
    }
    if (shm_ctx == NULL || shm_ctx->shpool == NULL || shm_ctx->store == NULL) {
        return NGX_DECLINED;
    }

    tp = ngx_timeofday();
    now = tp->sec;
    now_ms = (uint64_t) tp->sec * 1000u + (uint64_t) tp->msec;
    store = shm_ctx->store;

    ngx_shmtx_lock(&shm_ctx->shpool->mutex);

    for (ngx_uint_t i = 0; i < store->stat_count; i++) {
        if (store->stats[i].used && store->stats[i].ip == client_ip) {
            stat = &store->stats[i];
            break;
        }
    }

    if (stat == NULL) {
        if (store->stat_count < LWAF_MAX_IP_STATS) {
            stat = &store->stats[store->stat_count++];
        } else {
            /* 表满了。旧实现是 `stats[now % LWAF_MAX_IP_STATS]`——now 是秒级时间戳，
             * 同一秒内所有新 IP 会挤到同一个槽位互相覆盖，还会把正在封禁中的记录
             * 一起挤掉，等于用 IP 池就能绕过 CC。
             * 改成：只回收「已过封禁期且最久没出现」的槽位；如果 4096 项全在封禁
             * 期内，本次不记账直接放行——宁可漏记一个新 IP，也不解除别人的封禁。 */
            lwaf_ip_stat_t *victim = NULL;

            for (ngx_uint_t i = 0; i < store->stat_count; i++) {
                if (store->stats[i].used && store->stats[i].block_expire <= now) {
                    if (victim == NULL || store->stats[i].last_seen < victim->last_seen) {
                        victim = &store->stats[i];
                    }
                }
            }

            if (victim == NULL) {
                ngx_shmtx_unlock(&shm_ctx->shpool->mutex);
                return NGX_DECLINED;
            }
            stat = victim;
        }
        ngx_memzero(stat, sizeof(*stat));
        stat->used = 1;
        stat->ip = client_ip;
        stat->last_seen = now;
        stat->last_seen_ms = now_ms;
        stat->water_level = 0;
        stat->block_expire = 0;
    }

    if (stat->block_expire > now) {
        rc = NGX_HTTP_FORBIDDEN;
        goto done;
    }

    if (conf->max_requests == 0) {
        stat->block_expire = now + (time_t)conf->block_duration;
        rc = NGX_HTTP_FORBIDDEN;
        goto done;
    }

    capacity = conf->max_requests * LWAF_LEAK_SCALE;
    window = conf->window == 0 ? 1 : conf->window;

    /* 泄漏按毫秒算。last_seen_ms == 0 说明是 reload 继承下来的旧槽位
     * （结构体新增字段），这时退回秒精度，等这一次更新写回毫秒值。 */
    if (stat->water_level > 0) {
        uint64_t elapsed_ms = 0;

        if (stat->last_seen_ms != 0 && now_ms > stat->last_seen_ms) {
            elapsed_ms = now_ms - stat->last_seen_ms;
        } else if (stat->last_seen_ms == 0 && now > stat->last_seen) {
            elapsed_ms = (uint64_t)(now - stat->last_seen) * 1000u;
        }

        if (elapsed_ms > 0) {
            ngx_uint_t leaked;

            /* leaked = elapsed_ms * capacity / (window * 1000) */
            if (elapsed_ms * capacity >= (uint64_t) stat->water_level * window * 1000u) {
                leaked = stat->water_level;
            } else {
                leaked = (ngx_uint_t)((elapsed_ms * capacity) /
                                      ((uint64_t) window * 1000u));
            }
            stat->water_level -= leaked;
        }
    }
    stat->last_seen = now;
    stat->last_seen_ms = now_ms;

    if (stat->water_level > capacity - LWAF_LEAK_SCALE) {
        stat->block_expire = now + (time_t)conf->block_duration;
        rc = NGX_HTTP_FORBIDDEN;
        goto done;
    }

    stat->water_level += LWAF_LEAK_SCALE;

done:
    ngx_shmtx_unlock(&shm_ctx->shpool->mutex);
    return rc;
}

/**
 * @brief Decide whether the current request body must be read for BODY rules.
 *
 * @param r HTTP request.
 * @return Non-zero when a request body may be present and should be captured.
 */
static ngx_int_t
lwaf_request_needs_body(ngx_http_request_t *r)
{
    if (r->headers_in.content_length_n > 0) {
        return 1;
    }
#if (nginx_version >= 1003009)
    if (r->headers_in.chunked) {
        return 1;
    }
#endif
    return 0;
}

/**
 * @brief Copy Nginx request-body buffers into one null-terminated pool string.
 *
 * The rule engine truncates normalized zones to ::LWAF_MAX_ZONE_TEXT. This
 * helper therefore captures a bounded raw prefix instead of allowing very large
 * uploads to consume request-pool memory during ACCESS_PHASE inspection.
 *
 * @param r HTTP request whose body has already been read.
 * @param state Per-request LiteWAF context receiving the captured body.
 * @return NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_int_t
lwaf_capture_request_body(ngx_http_request_t *r, lwaf_request_state_t *state)
{
    ngx_chain_t *cl;
    size_t total = 0;
    size_t copied = 0;
    u_char *dst;

    if (state == NULL) {
        return NGX_ERROR;
    }

    state->body_done = 1;
    state->body.len = 0;
    state->body.data = (u_char *)"";

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_OK;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL || b->pos == NULL || b->last == NULL || b->last < b->pos) {
            continue;
        }
        total += (size_t)(b->last - b->pos);
        if (total >= LWAF_MAX_CAPTURE_BODY) {
            total = LWAF_MAX_CAPTURE_BODY;
            break;
        }
    }

    if (total == 0) {
        return NGX_OK;
    }

    dst = ngx_pnalloc(r->pool, total + 1);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    for (cl = r->request_body->bufs; cl != NULL && copied < total; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        size_t len;

        if (b == NULL || b->pos == NULL || b->last == NULL || b->last < b->pos) {
            continue;
        }
        len = (size_t)(b->last - b->pos);
        if (len > total - copied) {
            len = total - copied;
        }
        ngx_memcpy(dst + copied, b->pos, len);
        copied += len;
    }

    dst[copied] = '\0';
    state->body.data = dst;
    state->body.len = copied;
    return NGX_OK;
}

/**
 * @brief Append JSON-escaped string content into a bounded buffer.
 *
 * The helper emits the content of a JSON string without surrounding quotes.
 * It escapes quotes, backslashes, common control characters, and other ASCII
 * control bytes as `\u00XX`.
 *
 * @param p Current write pointer.
 * @param last Last safe write position in the destination buffer.
 * @param data Raw bytes to escape.
 * @param len Number of bytes in @p data.
 * @return Updated write pointer.
 */
static u_char *
lwaf_json_escape(u_char *p, u_char *last, const u_char *data, size_t len)
{
    static const u_char hex[] = "0123456789abcdef";

    if (data == NULL) {
        return p;
    }

    for (size_t i = 0; i < len && p < last; i++) {
        u_char ch = data[i];

        switch (ch) {
        case '"':
        case '\\':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = ch;
            break;
        case '\b':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = 'b';
            break;
        case '\f':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = 'f';
            break;
        case '\n':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = 'n';
            break;
        case '\r':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = 'r';
            break;
        case '\t':
            if (p + 2 > last) {
                return p;
            }
            *p++ = '\\';
            *p++ = 't';
            break;
        default:
            if (ch < 0x20) {
                if (p + 6 > last) {
                    return p;
                }
                *p++ = '\\';
                *p++ = 'u';
                *p++ = '0';
                *p++ = '0';
                *p++ = hex[ch >> 4];
                *p++ = hex[ch & 0x0f];
            } else {
                *p++ = ch;
            }
            break;
        }
    }

    return p;
}

/**
 * @brief Write one JSON Lines audit event.
 *
 * 审计日志一条 = 一个被拦截的外部请求，固定 14 个字段：
 * `time`(UTC 毫秒数字)、`client_ip`、`method`、`uri`、`reason`、`rule_id`、
 * `rule_name`、`zone`、`category`、`score`、`total_score`、`action`、`status`、`cost_us`。
 *
 * 时间口径（S1 对齐需求卡片）：`time` 为 **UTC 毫秒** 整数，不用本地时区、不用秒级字符串；
 * 展示层再按 Asia/Shanghai 渲染。`category` 保留引擎原值（SQL/XSS/RFI/...），
 * `SQL→SQLi`、`dynamic_block`（category 为空）→ CC 的展示映射交给采集/后端适配层，不改源日志。
 *
 * @param r HTTP request.
 * @param conf Location configuration.
 * @param client_ip Client IP in host byte order.
 * @param event Event fields.
 * @return NGX_OK when the log write succeeds, NGX_ERROR otherwise.
 */
static ngx_int_t
lwaf_log_write(ngx_http_request_t *r, lwaf_loc_conf_t *conf, in_addr_t client_ip,
               lwaf_log_event_t *event)
{
    ngx_fd_t fd;
    u_char ip_text[NGX_INET_ADDRSTRLEN];
    u_char line[4096];
    u_char *p;
    u_char *last;
    size_t len;
    const char *reason = event->reason != NULL ? event->reason : "";
    const char *action = event->action != NULL ? event->action : "";
    const char *rule_name = event->rule_name != NULL ? event->rule_name : "";
    const char *zone = event->zone != NULL ? event->zone : "";
    const char *category = event->category != NULL ? event->category : "";

    if (conf->log_path_full.len == 0) {
        return NGX_ERROR;
    }

    /* fd 复用：O_APPEND 语义下单次 write 落到文件末尾，多 worker 各自持有
     * 自己的 fd 并发写同一文件是安全的（内核保证 append 原子性）。
     * logrotate 用 copytruncate，inode 不变，所以 fd 一直有效。 */
    if (conf->log_fd == NGX_INVALID_FILE) {
        conf->log_fd = ngx_open_file(conf->log_path_full.data, NGX_FILE_APPEND,
                                     NGX_FILE_CREATE_OR_OPEN,
                                     NGX_FILE_DEFAULT_ACCESS);
        if (conf->log_fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "LiteWAF failed to open audit log \"%V\"",
                          &conf->log_path_full);
            return NGX_ERROR;
        }
    }
    fd = conf->log_fd;

    lwaf_ip_to_text(client_ip, ip_text, sizeof(ip_text));
    p = line;
    last = line + sizeof(line) - 2;

    /* `time` 输出 UTC 毫秒整数（epoch ms），不再是秒级字符串：
     * 采集器直接落库为 event_time_ms，同一秒内的多条事件也能按毫秒严格排序。 */
    {
        ngx_time_t *tp = ngx_timeofday();

        p = ngx_snprintf(p, last - p,
                         "{\"time\":%L,\"client_ip\":\"%s\",\"method\":\"",
                         (int64_t) tp->sec * 1000 + tp->msec, ip_text);
    }
    p = lwaf_json_escape(p, last, r->method_name.data, r->method_name.len);
    p = ngx_snprintf(p, last - p, "\",\"uri\":\"");
    p = lwaf_json_escape(p, last, r->unparsed_uri.data, r->unparsed_uri.len);
    p = ngx_snprintf(p, last - p, "\",\"reason\":\"");
    p = lwaf_json_escape(p, last, (const u_char *)reason, ngx_strlen(reason));
    p = ngx_snprintf(p, last - p, "\",\"rule_id\":%ui,\"rule_name\":\"",
                     event->rule_id);
    p = lwaf_json_escape(p, last, (const u_char *)rule_name,
                         ngx_strlen(rule_name));
    p = ngx_snprintf(p, last - p, "\",\"zone\":\"");
    p = lwaf_json_escape(p, last, (const u_char *)zone, ngx_strlen(zone));
    p = ngx_snprintf(p, last - p, "\",\"category\":\"");
    p = lwaf_json_escape(p, last, (const u_char *)category,
                         ngx_strlen(category));
    p = ngx_snprintf(p, last - p,
                     "\",\"score\":%ui,\"total_score\":%ui,\"action\":\"",
                     event->score, event->total_score);
    p = lwaf_json_escape(p, last, (const u_char *)action, ngx_strlen(action));
    p = ngx_snprintf(p, last - p, "\",\"status\":%ui,\"cost_us\":%ui}\n",
                     event->status, event->cost_us);

    len = (size_t) (p - line);
    if (ngx_write_fd(fd, line, len) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "LiteWAF failed to write audit log");
        /* 写失败就丢掉缓存的 fd，下次调用重新 open（例如磁盘满、inode 被替换） */
        ngx_close_file(fd);
        conf->log_fd = NGX_INVALID_FILE;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief Return the first match from a B score result, if present.
 *
 * @param result B score result.
 * @return First match pointer, or NULL.
 */
static const lwaf_match_t *
lwaf_first_match(const lwaf_score_result_t *result)
{
    return result->match_count > 0 ? &result->matches[0] : NULL;
}

/**
 * @brief Find a kept match by rule ID.
 *
 * @param result B score result.
 * @param rule_id Rule ID to find.
 * @return Matching audit record, or NULL.
 */
static const lwaf_match_t *
lwaf_find_match_by_rule_id(const lwaf_score_result_t *result, ngx_uint_t rule_id)
{
    for (size_t i = 0; i < result->match_count; i++) {
        if (result->matches[i].rule_id == rule_id) {
            return &result->matches[i];
        }
    }
    return NULL;
}

/**
 * @brief Resume ACCESS_PHASE processing after Nginx finishes reading the body.
 *
 * @param r HTTP request whose body read has completed.
 */
static void
ngx_http_lite_waf_body_handler(ngx_http_request_t *r)
{
    lwaf_request_state_t *state;

    state = ngx_http_get_module_ctx(r, ngx_http_lite_waf_module);
    if (state != NULL) {
        state->waiting_body = 0;
        (void)lwaf_capture_request_body(r, state);
    }

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

/**
 * @brief Main ACCESS_PHASE request handler.
 *
 * @param r HTTP request.
 * @return NGX_DECLINED to pass, or configured deny status to block.
 */
static ngx_int_t
ngx_http_lite_waf_handler(ngx_http_request_t *r)
{
    lwaf_loc_conf_t *conf;
    lwaf_request_state_t *state;
    lwaf_access_cidr_t *cidr;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_lite_waf_module);
    if (!conf->enable) {
        return NGX_DECLINED;
    }
    if (r->internal) {
        return NGX_DECLINED;
    }

    state = ngx_http_get_module_ctx(r, ngx_http_lite_waf_module);
    if (state == NULL) {
        state = ngx_pcalloc(r->pool, sizeof(*state));
        if (state == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        state->started_us = lwaf_now_us();
        ngx_http_set_ctx(r, state, ngx_http_lite_waf_module);
    }

    if (state->waiting_body) {
        return NGX_DONE;
    }

    if (!state->precheck_done) {
        if (lwaf_get_client_ip(r, conf, &state->client_ip) != NGX_OK) {
            return NGX_DECLINED;
        }

        if (conf->whitelist != NULL) {
            cidr = conf->whitelist->elts;
            for (ngx_uint_t i = 0; i < conf->whitelist->nelts; i++) {
                if (lwaf_ip_match_cidr(state->client_ip, &cidr[i]) == NGX_OK) {
                    return NGX_DECLINED;
                }
            }
        }

        if (conf->blacklist != NULL) {
            cidr = conf->blacklist->elts;
            for (ngx_uint_t i = 0; i < conf->blacklist->nelts; i++) {
                if (lwaf_ip_match_cidr(state->client_ip, &cidr[i]) == NGX_OK) {
                    lwaf_log_event_t event = {
                        .reason = "blacklist",
                        .action = "deny",
                        .status = conf->deny_status,
                        .cost_us = lwaf_now_us() - state->started_us,
                    };
                    (void)lwaf_log_write(r, conf, state->client_ip, &event);
                    return (ngx_int_t)conf->deny_status;
                }
            }
        }

        if (lwaf_dynamic_check_and_update(conf, state->client_ip) ==
            NGX_HTTP_FORBIDDEN) {
            lwaf_log_event_t event = {
                .reason = "dynamic_block",
                .action = "deny",
                .status = conf->deny_status,
                .cost_us = lwaf_now_us() - state->started_us,
            };
            (void)lwaf_log_write(r, conf, state->client_ip, &event);
            return (ngx_int_t)conf->deny_status;
        }

        state->precheck_done = 1;
    }

    if (!state->body_done && lwaf_request_needs_body(r)) {
        ngx_int_t rc;

        /* 请求体硬上限：有 Content-Length 且超过上限时直接拒绝，不再"截断后
         * 只查前 8KB"——旧行为等于给攻击者留了一条「垫填充绕过检测」的路。
         * chunked 请求没有 Content-Length，这里无法预判，退化为截断检测
         * （lwaf_capture_request_body 仍会记录实际截断长度）。 */
        if (conf->max_body_bytes > 0
            && r->headers_in.content_length_n > 0
            && (off_t) r->headers_in.content_length_n
                   > (off_t) conf->max_body_bytes)
        {
            lwaf_log_event_t event = {
                .reason = "body_too_large",
                .action = "deny",
                .status = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                .cost_us = lwaf_now_us() - state->started_us,
            };
            (void)lwaf_log_write(r, conf, state->client_ip, &event);
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        r->request_body_in_single_buf = 0;
        r->request_body_in_persistent_file = 0;
        r->request_body_in_clean_file = 1;
        state->waiting_body = 1;

        rc = ngx_http_read_client_request_body(r,
                                               ngx_http_lite_waf_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            state->waiting_body = 0;
            return rc;
        }
        if (rc == NGX_AGAIN) {
            return NGX_DONE;
        }

        state->waiting_body = 0;
        if (lwaf_capture_request_body(r, state) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else if (!state->body_done) {
        state->body_done = 1;
        state->body.data = (u_char *)"";
        state->body.len = 0;
    }

    if (conf->rules != NULL && conf->rules->count > 0) {
        lwaf_request_context_t *ctx;
        lwaf_score_result_t *result;

        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        result = ngx_pcalloc(r->pool, sizeof(*result));
        if (ctx == NULL || result == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        lwaf_build_request_context(r, state, ctx);
        lwaf_evaluate_request(ctx, conf->rules, &conf->thresholds,
                              conf->deny_status, result);
        if (result->blocked) {
            const lwaf_match_t *match =
                result->decisive_rule_id != 0
                    ? lwaf_find_match_by_rule_id(result, result->decisive_rule_id)
                    : lwaf_first_match(result);
            const char *reason = result->decisive_rule_id != 0
                                     ? "rule_block"
                                     : result->reason;
            lwaf_log_event_t event = {
                .reason = reason,
                .action = "deny",
                .status = result->status,
                .rule_id = match != NULL ? match->rule_id : result->decisive_rule_id,
                .rule_name = match != NULL ? match->rule_name : "",
                .zone = match != NULL ? lwaf_zone_name(match->zone) : "",
                .category = match != NULL ? lwaf_category_name(match->category) : "",
                .score = match != NULL ? match->score : 0,
                .total_score = result->scores[LWAF_TOTAL],
                .cost_us = lwaf_now_us() - state->started_us,
            };
            (void)lwaf_log_write(r, conf, state->client_ip, &event);
            return (ngx_int_t)result->status;
        }
    }

    return NGX_DECLINED;
}

/**
 * @brief Initialize or inherit the shared leaky-bucket dynamic block zone.
 *
 * @param shm_zone Nginx shared memory zone descriptor.
 * @param data Previous-cycle zone data during reload, or NULL on cold start.
 * @return NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_int_t
ngx_http_lite_waf_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    lwaf_shm_ctx_t *ctx = shm_zone->data;
    lwaf_shm_ctx_t *old = data;

    if (old != NULL) {
        ctx->shpool = old->shpool;
        ctx->store = old->store;
        lwaf_shared_ctx = ctx;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ctx->store = ngx_slab_alloc(ctx->shpool, sizeof(lwaf_shm_store_t));
    if (ctx->store == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx->store, sizeof(lwaf_shm_store_t));
    lwaf_shared_ctx = ctx;
    return NGX_OK;
}

/**
 * @brief Register the ACCESS_PHASE handler.
 *
 * @param cf Nginx configuration context.
 * @return NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_int_t
ngx_http_lite_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_shm_zone_t *shm_zone;
    lwaf_shm_ctx_t *shm_ctx;
    ngx_str_t shm_name = ngx_string(LWAF_SHM_ZONE_NAME);

    shm_ctx = ngx_pcalloc(cf->pool, sizeof(*shm_ctx));
    if (shm_ctx == NULL) {
        return NGX_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &shm_name, LWAF_SHM_ZONE_SIZE,
                                     &ngx_http_lite_waf_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }
    if (shm_zone->data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate LiteWAF shared memory zone \"%V\"",
                           &shm_name);
        return NGX_ERROR;
    }
    shm_zone->init = ngx_http_lite_waf_init_shm_zone;
    shm_zone->data = shm_ctx;
    lwaf_shared_ctx = shm_ctx;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_lite_waf_handler;
    return NGX_OK;
}

/**
 * @brief Configuration directives exposed by LiteWAF-NGX.
 */
static ngx_command_t ngx_http_lite_waf_commands[] = {
    { ngx_string("lite_waf"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, enable),
      NULL },

    { ngx_string("lite_waf_trust_proxy"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, trust_proxy),
      NULL },

    { ngx_string("lite_waf_deny_status"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_uint_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, deny_status),
      NULL },

    { ngx_string("lite_waf_blacklist"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_blacklist_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lite_waf_whitelist"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_whitelist_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lite_waf_rule_file"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_rule_file_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lite_waf_score_threshold"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_lite_waf_score_threshold_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lite_waf_dynamic_block"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, dynamic_block),
      NULL },

    { ngx_string("lite_waf_max_requests"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_uint_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, max_requests),
      NULL },

    { ngx_string("lite_waf_window"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_uint_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, window),
      NULL },

    { ngx_string("lite_waf_block_duration"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_uint_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, block_duration),
      NULL },

    { ngx_string("lite_waf_max_body_bytes"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_lite_waf_uint_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, max_body_bytes),
      NULL },

    { ngx_string("lite_waf_log_path"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(lwaf_loc_conf_t, log_path),
      NULL },

    ngx_null_command
};

/**
 * @brief Nginx HTTP module context.
 */
static ngx_http_module_t ngx_http_lite_waf_module_ctx = {
    NULL,
    ngx_http_lite_waf_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_lite_waf_create_loc_conf,
    ngx_http_lite_waf_merge_loc_conf
};

/**
 * @brief Nginx module entry symbol.
 */
ngx_module_t ngx_http_lite_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_lite_waf_module_ctx,
    ngx_http_lite_waf_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};
