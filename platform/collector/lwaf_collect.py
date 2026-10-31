#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lwaf_collect.py —— LiteWAF 日志采集器（S2 交付物）

职责（需求卡片 R33-07）：
  * 全平台**唯一**的 tail 承担者：后台看板、告警、导出都读数据库，不许各自再读日志
  * 每 1 秒扫一次增量，按完整换行切分，单批 ≤500 行
  * 主去重键 = 来源 + 文件身份(dev:ino) + 代次 + 字节偏移；游标在「数据行 + 错误行 + 游标」
    同一个事务里推进，提交失败就整批回滚、不推进，退避 1/2/5/10/30 秒
  * 支持 rename + create 轮转（inode 变化自动开新代次），**不支持** copytruncate
  * 磁盘 85% 告警、95% 停采（两者都不删数据）
  * 解析失败的行原样进 ingest_errors，不阻塞正常行

用法：
    python3 lwaf_collect.py --config config.ini          # 常驻
    python3 lwaf_collect.py --config config.ini --once   # 只跑一轮（测试/灌数据）
    python3 lwaf_collect.py --config config.ini --once --verbose

退出码：0 正常；2 配置错误；3 数据库连不上。
"""

import argparse
import configparser
import json
import os
import shutil
import signal
import sys
import time

import pymysql

# ---------------------------------------------------------------- 固定参数
BATCH_MAX = 500          # 单批最多处理行数（需求卡片口径）
POLL_INTERVAL = 1.0      # 轮询间隔（秒）
BACKOFF = [1, 2, 5, 10, 30]   # 失败退避序列
DISK_WARN_PCT = 85.0
DISK_STOP_PCT = 95.0

# 展示映射：引擎原值 → 教材九类里对应的名字（需求卡片第 111 行：映射在适配层做，不改源文件）
DISPLAY_MAP = {
    "SQL": "SQLi",
    "XSS": "XSS",
    "TRAVERSAL": "Traversal",
    "RFI": "RFI",
    "UPLOAD": "Upload",
    "SCAN": "Scanner",
    "EVADE": "Evasion",
    "ACL": "ACL",
    "CC": "CC",
}

_stop = False


def _on_signal(signum, _frame):
    """收到 SIGTERM/SIGINT 时只置标志，让当前事务跑完再退"""
    global _stop
    _stop = True
    log(f"收到信号 {signum}，当前批次处理完就退出")


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- 解析
class ParseError(ValueError):
    """单行解析失败（进 ingest_errors，不影响其它行）"""


def display_category(category, reason):
    """把引擎原值映射成展示类目；漏桶事件没有 category，靠 reason 判 CC"""
    if reason == "dynamic_block":
        return "CC"
    if reason == "blacklist":
        return "ACL"
    return DISPLAY_MAP.get((category or "").upper(), category or "UNKNOWN")


def _need(obj, key, typ, default=None):
    """取必填字段并校验类型；缺失或类型不对抛 ParseError（带字段名，方便定位）"""
    if key not in obj:
        if default is not None:
            return default
        raise ParseError(f"缺字段 {key}")
    val = obj[key]
    try:
        if typ is int:
            return int(val)
        if typ is float:
            return float(val)
        return str(val)
    except (TypeError, ValueError):
        raise ParseError(f"字段 {key} 类型不对: {val!r}")


def _to_ms(value):
    """把日志里的时间统一成毫秒。

    nginx 的 $msec 是「秒.毫秒」浮点（1792645000.123），而 fixture 里是毫秒整数
    （1789862400000）。用数量级区分：1e11 毫秒 = 1973 年、1e11 秒 = 5138 年，
    正常时间戳不会跨过这条线，所以小于 1e11 的一律当秒处理。
    """
    t = float(value)
    return int(round(t * 1000)) if t < 1e11 else int(t)


def parse_access(raw):
    """解析访问日志一行（字段：time/client_ip/method/uri/status/body_bytes_sent/request_time）"""
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ParseError("不是 JSON 对象")
    if "time" not in obj:
        raise ParseError("缺字段 time")
    return {
        "event_time_ms": _to_ms(obj["time"]),
        "client_ip": _need(obj, "client_ip", str),
        "method": _need(obj, "method", str, "GET"),
        "uri": _need(obj, "uri", str),
        "status": _need(obj, "status", int),
        "body_bytes_sent": _need(obj, "body_bytes_sent", int, 0),
        # 源日志是秒（$request_time），统一换成毫秒存
        "request_time_ms": round(_need(obj, "request_time", float, 0.0) * 1000, 3),
    }


def parse_waf(raw):
    """解析 WAF 审计日志一行（14 字段，见 docs/基线说明.md）"""
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ParseError("不是 JSON 对象")
    category = _need(obj, "category", str, "")
    reason = _need(obj, "reason", str, "")
    return {
        "event_time_ms": _need(obj, "time", int),
        "client_ip": _need(obj, "client_ip", str),
        "method": _need(obj, "method", str, "GET"),
        "uri": _need(obj, "uri", str),
        "reason": reason,
        "rule_id": _need(obj, "rule_id", int, 0),
        "rule_name": _need(obj, "rule_name", str, ""),
        "zone": _need(obj, "zone", str, ""),
        "category": category,
        "category_display": display_category(category, reason),
        "score": _need(obj, "score", int, 0),
        "total_score": _need(obj, "total_score", int, 0),
        "action": _need(obj, "action", str, ""),
        "status": _need(obj, "status", int, 403),
        "cost_us": _need(obj, "cost_us", int, 0),
    }


SQL_ACCESS = (
    "INSERT INTO requests (event_time_ms, client_ip, method, uri, status, "
    "body_bytes_sent, request_time_ms, source_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
)
SQL_WAF = (
    "INSERT INTO waf_events (event_time_ms, client_ip, method, uri, reason, rule_id, "
    "rule_name, zone, category, category_display, score, total_score, action, status, "
    "cost_us, source_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)
SQL_ERR = (
    "INSERT INTO ingest_errors (source_id, raw_line, error) VALUES (%s,%s,%s)"
)


# ---------------------------------------------------------------- 采集器
class Collector:
    def __init__(self, cfg, verbose=False):
        self.verbose = verbose
        self.poll = float(cfg.get("collector", "poll_interval", fallback=POLL_INTERVAL))
        self.batch = int(cfg.get("collector", "batch_max", fallback=BATCH_MAX))
        self.batch = max(1, min(self.batch, 5000))
        self.db_cfg = {
            "host": cfg.get("db", "host", fallback="127.0.0.1"),
            "port": int(cfg.get("db", "port", fallback="3306")),
            "user": cfg.get("db", "user"),
            "password": cfg.get("db", "password"),
            "database": cfg.get("db", "database", fallback="litewaf"),
            "charset": "utf8mb4",
            "autocommit": False,
            # 本机回环连 MariaDB 不需要 TLS；显式关掉，否则某些 pymysql/MariaDB 组合
            # 会在握手阶段报 TLSV1_ALERT_INTERNAL_ERROR。配置里可写 ssl_disabled=false 打开。
            "ssl_disabled": cfg.get("db", "ssl_disabled", fallback="true").strip().lower()
            in ("1", "true", "yes", "on"),
        }
        # sources 段：name = /abs/path|kind
        self.sources = []
        if cfg.has_section("sources"):
            for name, spec in cfg.items("sources"):
                spec = spec.strip()
                if "|" not in spec:
                    raise ValueError(f"sources.{name} 格式应为 <绝对路径>|<waf|access>")
                path, kind = spec.rsplit("|", 1)
                path, kind = path.strip(), kind.strip()
                if kind not in ("waf", "access"):
                    raise ValueError(f"sources.{name} kind 只能是 waf 或 access")
                if not os.path.isabs(path):
                    raise ValueError(f"sources.{name} 必须是绝对路径: {path}")
                self.sources.append({"name": name, "path": path, "kind": kind})
        if not self.sources:
            raise ValueError("配置里没有任何 sources")
        self.db = None

        # ---- 运行状态（给平台侧 /api/collector/status 读）----
        # 采集器是独立进程，平台不知道它活着没有。每轮把心跳、游标滞后、
        # 累计入库/错误数写到这个 JSON，后端读文件 + 判断新鲜度即可。
        self.status_file = cfg.get("collector", "status_file",
                                   fallback="/opt/litewaf/runtime/logs/collector_status.json")
        self.started_ms = int(time.time() * 1000)
        self.stat = {
            "ingested_total": 0,   # 累计入库行数
            "errors_total": 0,     # 累计被记为错误行的条数
            "rounds": 0,           # 跑了多少轮
            "last_error": "",      # 最近一次异常摘要
        }

    # ------------------------------------------------------------ 连接
    def connect(self):
        if self.db is not None:
            try:
                self.db.ping(reconnect=True)
                return
            except Exception:
                self.db = None
        self.db = pymysql.connect(**self.db_cfg)

    def close(self):
        if self.db is not None:
            try:
                self.db.close()
            finally:
                self.db = None

    # ------------------------------------------------------------ 来源注册
    def ensure_sources(self):
        """把配置里的来源写进 ingest_sources（名字唯一，存在就复用 id）"""
        with self.db.cursor() as cur:
            for src in self.sources:
                cur.execute(
                    "INSERT INTO ingest_sources (name, path, kind) VALUES (%s,%s,%s) "
                    "ON DUPLICATE KEY UPDATE path=VALUES(path), kind=VALUES(kind)",
                    (src["name"], src["path"], src["kind"]),
                )
            for src in self.sources:
                cur.execute("SELECT id FROM ingest_sources WHERE name=%s", (src["name"],))
                src["id"] = cur.fetchone()[0]
        self.db.commit()

    # ------------------------------------------------------------ 游标
    def _cursor_state(self, cur, source_id, fid, size):
        """取当前文件的 (代次, 偏移)；首次见到的文件身份从 0 开始"""
        cur.execute(
            "SELECT generation, byte_offset, inode_size FROM ingest_cursors "
            "WHERE source_id=%s AND file_identity=%s ORDER BY generation DESC LIMIT 1",
            (source_id, fid),
        )
        row = cur.fetchone()
        if row is None:
            return 1, 0
        gen, off, _old_size = row
        if size < off:
            # 同一 inode 被截断（copytruncate / 人工清空）：开新代次从头读，
            # 旧代次记录留着，便于事后核对「是不是有人清空了日志」
            gen += 1
            off = 0
        return gen, off

    def _save_cursor(self, cur, source_id, fid, gen, off, size):
        cur.execute(
            "INSERT INTO ingest_cursors (source_id, file_identity, generation, byte_offset, inode_size) "
            "VALUES (%s,%s,%s,%s,%s) "
            "ON DUPLICATE KEY UPDATE byte_offset=VALUES(byte_offset), inode_size=VALUES(inode_size)",
            (source_id, fid, gen, off, size),
        )

    # ------------------------------------------------------------ 单文件一轮
    def collect_source(self, src):
        """读一个来源的增量并入库，返回本轮处理的行数"""
        path = src["path"]
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return 0  # 文件还没生成，等下一轮
        fid = f"{st.st_dev}:{st.st_ino}"
        # 先把进度记下来：即使这轮没有新内容（提前 return），状态文件里也要有真实进度，
        # 否则页面会一直显示 offset=0/size=0，看不出采集器跟没跟上。
        src["_size"] = st.st_size

        with self.db.cursor() as cur:
            gen, off = self._cursor_state(cur, src["id"], fid, st.st_size)
            self._save_cursor(cur, src["id"], fid, gen, off, st.st_size)
            self.db.commit()
        src["_offset"] = off

        if st.st_size <= off:
            return 0  # 没有新内容

        # 只读增量，避免每次从头扫（10 万行也不怕）
        with open(path, "rb") as f:
            f.seek(off)
            chunk = f.read(st.st_size - off)

        # 只处理以换行结尾的完整行；尾部半行留到下次（也许正在写）
        cut = chunk.rfind(b"\n")
        if cut < 0:
            return 0
        body = chunk[: cut + 1]

        lines = body.split(b"\n")[:-1]
        if len(lines) > self.batch:
            lines = lines[: self.batch]
            body = b"\n".join(lines) + b"\n"

        rows, errs = [], []
        for raw in lines:
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                parse = parse_waf if src["kind"] == "waf" else parse_access
                rec = parse(text)
                rows.append((src["kind"], rec))
            except Exception as exc:  # 单行坏，不影响整批
                errs.append((src["id"], text[:4000], f"{type(exc).__name__}: {exc}"[:255]))

        # 数据行 + 错误行 + 游标推进，同一个事务
        self.db.begin()
        try:
            with self.db.cursor() as cur:
                if src["kind"] == "waf":
                    cur.executemany(
                        SQL_WAF,
                        [tuple(r[k] for k in (
                            "event_time_ms", "client_ip", "method", "uri", "reason",
                            "rule_id", "rule_name", "zone", "category", "category_display",
                            "score", "total_score", "action", "status", "cost_us"))
                         + (src["id"],) for _k, r in rows],
                    )
                else:
                    cur.executemany(
                        SQL_ACCESS,
                        [tuple(r[k] for k in (
                            "event_time_ms", "client_ip", "method", "uri",
                            "status", "body_bytes_sent", "request_time_ms"))
                         + (src["id"],) for _k, r in rows],
                    )
                if errs:
                    cur.executemany(SQL_ERR, errs)
                self._save_cursor(cur, src["id"], fid, gen, off + len(body), st.st_size)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

        if errs:
            log(f"{src['name']}: {len(errs)} 行解析失败（已记 ingest_errors）")
        if self.verbose and rows:
            log(f"{src['name']}: +{len(rows)} 行，偏移 {off} → {off + len(body)}")

        # 状态累计：给 /api/collector/status 用
        self.stat["ingested_total"] += len(rows)
        self.stat["errors_total"] += len(errs)
        src["_offset"] = off + len(body)
        src["_size"] = st.st_size
        return len(rows)

    # ------------------------------------------------------------ 运行状态
    def write_status(self):
        """把心跳与滞后情况写成 JSON，供后端 /api/collector/status 读取。

        写成"先写临时文件再 os.replace"的原子替换：后端随时可能来读，
        不能让它读到写了一半的 JSON。
        """
        now = int(time.time() * 1000)
        sources = []
        for src in self.sources:
            size = src.get("_size") or 0
            off = src.get("_offset") or 0
            sources.append({
                "name": src["name"],
                "kind": src["kind"],
                "path": src["path"],
                "offset": off,
                "size": size,
                # lag = 还没读的字节数；一直涨说明采不过来了
                "lag_bytes": max(0, size - off),
            })
        payload = {
            "schema_version": 1,
            "ts": now,
            "started_ms": self.started_ms,
            "pid": os.getpid(),
            "poll_interval_s": self.poll,
            "batch_max": self.batch,
            "rounds": self.stat["rounds"],
            "ingested_total": self.stat["ingested_total"],
            "errors_total": self.stat["errors_total"],
            "last_error": self.stat["last_error"],
            "sources": sources,
        }
        try:
            os.makedirs(os.path.dirname(self.status_file), exist_ok=True)
            tmp = f"{self.status_file}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            os.replace(tmp, self.status_file)
        except OSError as exc:
            # 状态写不进去不能影响采集本身，只记一行日志
            log(f"状态文件写入失败（不影响采集）：{exc}")

    # ------------------------------------------------------------ 磁盘水位
    def check_disk(self):
        usage = shutil.disk_usage("/")
        pct = usage.used / usage.total * 100
        if pct >= DISK_STOP_PCT:
            log(f"磁盘 {pct:.1f}% 超过 {DISK_STOP_PCT}%，停止采集（数据保留，请人工清理）")
            return False
        if pct >= DISK_WARN_PCT:
            log(f"警告：磁盘 {pct:.1f}% 超过 {DISK_WARN_PCT}%")
        return True

    # ------------------------------------------------------------ 主循环
    def run(self):
        if not self.check_disk():
            return 3
        self.connect()
        self.ensure_sources()
        log(f"采集器启动：{len(self.sources)} 个来源，轮询 {self.poll}s，单批 {self.batch} 行")
        log(f"状态文件：{self.status_file}（每轮刷新一次）")

        bo_idx = 0
        disk_tick = 0
        while not _stop:
            try:
                total = 0
                for src in self.sources:
                    total += self.collect_source(src)
                bo_idx = 0
                if total and self.verbose:
                    log(f"本轮共 {total} 行")
            except Exception as exc:
                wait = BACKOFF[min(bo_idx, len(BACKOFF) - 1)]
                log(f"采集失败：{type(exc).__name__}: {exc}；{wait}s 后重试")
                self.stat["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
                self.write_status()
                self.close()
                bo_idx += 1
                # 退避期间也要能响应 SIGTERM
                for _ in range(int(wait * 10)):
                    if _stop:
                        break
                    time.sleep(0.1)
                continue

            # 每轮心跳
            self.stat["rounds"] += 1
            self.write_status()

            # 每 60 秒看一次磁盘，避免每轮 statfs 太勤
            disk_tick += 1
            if disk_tick * self.poll >= 60:
                disk_tick = 0
                if not self.check_disk():
                    return 3

            for _ in range(int(self.poll * 10)):
                if _stop:
                    break
                time.sleep(0.1)

        log("采集器退出")
        self.close()
        return 0

    def run_once(self):
        """把当前积压全部采完再退出（测试/初始导入用）

        注意：一轮最多处理 batch 行；积压多时要循环到「本轮 0 行」为止，
        否则 --once 看起来只采了 500 行，会被误判成漏采。
        """
        self.connect()
        self.ensure_sources()
        total = 0
        rounds = 0
        while not _stop:
            n = 0
            for src in self.sources:
                n += self.collect_source(src)
            rounds += 1
            total += n
            if n == 0:
                break
        log(f"单轮完成，共 {total} 行（{rounds} 批）")
        self.close()
        return total


# ---------------------------------------------------------------- 入口
def load_config(path):
    cfg = configparser.ConfigParser()
    if not cfg.read(path, encoding="utf-8"):
        raise FileNotFoundError(f"读不到配置：{path}")
    return cfg


def main():
    ap = argparse.ArgumentParser(description="LiteWAF 日志采集器")
    ap.add_argument("--config", required=True, help="ini 配置文件路径")
    ap.add_argument("--once", action="store_true", help="只跑一轮后退出")
    ap.add_argument("--verbose", action="store_true", help="打印每批明细")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        cfg = load_config(args.config)
        collector = Collector(cfg, verbose=args.verbose)
    except Exception as exc:
        log(f"配置错误：{exc}")
        return 2

    try:
        if args.once:
            collector.run_once()
            return 0
        return collector.run()
    except pymysql.err.OperationalError as exc:
        log(f"数据库连不上：{exc}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
