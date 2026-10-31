#!/usr/bin/env python3
"""
LiteWAF 引擎执行器（engine-exec）—— 平台与 nginx 之间唯一的「动手」通道。

设计约束（需求卡片 R37-04 / R34-01 / R34-09）：
  * 只监听 127.0.0.1，外部网络访问不到
  * 每个请求必须带 X-Engine-Token（文件 /opt/litewaf/runtime/engine.token，权限 600）
  * 只认四个动作：check / publish / rollback / status，没有第五个
  * 参数只接受 candidate_id / 规则文本 / CC 三个整数，绝不接受可执行路径、shell 片段、任意命令
  * 调 nginx 一律用参数数组（subprocess list），不经过 shell，杜绝命令拼接

一次「候选」= 规则文本 + CC 三参数（max_requests / window / block_duration），
发布时两者一起生效、一起回退，避免"规则改了但 CC 还是旧的"这种半套状态。

发布语义：
  check    —— 候选写成临时文件，用真实 nginx 做 `nginx -t`（只校验、不 reload）
  publish  —— 候选转正式版本 → 原子替换规则文件 + nginx.conf 的 CC 三行 → `nginx -s reload`
              → 新 TCP 连接连打 probe 3 次确认 worker 真的换了配置
              → 失败自动回滚到发布前，不会把线上留在半死状态
  rollback —— 把 current 切回 previous（规则 + CC 一起回滚，同样 reload + 探测）

启动（root）：
    sudo /usr/bin/python3 /opt/litewaf/engine/engine_exec.py
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RT = "/opt/litewaf/runtime"
NGINX_BIN = "/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx"
LISTEN = ("127.0.0.1", 18081)
SITE = "http://127.0.0.1:18010"
PROBE_URL = SITE + "/waf-marker"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

TOKEN_FILE = os.path.join(RT, "engine.token")
RULES = os.path.join(RT, "rules", "litewaf_rules.conf")
VERSIONS = os.path.join(RT, "versions")
CANDIDATES = os.path.join(RT, "candidates")
CONF_DIR = os.path.join(RT, "conf")
MAIN_CONF = os.path.join(CONF_DIR, "nginx.conf")

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
CC_DEFAULT = {"max_requests": 20, "window": 10, "block_duration": 60}
# 卡片 R34-09 的合法区间
CC_RANGES = {"max_requests": (2, 1000), "window": (1, 3600), "block_duration": (1, 86400)}


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def read_token():
    if not os.path.exists(TOKEN_FILE):
        os.makedirs(RT, exist_ok=True)
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(secrets.token_urlsafe(24))
        os.chmod(TOKEN_FILE, 0o600)
    with open(TOKEN_FILE, encoding="utf-8") as f:
        return f.read().strip()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run(cmd, timeout=25):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode == 0, ((p.stdout or "") + (p.stderr or "")).strip()


def nginx_test(conf_rel):
    return run([NGINX_BIN, "-p", RT, "-c", conf_rel, "-t"])


def nginx_reload():
    return run([NGINX_BIN, "-p", RT, "-c", "conf/nginx.conf", "-s", "reload"], timeout=20)


def http_code(url, ua=None):
    req = urllib.request.Request(url, headers={"User-Agent": ua} if ua else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def probe_after_reload():
    """
    reload 退出码为 0 不代表 worker 真的换了配置（老 worker 会把手上的请求做完）。
    用「新连接连打 3 次」做行为确认：marker 200 / 正常 200 / SQLi 403。
    """
    tries = []
    for i in range(3):
        code = http_code(PROBE_URL)
        tries.append({"try": i + 1, "marker": code})
        if code == 200:
            break
        time.sleep(0.5)
    marker_ok = any(t["marker"] == 200 for t in tries)
    normal = http_code(SITE + "/index.html", UA)
    sqli = http_code(SITE + "/?id=1%20UNION%20SELECT%20password%20FROM%20users", UA)
    return {
        "ok": marker_ok and normal == 200 and sqli == 403,
        "marker_tries": tries, "normal": normal, "sqli": sqli,
    }


def nginx_alive():
    pid_file = os.path.join(RT, "logs", "nginx.pid")
    try:
        with open(pid_file, encoding="utf-8") as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except Exception:
        return False


def read_ptr(name):
    p = os.path.join(RT, name)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return f.read().strip()
    return ""


def write_ptr(name, value):
    tmp = os.path.join(RT, "." + name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    os.replace(tmp, os.path.join(RT, name))


def read_cc():
    """从 nginx.conf 读出当前 CC 三参数（平台展示用）"""
    try:
        with open(MAIN_CONF, encoding="utf-8") as f:
            conf = f.read()
    except OSError:
        return dict(CC_DEFAULT)
    out = {}
    for key in CC_DEFAULT:
        m = re.search(r"lite_waf_%s\s+(\d+)\s*;" % key, conf)
        out[key] = int(m.group(1)) if m else CC_DEFAULT[key]
    return out


def validate_cc(cc):
    """CC 参数校验：类型、范围、D>=W。返回 (normalized, error)"""
    out = dict(CC_DEFAULT)
    if cc is None:
        return out, None
    for key, (lo, hi) in CC_RANGES.items():
        if key not in cc:
            continue
        try:
            v = int(cc[key])
        except (TypeError, ValueError):
            return None, "%s 必须是整数" % key
        if not (lo <= v <= hi):
            return None, "%s 超出范围 %d-%d" % (key, lo, hi)
        out[key] = v
    if out["block_duration"] < out["window"]:
        return None, "封禁时长必须不小于统计窗口"
    return out, None


def with_cc(conf, cc):
    """把 nginx.conf 文本里的 CC 三行替换成目标值"""
    for key in CC_DEFAULT:
        conf = re.sub(r"lite_waf_%s\s+\d+\s*;" % key,
                      "lite_waf_%s %d;" % (key, cc[key]), conf)
    return conf


def apply_files(rules_text, cc):
    """原子写入规则文件与 nginx.conf（先写 .tmp 再 os.replace）"""
    with open(MAIN_CONF, encoding="utf-8") as f:
        conf = f.read()
    with open(MAIN_CONF + ".tmp", "w", encoding="utf-8") as f:
        f.write(with_cc(conf, cc))
    os.chmod(MAIN_CONF + ".tmp", 0o644)
    os.replace(MAIN_CONF + ".tmp", MAIN_CONF)

    with open(RULES + ".tmp", "w", encoding="utf-8") as f:
        f.write(rules_text)
    os.chmod(RULES + ".tmp", 0o644)
    os.replace(RULES + ".tmp", RULES)


def list_versions():
    out = []
    if os.path.isdir(VERSIONS):
        for name in sorted(os.listdir(VERSIONS)):
            mf = os.path.join(VERSIONS, name, "manifest.json")
            if os.path.isfile(mf):
                try:
                    with open(mf, encoding="utf-8") as f:
                        out.append(json.load(f))
                except Exception:
                    out.append({"version": name, "error": "manifest 解析失败"})
    return out


def next_version_id():
    nums = [int(m.group(1)) for m in
            (re.match(r"^v(\d+)$", n) for n in os.listdir(VERSIONS) if os.path.isdir(VERSIONS)) if m]
    return "v%d" % (max(nums) + 1 if nums else 1)


def write_version(version, rules_text, cc, kind, candidate_id):
    vdir = os.path.join(VERSIONS, version)
    os.makedirs(vdir, exist_ok=True)
    with open(os.path.join(vdir, "litewaf_rules.conf"), "w", encoding="utf-8") as f:
        f.write(rules_text)
    manifest = {
        "version": version, "kind": kind,
        "hash": sha256_text(rules_text),
        "bytes": len(rules_text.encode("utf-8")),
        "cc": cc,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "from_candidate": candidate_id,
        "previous": read_ptr("current"),
    }
    with open(os.path.join(vdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest


def do_check(rules_text, cc, name):
    cc_norm, err = validate_cc(cc)
    if err:
        return {"ok": False, "error": err, "stage": "参数校验"}

    os.makedirs(CANDIDATES, exist_ok=True)
    cid = "c%d-%s" % (int(time.time()), secrets.token_hex(3))
    cpath = os.path.join(CANDIDATES, cid + ".json")
    with open(cpath, "w", encoding="utf-8") as f:
        json.dump({"rules": rules_text, "cc": cc_norm, "name": name}, f, ensure_ascii=False)
    os.chmod(cpath, 0o644)

    # 用候选生成一份完整主配置：rule_file 指向候选规则、CC 用候选值
    with open(MAIN_CONF, encoding="utf-8") as f:
        conf = f.read()
    rpath = os.path.join(CANDIDATES, cid + ".conf")
    with open(rpath, "w", encoding="utf-8") as f:
        f.write(rules_text)
    os.chmod(rpath, 0o644)
    conf = re.sub(r"lite_waf_rule_file\s+\S+;", "lite_waf_rule_file %s;" % rpath, conf)
    conf = with_cc(conf, cc_norm)
    test_conf = "conf/test-%s.conf" % cid
    with open(os.path.join(RT, test_conf), "w", encoding="utf-8") as f:
        f.write(conf)

    ok, out = nginx_test(test_conf)
    for p in (os.path.join(RT, test_conf), rpath):
        if not ok:
            try:
                os.remove(p)
            except OSError:
                pass
    if not ok:
        try:
            os.remove(cpath)
        except OSError:
            pass

    return {
        "ok": ok, "candidate_id": cid if ok else None,
        "hash": sha256_text(rules_text),
        "bytes": len(rules_text.encode("utf-8")),
        "cc": cc_norm, "name": name, "engine_output": out,
    }


def do_publish(candidate_id):
    if not ID_RE.match(candidate_id or ""):
        return {"ok": False, "error": "candidate_id 非法"}
    cpath = os.path.join(CANDIDATES, candidate_id + ".json")
    if not os.path.isfile(cpath):
        return {"ok": False, "error": "候选不存在（可能已发布或已过期）"}
    with open(cpath, encoding="utf-8") as f:
        cand = json.load(f)
    rules_text = cand["rules"]
    cc = cand.get("cc") or read_cc()

    ok, out = nginx_test("conf/nginx.conf")
    if not ok:
        return {"ok": False, "error": "当前主配置就不合法，拒绝发布", "engine_output": out}

    old_rules = ""
    if os.path.exists(RULES):
        with open(RULES, encoding="utf-8") as f:
            old_rules = f.read()
    with open(MAIN_CONF, encoding="utf-8") as f:
        old_conf = f.read()
    old_cc = read_cc()

    new_id = next_version_id()
    apply_files(rules_text, cc)
    ok_reload, reload_out = nginx_reload()
    probe = probe_after_reload() if ok_reload else {"ok": False, "reason": "reload 失败"}

    if ok_reload and probe["ok"]:
        manifest = write_version(new_id, rules_text, cc, "publish", candidate_id)
        prev = read_ptr("current")
        if prev and prev != new_id:
            write_ptr("previous", prev)
        write_ptr("current", new_id)
        try:
            os.remove(cpath)
        except OSError:
            pass
        return {"ok": True, "version": new_id, "hash": manifest["hash"],
                "cc": cc, "previous": read_ptr("previous"),
                "probe": probe, "reload_output": reload_out}

    # 失败：规则和 CC 一起恢复，再 reload，保证线上回到发布前
    with open(RULES + ".tmp", "w", encoding="utf-8") as f:
        f.write(old_rules)
    os.replace(RULES + ".tmp", RULES)
    with open(MAIN_CONF + ".tmp", "w", encoding="utf-8") as f:
        f.write(old_conf)
    os.replace(MAIN_CONF + ".tmp", MAIN_CONF)
    nginx_reload()
    return {"ok": False, "error": "发布后探测失败，已自动回滚到发布前（规则+CC）",
            "probe": probe, "reload_output": reload_out, "restored_cc": old_cc}


def do_rollback():
    cur, prev = read_ptr("current"), read_ptr("previous")
    if not prev or prev == cur:
        return {"ok": False, "error": "没有可回退的上一版本"}
    mf = os.path.join(VERSIONS, prev, "manifest.json")
    src = os.path.join(VERSIONS, prev, "litewaf_rules.conf")
    if not (os.path.isfile(mf) and os.path.isfile(src)):
        return {"ok": False, "error": "上一版本文件缺失：%s" % prev}
    with open(mf, encoding="utf-8") as f:
        manifest = json.load(f)
    with open(src, encoding="utf-8") as f:
        rules_text = f.read()
    cc = manifest.get("cc") or read_cc()

    apply_files(rules_text, cc)
    ok_reload, reload_out = nginx_reload()
    probe = probe_after_reload() if ok_reload else {"ok": False}
    if ok_reload and probe["ok"]:
        write_ptr("previous", cur)
        write_ptr("current", prev)
        return {"ok": True, "version": prev, "cc": cc, "probe": probe,
                "reload_output": reload_out}
    return {"ok": False, "error": "回退后探测失败", "probe": probe}


class Handler(BaseHTTPRequestHandler):
    token = ""

    def log_message(self, fmt, *args):
        log("%s %s" % (self.address_string(), fmt % args))

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        if self.headers.get("X-Engine-Token", "") != self.token:
            self._send(401, {"ok": False, "error": "执行器令牌无效"})
            return False
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 2_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        if not self._auth():
            return
        if self.path == "/status":
            return self._send(200, {
                "ok": True, "nginx_alive": nginx_alive(),
                "current": read_ptr("current"), "previous": read_ptr("previous"),
                "cc": read_cc(),
                "marker": http_code(PROBE_URL),
                "normal": http_code(SITE + "/index.html", UA),
                "sqli": http_code(SITE + "/?id=1%20UNION%20SELECT%20x", UA),
                "versions": list_versions()[-10:],
            })
        if self.path == "/rules":
            # 平台读当前规则全文（只读，不落盘）
            with open(RULES, encoding="utf-8") as f:
                text = f.read()
            return self._send(200, {"ok": True, "text": text,
                                    "hash": sha256_text(text), "cc": read_cc()})
        return self._send(404, {"ok": False, "error": "未知路径"})

    def do_POST(self):
        if not self._auth():
            return
        body = self._body()
        try:
            if self.path == "/check":
                text = body.get("rules") or body.get("text")
                if not isinstance(text, str) or not text.strip():
                    return self._send(400, {"ok": False, "error": "规则文本必填"})
                res = do_check(text, body.get("cc"), body.get("name") or "candidate")
                log("check → ok=%s" % res["ok"])
                return self._send(200, res)
            if self.path == "/publish":
                res = do_publish(body.get("candidate_id"))
                log("publish → ok=%s version=%s" % (res.get("ok"), res.get("version")))
                return self._send(200, res)
            if self.path == "/rollback":
                res = do_rollback()
                log("rollback → ok=%s" % res.get("ok"))
                return self._send(200, res)
            return self._send(404, {"ok": False, "error": "未知动作（只支持 check/publish/rollback）"})
        except subprocess.TimeoutExpired:
            return self._send(500, {"ok": False, "error": "nginx 命令超时"})
        except Exception as exc:                    # noqa: BLE001
            log("内部错误：%r" % exc)
            return self._send(500, {"ok": False, "error": "执行器内部错误：%s" % exc})


def main():
    Handler.token = read_token()
    for d in (CANDIDATES, VERSIONS):
        os.makedirs(d, exist_ok=True)
    srv = ThreadingHTTPServer(LISTEN, Handler)
    log("engine-exec 监听 %s:%d" % LISTEN)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
