#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 OWASP CRS 回归测试集里抽出可用的攻击/正常样本。

CRS 的测试是「请求 → 期望命中哪些规则 ID」的结构，用来验证 CRS 自己。
我们要的是**请求本身**：把它喂给我们的引擎，看拦不拦得住。

判定口径（不是照抄 CRS 的规则 ID，而是看它承认这是个攻击请求）：
- 该 test 的 output.log.expect_ids 非空 → 期望被拦（攻击样本）
- 有 no_expect_ids 或压根没有 log 段 → 期望放行（正常样本）

只保留我们引擎真正覆盖的类别（SQLi/XSS/LFI/RFI/RCE/扫描器），
协议层、multipart 解析这类我们没实现的直接跳过。

用法：python scripts/s14_extract_crs.py
输出：samples/crs_attack.tsv / samples/crs_benign.tsv（tab 分隔，表头一行）
列：category  method  path  query  ua  cookie  body
"""
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".tools", "py"))
import yaml  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZIP = os.path.join(ROOT, "samples", "raw", "coreruleset-main.zip")

# 只收我们引擎有对应类别的目录
CATEGORY = {
    "REQUEST-913-SCANNER-DETECTION": "SCAN",
    "REQUEST-930-APPLICATION-ATTACK-LFI": "TRAVERSAL",
    "REQUEST-931-APPLICATION-ATTACK-RFI": "RFI",
    # 932/933 是命令注入与 PHP 注入，不是 SQLi。早期版本把这两类并进 SQL，
    # 会让「SQLi 检出率」被拉垮到 20%，其实是引擎压根没有这两族规则。
    # 单列出来，只说明「不覆盖」，不进 SQLi/XSS 的统计。
    "REQUEST-932-APPLICATION-ATTACK-RCE": "RCE",
    "REQUEST-933-APPLICATION-ATTACK-PHP": "PHP",
    "REQUEST-941-APPLICATION-ATTACK-XSS": "XSS",
    "REQUEST-942-APPLICATION-ATTACK-SQLI": "SQL",
}

HEADER = ["category", "method", "path", "query", "ua", "cookie", "body", "headers"]


def split_uri(uri):
    """把 '/a/b?c=d' 拆成 ('/a/b', 'c=d')。"""
    if not uri:
        return "/", ""
    if "?" in uri:
        path, query = uri.split("?", 1)
        return path or "/", query
    return uri, ""


def pick_headers(headers):
    """只拼线上模块也会扫的那几个头（UA/Referer/Content-Type/Cookie）。

    引擎的 HEADERS zone 在模块侧只收这四类（见 lwaf_build_request_context），
    评估器保持同样的口径，不然检出率会比真实实例虚高。
    """
    ua = ""
    cookie = ""
    blob = []
    if not isinstance(headers, dict):
        return ua, cookie, ""
    for k, v in headers.items():
        name = str(k)
        kl = name.lower()
        val = str(v)
        if kl == "user-agent":
            ua = val
        elif kl == "cookie":
            cookie = val
        if kl in ("user-agent", "cookie", "referer", "content-type"):
            blob.append(f"{name}: {val}")
    return ua, cookie, "\n".join(blob)


def main():
    with zipfile.ZipFile(ZIP) as z:
        names = [n for n in z.namelist()
                 if "/tests/regression/tests/" in n and n.endswith((".yaml", ".yml"))]
        attack, benign = [], []
        skipped = {"non_str_body": 0, "no_input": 0, "other_cat": 0, "bad_yaml": 0}

        for name in names:
            parts = name.split("/")
            cat = CATEGORY.get(parts[4]) if len(parts) > 4 else None
            if not cat:
                skipped["other_cat"] += 1
                continue
            try:
                doc = yaml.safe_load(z.read(name).decode("utf-8", "replace"))
            except Exception:
                skipped["bad_yaml"] += 1
                continue
            if not isinstance(doc, dict):
                continue
            for test in doc.get("tests") or []:
                stages = test.get("stages") or []
                if not stages:
                    skipped["no_input"] += 1
                    continue
                inp = (stages[0] or {}).get("input") or {}
                out = (stages[0] or {}).get("output") or {}
                uri = inp.get("uri") or ""
                if "@" in uri:  # 变量插值类样本跳过
                    skipped["no_input"] += 1
                    continue
                body = inp.get("data_") or inp.get("data") or ""
                if body is None:
                    body = ""
                if isinstance(body, (dict, list)):
                    skipped["non_str_body"] += 1
                    continue
                ua, cookie, hblob = pick_headers(inp.get("headers"))
                path, query = split_uri(str(uri))
                row = [cat, str(inp.get("method") or "GET"), path, query,
                       ua, cookie, str(body), hblob]

                log = ((out or {}).get("log") or {}) if isinstance(out, dict) else {}
                if log.get("expect_ids"):
                    attack.append(row)
                elif log.get("no_expect_ids") or not log:
                    benign.append(row)

    def dump(rows, filename):
        path = os.path.join(ROOT, "samples", filename)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\t".join(HEADER) + "\n")
            for r in rows:
                f.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in r) + "\n")
        return path

    dump(attack, "crs_attack.tsv")
    dump(benign, "crs_benign.tsv")

    by_cat = {}
    for r in attack:
        by_cat[r[0]] = by_cat.get(r[0], 0) + 1
    print(json.dumps({
        "attack": len(attack), "benign": len(benign),
        "attack_by_category": by_cat, "skipped": skipped,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
