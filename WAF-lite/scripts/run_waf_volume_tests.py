#!/usr/bin/env python3
"""Run a larger LiteWAF-NGX functional/security regression dataset.

The script intentionally uses only the Python standard library so it can run in
course environments without additional package installation.  It assumes the
target Nginx configuration disables dynamic blocking; dynamic blocking has its
own focused test in ``scripts/run_waf_tests.sh``.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class CaseTemplate:
    """One reusable test case template."""

    name: str
    sample_type: str
    expected_status: int
    path: str
    user_agent: str = "LiteWAF-Volume/1.0"


ATTACK_TEMPLATES = [
    CaseTemplate("sql tautology", "attack", 403, "/search?q=1%27%20OR%20%271%27=%271"),
    CaseTemplate("sql union select", "attack", 403, "/item?id=1%20UNION%20SELECT%20user,password%20FROM%20users"),
    CaseTemplate("sql comment bypass", "attack", 403, "/login?user=admin%27%20OR%201=1--"),
    CaseTemplate("sql drop table", "attack", 403, "/api/order?id=1%3Bdrop%20table%20orders"),
    CaseTemplate("sql hex literal", "attack", 403, "/api/item?id=0xdeadbeef%20UNION%20SELECT"),
    CaseTemplate("rfi http scheme", "attack", 403, "/redirect?next=http%3A%2F%2Fevil.example%2Fshell.txt"),
    CaseTemplate("rfi php wrapper", "attack", 403, "/view?file=php%3A%2F%2Ffilter%2Fresource%3Dindex.php"),
    CaseTemplate("unix traversal", "attack", 403, "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    CaseTemplate("windows cmd shell", "attack", 403, "/download?file=..%5C..%5Cwindows%5Csystem32%5Ccmd.exe"),
    CaseTemplate("powershell probe", "attack", 403, "/run?bin=powershell.exe"),
    CaseTemplate("xss script tag", "attack", 403, "/comment?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    CaseTemplate("xss javascript uri", "attack", 403, "/redirect?next=javascript%3Aalert(1)"),
    CaseTemplate("xss event handler", "attack", 403, "/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E"),
    CaseTemplate("xss svg onload", "attack", 403, "/search?q=%3Csvg%20onload=alert(1)%3E"),
    CaseTemplate("encoded evasion", "attack", 403, "/search?q=%25u003c%26%23x3c"),
    CaseTemplate("dangerous upload ext", "attack", 403, "/upload?file=shell.php"),
    CaseTemplate("nikto user agent", "attack", 403, "/", "Nikto/2.5.0"),
    CaseTemplate("sqlmap user agent", "attack", 403, "/", "sqlmap/1.8"),
    CaseTemplate("python requests ua", "attack", 403, "/", "python-requests/2.31"),
    CaseTemplate("wget user agent", "attack", 403, "/", "Wget/1.21"),
]

NORMAL_TEMPLATES = [
    CaseTemplate("homepage", "normal", 200, "/"),
    CaseTemplate("index html", "normal", 200, "/index.html"),
    CaseTemplate("about page", "normal", 200, "/about"),
    CaseTemplate("contact page", "normal", 200, "/contact"),
    CaseTemplate("login page", "normal", 200, "/login"),
    CaseTemplate("search nginx", "normal", 200, "/search?q=nginx"),
    CaseTemplate("numeric product id", "normal", 200, "/product?id=1001"),
    CaseTemplate("api status", "normal", 200, "/api/status"),
    CaseTemplate("css asset", "normal", 200, "/assets/app.css"),
    CaseTemplate("js asset", "normal", 200, "/assets/app.js"),
    CaseTemplate("image asset", "normal", 200, "/images/logo.png"),
    CaseTemplate("text document", "normal", 200, "/docs/readme.txt"),
    CaseTemplate("profile alice", "normal", 200, "/profile?name=alice"),
    CaseTemplate("simple comment", "normal", 200, "/comment?msg=hello-world"),
    CaseTemplate("cart item", "normal", 200, "/cart?item=book&qty=1"),
    CaseTemplate("manual download", "normal", 200, "/download?file=manual.pdf"),
    CaseTemplate("health check", "normal", 200, "/health"),
    CaseTemplate("pagination", "normal", 200, "/api/users?page=1&size=10"),
    CaseTemplate("friendly url", "normal", 200, "/news/2026/course-design"),
    CaseTemplate("safe upload name", "normal", 200, "/upload?file=avatar.png"),
]


def add_case_marker(path: str, index: int) -> str:
    """Return the original request path.

    Security payloads can be sensitive to suffix position.  For example the
    dangerous upload rule intentionally anchors the extension at the end of the
    inspected value, so adding a benign marker would change the test meaning.
    The CSV case ID is sufficient to distinguish repeated samples.
    """
    return path


def request(base, case: CaseTemplate, index: int, timeout: float) -> tuple[int, int, str]:
    """Execute one HTTP GET and return status, duration in microseconds, error."""
    path = add_case_marker(case.path, index)
    conn = http.client.HTTPConnection(base.hostname, base.port, timeout=timeout)
    started = time.perf_counter_ns()
    try:
        conn.request("GET", path, headers={"User-Agent": case.user_agent})
        response = conn.getresponse()
        response.read()
        status = response.status
        error = ""
    except Exception as exc:  # pragma: no cover - integration-only path
        status = 0
        error = exc.__class__.__name__
    finally:
        conn.close()
    duration_us = (time.perf_counter_ns() - started) // 1000
    return status, duration_us, error


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18011")
    parser.add_argument("--repeat", type=int, default=10,
                        help="Repeat each attack and normal template this many times.")
    parser.add_argument("--output", default="logs/volume_results.csv")
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def main() -> int:
    """Run the volume test dataset and write a CSV report."""
    args = parse_args()
    base = urlparse(args.base_url)
    if base.scheme != "http" or base.hostname is None:
        raise SystemExit("--base-url must be an http URL with host and port")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    total = passed = 0
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id", "name", "type", "expected_status", "actual_status",
            "passed", "duration_us", "error",
        ])
        for round_index in range(1, args.repeat + 1):
            for prefix, templates in (("VA", ATTACK_TEMPLATES), ("VN", NORMAL_TEMPLATES)):
                for template_index, template in enumerate(templates, 1):
                    case_id = f"{prefix}{round_index:02d}{template_index:02d}"
                    actual, duration_us, error = request(
                        base, template, round_index * 100 + template_index, args.timeout
                    )
                    ok = actual == template.expected_status
                    total += 1
                    passed += 1 if ok else 0
                    writer.writerow([
                        case_id, template.name, template.sample_type,
                        template.expected_status, actual,
                        "yes" if ok else "no", duration_us, error,
                    ])

    print(f"LiteWAF-NGX volume test: {passed}/{total} passed")
    print(f"Results: {output}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
