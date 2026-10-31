#!/usr/bin/env python3
"""Run sustained mixed normal/attack traffic against LiteWAF-NGX.

The test uses only Python's standard library so it can run in local, Docker,
and CI environments.  It mixes normal and malicious GET requests for a fixed
duration, checks the expected status code for every response, and writes both a
per-request CSV and a compact JSON summary.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import http.client


@dataclass(frozen=True)
class SoakCase:
    """Reusable request template for mixed traffic."""

    name: str
    sample_type: str
    expected_status: int
    path: str
    user_agent: str = "LiteWAF-Soak/1.0"


ATTACK_CASES = [
    SoakCase("sql tautology", "attack", 403, "/search?q=1%27%20OR%20%271%27=%271"),
    SoakCase("union select", "attack", 403, "/item?id=1%20UNION%20SELECT%20password%20FROM%20users"),
    SoakCase("xss script", "attack", 403, "/comment?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    SoakCase("rfi wrapper", "attack", 403, "/view?file=php%3A%2F%2Ffilter%2Fresource%3Dindex.php"),
    SoakCase("traversal", "attack", 403, "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    SoakCase("dangerous upload", "attack", 403, "/upload?file=shell.php"),
    SoakCase("scanner ua", "attack", 403, "/", "sqlmap/1.8"),
]

NORMAL_CASES = [
    SoakCase("home", "normal", 200, "/"),
    SoakCase("index", "normal", 200, "/index.html"),
    SoakCase("search", "normal", 200, "/search?q=nginx"),
    SoakCase("product", "normal", 200, "/product?id=1001"),
    SoakCase("profile", "normal", 200, "/profile?name=alice"),
    SoakCase("asset css", "normal", 200, "/assets/app.css"),
    SoakCase("download", "normal", 200, "/download?file=manual.pdf"),
]


def request(base, case: SoakCase, timeout: float) -> tuple[int, int, str]:
    """Execute one HTTP request and return status, duration_us, and error."""
    conn = http.client.HTTPConnection(base.hostname, base.port, timeout=timeout)
    started = time.perf_counter_ns()
    try:
        conn.request("GET", case.path, headers={"User-Agent": case.user_agent})
        response = conn.getresponse()
        response.read()
        status = response.status
        error = ""
    except Exception as exc:  # pragma: no cover - integration-only path
        status = 0
        error = exc.__class__.__name__
    finally:
        conn.close()
    return status, (time.perf_counter_ns() - started) // 1000, error


def worker(worker_id: int, args, base, stop_at: float, lock: threading.Lock, rows: list[list[object]]) -> None:
    """Generate mixed traffic until the shared stop timestamp is reached."""
    rng = random.Random(args.seed + worker_id)
    next_send = time.monotonic()
    interval = args.concurrency / args.target_rps if args.target_rps > 0 else 0.0
    sequence = 0

    while time.monotonic() < stop_at:
        case = rng.choice(ATTACK_CASES if rng.random() < args.attack_ratio else NORMAL_CASES)
        status, duration_us, error = request(base, case, args.timeout)
        sequence += 1
        passed = status == case.expected_status
        with lock:
            rows.append([
                worker_id,
                sequence,
                case.name,
                case.sample_type,
                case.expected_status,
                status,
                "yes" if passed else "no",
                duration_us,
                error,
            ])

        if interval > 0:
            next_send += interval
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18013")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--target-rps", type=float, default=120.0)
    parser.add_argument("--attack-ratio", type=float, default=0.35)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=20260701)
    parser.add_argument("--output", default="logs/soak_results.csv")
    parser.add_argument("--summary", default="logs/soak_summary.json")
    return parser.parse_args()


def percentile(values: list[int], pct: float) -> float:
    """Return a simple nearest-rank percentile."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return float(ordered[index])


def main() -> int:
    """Run the soak test and write CSV/JSON reports."""
    args = parse_args()
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be >= 1")
    if not 0.0 <= args.attack_ratio <= 1.0:
        raise SystemExit("--attack-ratio must be between 0 and 1")

    base = urlparse(args.base_url)
    if base.scheme != "http" or base.hostname is None or base.port is None:
        raise SystemExit("--base-url must be an http URL with host and port")

    rows: list[list[object]] = []
    lock = threading.Lock()
    stop_at = time.monotonic() + args.duration
    threads = [
        threading.Thread(target=worker, args=(i + 1, args, base, stop_at, lock, rows))
        for i in range(args.concurrency)
    ]

    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "worker", "sequence", "name", "type", "expected_status",
            "actual_status", "passed", "duration_us", "error",
        ])
        writer.writerows(rows)

    total = len(rows)
    failed = sum(1 for row in rows if row[6] != "yes")
    attacks = sum(1 for row in rows if row[3] == "attack")
    normals = total - attacks
    durations = [int(row[7]) for row in rows]
    summary = {
        "duration_s": round(elapsed, 3),
        "total": total,
        "attacks": attacks,
        "normals": normals,
        "failed": failed,
        "requests_per_second": round(total / elapsed, 2) if elapsed > 0 else 0,
        "latency_avg_us": round(statistics.mean(durations), 2) if durations else 0,
        "latency_p95_us": percentile(durations, 95),
        "latency_p99_us": percentile(durations, 99),
    }
    Path(args.summary).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("LiteWAF-NGX soak test summary")
    print(json.dumps(summary, indent=2))
    print(f"Results: {output}")
    print(f"Summary: {args.summary}")
    return 0 if failed == 0 and total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
