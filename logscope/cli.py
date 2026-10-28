from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyze import analyze, browser_share, detect_scanners
from .parser import read_entries


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logscope", description="Analyse nginx/Apache access logs.")
    p.add_argument("logfile", nargs="?", help="path to access.log ('-' for stdin)")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--since", help="ISO date, e.g. 2024-12-08")
    p.add_argument("--only-errors", action="store_true")
    return p


def render(report, top: int) -> str:
    if not report.total:
        return "no parsable log lines"
    out = [
        f"requests     : {report.total:,}",
        f"window       : {report.first:%Y-%m-%d %H:%M} -> {report.last:%Y-%m-%d %H:%M}",
        f"bytes served : {report.human_bytes}",
        f"error rate   : {report.error_rate:.1%}",
        f"bot traffic  : {report.bots:,} requests",
        "",
        "status codes:",
    ]
    out += [f"  {code}: {n:,}" for code, n in report.by_status.most_common()]
    out += ["", f"top {top} paths:"]
    out += [f"  {n:>6,}  {path}" for path, n in report.by_path.most_common(top)]
    out += ["", f"top {top} IPs:"]
    out += [f"  {n:>6,}  {ip}" for ip, n in report.by_ip.most_common(top)]
    if report.errors:
        out += ["", "error hot spots:"]
        out += [f"  {n:>6,}  {err}" for err, n in report.errors.most_common(top)]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.logfile:
        args.logfile = input("log path: ").strip()

    entries = read_entries(args.logfile)
    if args.since:
        entries = (e for e in entries if e.time.strftime("%Y-%m-%d") >= args.since)
    if args.only_errors:
        entries = (e for e in entries if e.is_error)

    report = analyze(entries)
    print(render(report, args.top))
    scanners = detect_scanners(report)
    if scanners:
        print("\nsuspicious (>= 20 requests): " + ", ".join(scanners[:5]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
