"""Aggregations over a stream of log entries."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from .parser import LogEntry

BOTS = ("bot", "crawler", "spider", "curl", "wget", "python-requests", "headless")


@dataclass(slots=True)
class Report:
    total: int = 0
    malformed: int = 0
    bytes_served: int = 0
    by_status: Counter[int] = field(default_factory=Counter)
    by_path: Counter[str] = field(default_factory=Counter)
    by_ip: Counter[str] = field(default_factory=Counter)
    by_hour: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    bots: int = 0
    first: datetime | None = None
    last: datetime | None = None

    @property
    def error_rate(self) -> float:
        return sum(c for s, c in self.by_status.items() if s >= 400) / self.total if self.total else 0.0

    @property
    def human_bytes(self) -> str:
        n = float(self.bytes_served)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"


def analyze(entries: Iterable[LogEntry]) -> Report:
    report = Report()
    for e in entries:
        report.total += 1
        report.bytes_served += e.size
        report.by_status[e.status] += 1
        report.by_path[e.path] += 1
        report.by_ip[e.ip] += 1
        report.by_hour[e.time.strftime("%Y-%m-%d %H:00")] += 1
        if e.is_error:
            report.errors[f"{e.status} {e.path}"] += 1
        if any(b in e.agent.lower() for b in BOTS):
            report.bots += 1
        if report.first is None or e.time < report.first:
            report.first = e.time
        if report.last is None or e.time > report.last:
            report.last = e.time
    return report


def detect_scanners(report: Report, *, threshold: int = 20) -> list[str]:
    """IPs hammering error pages are the cheapest brute-force signal there is."""
    suspicious = [ip for ip, n in report.by_ip.items() if n >= threshold]
    return sorted(suspicious, key=lambda ip: -report.by_ip[ip])


def browser_share(entries: Iterable[LogEntry]) -> dict[str, float]:
    counts: dict[str, int] = defaultdict(int)
    total = 0
    families = {
        "Chrome": ("chrome", "crios"),
        "Firefox": ("firefox",),
        "Safari": ("safari",),
        "Edge": ("edg",),
        "Bot": BOTS,
    }
    for e in entries:
        ua = e.agent.lower()
        total += 1
        for family, needles in families.items():
            if any(n in ua for n in needles):
                counts[family] += 1
                break
        else:
            counts["Other"] += 1
    return {k: v / total for k, v in counts.items()} if total else {}
