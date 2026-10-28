"""Parse nginx/Apache 'combined' log lines without loading the file into memory."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(slots=True)
class LogEntry:
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    size: int
    agent: str

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def is_server_error(self) -> bool:
        return self.status >= 500


def parse_time(raw: str) -> datetime:
    """nginx format: 10/Oct/2024:13:55:36 +0300"""
    stamp, _, offset = raw.partition(" ")
    day, month, rest = stamp.split("/")
    year, _, clock = rest.partition(":")
    hour, minute, second = (int(x) for x in clock.split(":"))
    sign = 1 if offset.startswith("+") else -1
    tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
    return datetime(int(year), MONTHS[month], int(day), hour, minute, second, tzinfo=tz)


def parse_line(line: str) -> LogEntry | None:
    """Returns None for malformed lines - a log parser must never crash a pipeline."""
    match = COMBINED.match(line.strip())
    if not match:
        return None
    g = match.groupdict()
    try:
        return LogEntry(
            ip=g["ip"],
            time=parse_time(g["time"]),
            method=g["method"],
            path=g["path"],
            status=int(g["status"]),
            size=0 if g["size"] == "-" else int(g["size"]),
            agent=g["agent"],
        )
    except (ValueError, KeyError):
        return None


def read_entries(path: str | Path) -> Iterator[LogEntry]:
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line)
            if entry is not None:
                yield entry
