from __future__ import annotations

from datetime import timezone

import pytest

from logscope.analyze import analyze, browser_share, detect_scanners
from logscope.parser import LogEntry, parse_line, parse_time

LINE = (
    '203.0.113.7 - - [08/Dec/2024:13:55:36 +0300] "GET /books/42 HTTP/1.1" '
    '200 5123 "https://example.com" "Mozilla/5.0 (X11) Chrome/120.0"'
)


def entry(status=200, path="/", ip="1.1.1.1", agent="Mozilla/5.0 Chrome/120", size=10):
    return LogEntry(
        ip=ip,
        time=parse_time("08/Dec/2024:10:00:00 +0000"),
        method="GET",
        path=path,
        status=status,
        size=size,
        agent=agent,
    )


def test_parse_valid_line():
    e = parse_line(LINE)
    assert e is not None
    assert e.ip == "203.0.113.7"
    assert e.status == 200 and e.size == 5123
    assert e.time.tzinfo is not None


def test_parse_time_matches_offset():
    dt = parse_time("08/Dec/2024:13:55:36 +0300")
    assert dt.year == 2024 and dt.month == 12 and dt.day == 8
    assert dt.utcoffset().total_seconds() == 3 * 3600


@pytest.mark.parametrize("bad", ["", "garbage", '1.1.1.1 - - [bogus] "GET / HTTP/1.1" 200 1 "-" "-"'])
def test_malformed_lines_return_none(bad):
    assert parse_line(bad) is None


def test_dash_size_becomes_zero():
    line = LINE.replace("200 5123", "304 -")
    assert parse_line(line).size == 0


def test_analyze_counts():
    report = analyze([entry(), entry(status=404), entry(status=500)])
    assert report.total == 3
    assert report.by_status[404] == 1
    assert report.error_rate == pytest.approx(2 / 3)


def test_error_rate_empty_is_zero():
    assert analyze([]).error_rate == 0.0


def test_bytes_human_readable():
    assert analyze([entry(size=2048)]).human_bytes.endswith("KB")


def test_detect_scanners():
    entries = [entry() for _ in range(25)] + [entry(ip="2.2.2.2")]
    assert detect_scanners(analyze(entries), threshold=20) == ["1.1.1.1"]


def test_browser_share_sums_to_one():
    share = browser_share([entry(), entry(agent="curl/8.0"), entry(agent="xyz")])
    assert sum(share.values()) == pytest.approx(1.0)
    assert share["Chrome"] == pytest.approx(1 / 3)
    assert share["Bot"] == pytest.approx(1 / 3)


def test_generator_input_is_consumed_once():
    """analyze() must work on a stream, not require a list."""
    report = analyze(entry() for _ in range(5))
    assert report.total == 5
