from datetime import datetime

import pytest

from log_analyzer.parser import parse_log, parse_logs, parse_timestamp
from tests.conftest import sshd_line


def test_parse_log_extracts_failed_event(write_log):
    path = write_log([sshd_line("Jul  4 18:24:58", "Failed", "45.155.205.233", "50356", user="root")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    event = events[0]
    assert event["status"] == "Failed"
    assert event["ip"] == "45.155.205.233"
    assert event["user"] == "root"
    assert event["port"] == "50356"
    assert event["timestamp"] == "2026-07-04 18:24:58"
    assert event["invalid_user"] is False
    assert event["source_file"] == str(path)


def test_parse_log_retains_raw_line_for_evidence(write_log):
    line = sshd_line("Jul  4 18:24:58", "Failed", "45.155.205.233", "50356", user="root")
    path = write_log([line])

    events = parse_log(path, reference_year=2026)

    assert events[0]["raw_line"] == line


def test_parse_log_extracts_accepted_event(write_log):
    path = write_log([sshd_line("Jul  4 18:25:10", "Accepted", "45.155.205.233", "50356", user="root")])

    events = parse_log(path, reference_year=2026)

    assert events[0]["status"] == "Accepted"


def test_parse_log_flags_invalid_user(write_log):
    path = write_log([sshd_line("Jul  4 18:24:58", "Failed", "1.2.3.4", "22", user="admin", invalid=True)])

    events = parse_log(path, reference_year=2026)

    assert events[0]["invalid_user"] is True
    assert events[0]["user"] == "admin"


def test_parse_log_ignores_unrelated_lines(write_log):
    path = write_log([
        "Jul  4 18:00:00 host systemd[1]: Started Session 12 of user root.",
        sshd_line("Jul  4 18:24:58", "Failed", "1.2.3.4", "22"),
        "Jul  4 18:30:00 host CRON[999]: pam_unix(cron:session): session opened",
    ])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1


def test_parse_log_reads_gzip_files(write_gz_log):
    path = write_gz_log([sshd_line("Jul  4 18:24:58", "Failed", "1.2.3.4", "22")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    assert events[0]["ip"] == "1.2.3.4"


def test_parse_logs_merges_and_sorts_across_files(write_log):
    path_a = write_log([sshd_line("Jul  4 18:30:00", "Failed", "1.1.1.1", "22")], name="a.log")
    path_b = write_log([sshd_line("Jul  4 18:00:00", "Failed", "2.2.2.2", "22")], name="b.log")

    events = parse_logs([path_a, path_b], reference_year=2026)

    assert [e["ip"] for e in events] == ["2.2.2.2", "1.1.1.1"]


def test_parse_timestamp_uses_given_reference_year():
    ts = parse_timestamp("Jul  4 18:24:58", reference_year=2020)
    assert ts == datetime(2020, 7, 4, 18, 24, 58)


def test_parse_timestamp_defaults_to_current_year():
    ts = parse_timestamp("Jul  4 18:24:58")
    assert ts.year == datetime.now().year


@pytest.mark.parametrize("bad_ip_line", [
    "Jul  4 18:24:58 host sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
])
def test_parse_log_skips_lines_with_malformed_ip(write_log, bad_ip_line):
    path = write_log([bad_ip_line])

    events = parse_log(path, reference_year=2026)

    assert events == []
