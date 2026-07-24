from log_analyzer.parser import parse_log
from tests.conftest import (
    sshd_line,
    su_fail_line,
    su_success_line,
    sudo_fail_line,
    sudo_success_line,
)


def test_parse_log_extracts_sudo_failure(write_log):
    path = write_log([sudo_fail_line("Jul  4 10:00:01", user="alice")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    e = events[0]
    assert e["log_type"] == "sudo"
    assert e["status"] == "Failed"
    assert e["actor"] == "alice"
    assert e["actor_type"] == "user"
    assert e["user"] == "alice"
    assert e["ip"] is None
    assert e["port"] is None


def test_parse_log_extracts_sudo_success(write_log):
    path = write_log([sudo_success_line("Jul  4 10:00:05", user="alice", target_user="root", command="/usr/bin/whoami")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    e = events[0]
    assert e["log_type"] == "sudo"
    assert e["status"] == "Accepted"
    assert e["actor"] == "alice"


def test_parse_log_extracts_su_failure(write_log):
    path = write_log([su_fail_line("Jul  4 10:00:01", target_user="root")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    e = events[0]
    assert e["log_type"] == "su"
    assert e["status"] == "Failed"
    assert e["actor"] == "root"
    assert e["actor_type"] == "user"


def test_parse_log_extracts_su_success(write_log):
    path = write_log([su_success_line("Jul  4 10:00:05", user="alice", target_user="root")])

    events = parse_log(path, reference_year=2026)

    assert len(events) == 1
    e = events[0]
    assert e["log_type"] == "su"
    assert e["status"] == "Accepted"
    assert e["actor"] == "alice"


def test_parse_log_handles_mixed_sshd_sudo_su_in_one_file(write_log):
    path = write_log([
        sshd_line("Jul  4 09:00:00", "Failed", "1.2.3.4", "22"),
        sudo_fail_line("Jul  4 09:01:00", user="bob"),
        su_success_line("Jul  4 09:02:00", user="bob", target_user="root"),
        "Jul  4 09:03:00 host CRON[999]: pam_unix(cron:session): session opened",
    ])

    events = parse_log(path, reference_year=2026)

    log_types = sorted(e["log_type"] for e in events)
    assert log_types == ["su", "sshd", "sudo"] or log_types == ["sshd", "su", "sudo"]
    assert len(events) == 3


def test_parse_log_forced_log_type_ignores_other_formats(write_log):
    path = write_log([
        sshd_line("Jul  4 09:00:00", "Failed", "1.2.3.4", "22"),
        sudo_fail_line("Jul  4 09:01:00", user="bob"),
    ])

    events = parse_log(path, reference_year=2026, log_type="sudo")

    assert len(events) == 1
    assert events[0]["log_type"] == "sudo"
