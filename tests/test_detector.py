from datetime import datetime

from log_analyzer.detector import (
    build_session_timeline,
    count_ips,
    detect_bruteforce,
    detect_username_enumeration,
    failed_events,
    accepted_events,
    filter_by_time,
    top_ips,
    unique_usernames_tried,
)
from tests.conftest import make_event


def test_count_ips_tallies_occurrences():
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-01 00:00:01", "Failed", "1.1.1.1"),
        make_event("2026-01-01 00:00:02", "Failed", "2.2.2.2"),
    ]
    counts = count_ips(events)
    assert counts["1.1.1.1"] == 2
    assert counts["2.2.2.2"] == 1


def test_top_ips_respects_n():
    events = [make_event("2026-01-01 00:00:00", "Failed", f"1.1.1.{i}") for i in range(5)]
    assert len(top_ips(events, n=2)) == 2


def test_failed_and_accepted_events_split_by_status():
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-01 00:00:01", "Accepted", "1.1.1.1"),
    ]
    assert len(failed_events(events)) == 1
    assert len(accepted_events(events)) == 1
    assert failed_events(events)[0]["status"] == "Failed"
    assert accepted_events(events)[0]["status"] == "Accepted"


def test_detect_bruteforce_flags_ip_at_or_above_threshold():
    events = [
        make_event(f"2026-01-01 00:00:{i:02d}", "Failed", "9.9.9.9")
        for i in range(5)
    ]
    flagged = detect_bruteforce(events, threshold=5, window_minutes=2)
    assert "9.9.9.9" in flagged
    assert flagged["9.9.9.9"]["count"] == 5


def test_detect_bruteforce_ignores_ip_under_threshold():
    events = [
        make_event(f"2026-01-01 00:00:{i:02d}", "Failed", "8.8.8.8")
        for i in range(4)
    ]
    flagged = detect_bruteforce(events, threshold=5, window_minutes=2)
    assert "8.8.8.8" not in flagged


def test_detect_bruteforce_respects_time_window():
    burst_one = [make_event(f"2026-01-01 00:00:{i:02d}", "Failed", "7.7.7.7") for i in range(3)]
    burst_two = [make_event(f"2026-01-01 00:10:{i:02d}", "Failed", "7.7.7.7") for i in range(3)]
    events = burst_one + burst_two

    flagged = detect_bruteforce(events, threshold=5, window_minutes=2)

    assert "7.7.7.7" not in flagged


def test_detect_bruteforce_only_counts_failed_events():
    events = [make_event(f"2026-01-01 00:00:{i:02d}", "Accepted", "6.6.6.6") for i in range(5)]
    flagged = detect_bruteforce(events, threshold=5, window_minutes=2)
    assert flagged == {}


def test_detect_username_enumeration_flags_distinct_usernames_in_window():
    events = [
        make_event(f"2026-01-01 00:00:{i:02d}", "Failed", "5.5.5.5", user=f"user{i}")
        for i in range(5)
    ]
    flagged = detect_username_enumeration(events, threshold=5, window_minutes=2)
    assert "5.5.5.5" in flagged
    assert flagged["5.5.5.5"]["distinct_usernames"] == 5


def test_detect_username_enumeration_ignores_repeated_single_user():
    events = [
        make_event(f"2026-01-01 00:00:{i:02d}", "Failed", "4.4.4.4", user="root")
        for i in range(5)
    ]
    flagged = detect_username_enumeration(events, threshold=5, window_minutes=2)
    assert "4.4.4.4" not in flagged


def test_build_session_timeline_marks_breached_when_login_succeeds():
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "3.3.3.3", user="root"),
        make_event("2026-01-01 00:00:05", "Accepted", "3.3.3.3", user="root"),
    ]
    timeline = build_session_timeline(events, "3.3.3.3")
    assert timeline["breached"] is True
    assert timeline["total_attempts"] == 2
    assert timeline["failed_attempts"] == 1
    assert timeline["accepted_attempts"] == 1
    assert timeline["duration_seconds"] == 5


def test_build_session_timeline_not_breached_without_success():
    events = [make_event("2026-01-01 00:00:00", "Failed", "3.3.3.3")]
    timeline = build_session_timeline(events, "3.3.3.3")
    assert timeline["breached"] is False


def test_build_session_timeline_returns_none_for_unknown_ip():
    events = [make_event("2026-01-01 00:00:00", "Failed", "3.3.3.3")]
    assert build_session_timeline(events, "0.0.0.0") is None


def test_filter_by_time_applies_since_and_until_bounds():
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-02 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-03 00:00:00", "Failed", "1.1.1.1"),
    ]
    result = filter_by_time(events, since=datetime(2026, 1, 2), until=datetime(2026, 1, 2, 23, 59, 59))
    assert len(result) == 1
    assert result[0]["timestamp"] == "2026-01-02 00:00:00"


def test_filter_by_time_returns_all_when_no_bounds_given():
    events = [make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1")]
    assert filter_by_time(events) == events


def test_unique_usernames_tried_counts_across_all_ips():
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1", user="root"),
        make_event("2026-01-01 00:00:01", "Failed", "2.2.2.2", user="root"),
        make_event("2026-01-01 00:00:02", "Failed", "2.2.2.2", user="admin"),
    ]
    counts = unique_usernames_tried(events)
    assert counts["root"] == 2
    assert counts["admin"] == 1
