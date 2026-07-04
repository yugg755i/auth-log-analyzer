from collections import Counter
from datetime import datetime

from log_analyzer.detector import (
    accepted_events,
    build_session_timeline,
    count_ips,
    detect_bruteforce,
    detect_username_enumeration,
    failed_events,
    top_ips,
)
from log_analyzer.enrichment import is_malicious


def _hourly_histogram(events):
    buckets = Counter()
    for e in events:
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        bucket_key = ts.strftime("%Y-%m-%d %H:00")
        buckets[bucket_key] += 1

    ordered_keys = sorted(buckets.keys())
    return [{"hour": k, "count": buckets[k]} for k in ordered_keys]


def build_report_context(
    events,
    source_files,
    bruteforce_threshold=5,
    bruteforce_window_minutes=2,
    enum_threshold=5,
    enum_window_minutes=2,
    abuse_data=None,
    confidence_threshold=50,
):
    abuse_data = abuse_data or {}

    failed = failed_events(events)
    accepted = accepted_events(events)

    bruteforce = detect_bruteforce(
        events, threshold=bruteforce_threshold, window_minutes=bruteforce_window_minutes
    )
    username_enum = detect_username_enumeration(
        events, threshold=enum_threshold, window_minutes=enum_window_minutes
    )

    malicious_ips = {
        ip: data for ip, data in abuse_data.items()
        if is_malicious(data, confidence_threshold)
    }

    timestamps = [e["timestamp"] for e in events]
    time_range = (min(timestamps), max(timestamps)) if timestamps else (None, None)

    # every IP worth a closer look gets a session timeline
    flagged_ips = set(bruteforce) | set(username_enum) | set(malicious_ips)
    timelines = {
        ip: build_session_timeline(events, ip)
        for ip in sorted(flagged_ips, key=lambda ip: bruteforce.get(ip, {}).get("count", 0), reverse=True)
    }

    verdict = _build_verdict(malicious_ips, bruteforce, username_enum)

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_files": [str(f) for f in source_files],
        "time_range": time_range,
        "total_events": len(events),
        "total_failed": len(failed),
        "total_accepted": len(accepted),
        "unique_ips": len(count_ips(events)),
        "top_ips": top_ips(events, n=10),
        "bruteforce": sorted(bruteforce.items(), key=lambda kv: -kv[1]["count"]),
        "bruteforce_threshold": bruteforce_threshold,
        "bruteforce_window_minutes": bruteforce_window_minutes,
        "username_enum": sorted(username_enum.items(), key=lambda kv: -kv[1]["distinct_usernames"]),
        "enum_threshold": enum_threshold,
        "enum_window_minutes": enum_window_minutes,
        "malicious_ips": malicious_ips,
        "accepted_after_bruteforce": _accepted_after_bruteforce(events, bruteforce),
        "timelines": timelines,
        "hourly_histogram": _hourly_histogram(events),
        "verdict": verdict,
    }


def _build_verdict(malicious_ips, bruteforce, username_enum):
    parts = []
    if malicious_ips:
        parts.append(f"{len(malicious_ips)} IP(s) confirmed malicious via threat intel")
    if bruteforce:
        parts.append(f"{len(bruteforce)} IP(s) show time-windowed brute-force patterns")
    if username_enum:
        parts.append(f"{len(username_enum)} IP(s) show username enumeration")

    if not parts:
        return "No brute-force, enumeration, or confirmed-malicious activity detected in this window."

    return ", ".join(parts) + "."


def _accepted_after_bruteforce(events, bruteforce_ips):
    if not bruteforce_ips:
        return []

    return [e for e in events if e["status"] == "Accepted" and e["ip"] in bruteforce_ips]
