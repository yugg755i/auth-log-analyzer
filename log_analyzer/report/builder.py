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
from log_analyzer.report.scoring import build_executive_summary, build_narrative, score_ip

EVIDENCE_LINE_LIMIT = 8


def _collect_evidence(events, ip, bruteforce, limit=EVIDENCE_LINE_LIMIT):
    ip_events = [e for e in events if e["ip"] == ip]

    window = bruteforce.get(ip)
    if window:
        windowed = [
            e for e in ip_events
            if window["window_start"] <= e["timestamp"] <= window["window_end"]
        ]
        if windowed:
            ip_events = windowed

    return [e["raw_line"] for e in ip_events[:limit] if e.get("raw_line")]


def _timeline_points(events, ip):
    ip_events = sorted((e for e in events if e["ip"] == ip), key=lambda e: e["timestamp"])
    if not ip_events:
        return []

    first = datetime.strptime(ip_events[0]["timestamp"], "%Y-%m-%d %H:%M:%S")
    last = datetime.strptime(ip_events[-1]["timestamp"], "%Y-%m-%d %H:%M:%S")
    duration = (last - first).total_seconds()

    points = []
    for e in ip_events:
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        offset_pct = 0.0 if duration == 0 else round((ts - first).total_seconds() / duration * 100, 2)
        points.append({
            "offset_pct": offset_pct,
            "status": e["status"],
            "timestamp": e["timestamp"],
            "user": e["user"],
        })
    return points


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
    geoip_data=None,
    confidence_threshold=50,
):
    abuse_data = abuse_data or {}
    geoip_data = geoip_data or {}

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

    flagged_ips = set(bruteforce) | set(username_enum) | set(malicious_ips)
    timelines = {
        ip: build_session_timeline(events, ip)
        for ip in sorted(flagged_ips, key=lambda ip: bruteforce.get(ip, {}).get("count", 0), reverse=True)
    }

    verdict = _build_verdict(malicious_ips, bruteforce, username_enum)

    ip_scores = {
        ip: score_ip(ip, bruteforce, username_enum, malicious_ips, timelines.get(ip))
        for ip in flagged_ips
    }
    narratives = {
        ip: build_narrative(ip, bruteforce, username_enum, malicious_ips, timelines.get(ip), geoip_data)
        for ip in flagged_ips
    }
    evidence = {
        ip: _collect_evidence(events, ip, bruteforce)
        for ip in flagged_ips
    }
    timeline_points = {
        ip: _timeline_points(events, ip)
        for ip in flagged_ips
    }
    executive_summary = build_executive_summary(ip_scores)
    investigation_order = sorted(
        flagged_ips, key=lambda ip: ip_scores[ip]["score"], reverse=True
    )

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
        "ip_scores": ip_scores,
        "narratives": narratives,
        "evidence": evidence,
        "timeline_points": timeline_points,
        "executive_summary": executive_summary,
        "investigation_order": investigation_order,
        "geoip": geoip_data,
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
