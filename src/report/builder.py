from collections import Counter
from datetime import datetime

from src.detector import (
    accepted_events,
    count_ips,
    detect_bruteforce,
    failed_events,
    top_ips,
)
from src.enrichment import is_malicious


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
    abuse_data=None,
    confidence_threshold=50,
):
    abuse_data = abuse_data or {}

    failed = failed_events(events)
    accepted = accepted_events(events)
    bruteforce = detect_bruteforce(events, threshold=bruteforce_threshold)

    malicious_ips = {
        ip: data for ip, data in abuse_data.items()
        if is_malicious(data, confidence_threshold)
    }

    timestamps = [e["timestamp"] for e in events]
    time_range = (min(timestamps), max(timestamps)) if timestamps else (None, None)

    # verdict line for the executive summary
    if malicious_ips:
        verdict = f"{len(malicious_ips)} IP(s) confirmed malicious via threat intel, {len(bruteforce)} show brute-force patterns."
    elif bruteforce:
        verdict = f"No confirmed-malicious IPs, but {len(bruteforce)} IP(s) show brute-force patterns worth reviewing."
    else:
        verdict = "No brute-force patterns or confirmed-malicious IPs detected in this window."

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_files": [str(f) for f in source_files],
        "time_range": time_range,
        "total_events": len(events),
        "total_failed": len(failed),
        "total_accepted": len(accepted),
        "unique_ips": len(count_ips(events)),
        "top_ips": top_ips(events, n=10),
        "bruteforce": sorted(bruteforce.items(), key=lambda kv: -kv[1]),
        "bruteforce_threshold": bruteforce_threshold,
        "malicious_ips": malicious_ips,
        "accepted_after_bruteforce": _accepted_after_bruteforce(events, bruteforce),
        "hourly_histogram": _hourly_histogram(events),
        "verdict": verdict,
    }


def _accepted_after_bruteforce(events, bruteforce_ips):
    if not bruteforce_ips:
        return []

    hits = []
    for e in events:
        if e["status"] == "Accepted" and e["ip"] in bruteforce_ips:
            hits.append(e)
    return hits
