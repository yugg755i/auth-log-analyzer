from collections import Counter
from datetime import datetime


def filter_by_time(events, since=None, until=None):
    """Keep only events within [since, until] (inclusive), both optional."""
    if not since and not until:
        return events

    def in_range(event):
        ts = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
        if since and ts < since:
            return False
        if until and ts > until:
            return False
        return True

    return [e for e in events if in_range(e)]


def count_ips(events):
    return Counter(event["ip"] for event in events)


def top_ips(events, n=10):
    return count_ips(events).most_common(n)


def failed_events(events):
    return [e for e in events if e["status"] == "Failed"]


def accepted_events(events):
    return [e for e in events if e["status"] == "Accepted"]


def detect_bruteforce(events, threshold=5):
    """Flag IPs with >= threshold failed attempts, total, across the input."""
    counts = count_ips(failed_events(events))
    return {ip: count for ip, count in counts.items() if count >= threshold}


def unique_usernames_tried(events):
    return Counter(event["user"] for event in events)
