from collections import Counter, defaultdict
from datetime import datetime, timedelta

TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def _parse_ts(event):
    return datetime.strptime(event["timestamp"], TS_FORMAT)


def filter_by_time(events, since=None, until=None):
    if not since and not until:
        return events

    def in_range(event):
        ts = _parse_ts(event)
        if since and ts < since:
            return False
        if until and ts > until:
            return False
        return True

    return [e for e in events if in_range(e)]


def count_ips(events):
    return Counter(event["ip"] for event in events if event.get("ip"))


def top_ips(events, n=10):
    return count_ips(events).most_common(n)


def failed_events(events):
    return [e for e in events if e["status"] == "Failed"]


def accepted_events(events):
    return [e for e in events if e["status"] == "Accepted"]


def detect_bruteforce(events, threshold=5, window_minutes=2):
    by_actor = defaultdict(list)
    for e in failed_events(events):
        by_actor[e["actor"]].append(_parse_ts(e))

    window = timedelta(minutes=window_minutes)
    flagged = {}

    for actor, timestamps in by_actor.items():
        timestamps.sort()
        left = 0
        best_count = 0
        best_start = best_end = None

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count > best_count:
                best_count = count
                best_start, best_end = timestamps[left], timestamps[right]

        if best_count >= threshold:
            flagged[actor] = {
                "count": best_count,
                "window_start": best_start.strftime(TS_FORMAT),
                "window_end": best_end.strftime(TS_FORMAT),
            }

    return flagged


def detect_username_enumeration(events, threshold=5, window_minutes=2):
    by_actor = defaultdict(list)
    for e in events:
        by_actor[e["actor"]].append((_parse_ts(e), e["user"]))

    window = timedelta(minutes=window_minutes)
    flagged = {}

    for actor, entries in by_actor.items():
        entries.sort(key=lambda pair: pair[0])
        left = 0
        best_users = set()
        best_start = best_end = None

        for right in range(len(entries)):
            while entries[right][0] - entries[left][0] > window:
                left += 1
            window_users = {user for _, user in entries[left:right + 1]}
            if len(window_users) > len(best_users):
                best_users = window_users
                best_start, best_end = entries[left][0], entries[right][0]

        if len(best_users) >= threshold:
            flagged[actor] = {
                "distinct_usernames": len(best_users),
                "usernames": sorted(best_users),
                "window_start": best_start.strftime(TS_FORMAT),
                "window_end": best_end.strftime(TS_FORMAT),
            }

    return flagged


def build_session_timeline(events, actor):
    actor_events = sorted((e for e in events if e["actor"] == actor), key=lambda e: e["timestamp"])
    if not actor_events:
        return None

    failed = [e for e in actor_events if e["status"] == "Failed"]
    accepted = [e for e in actor_events if e["status"] == "Accepted"]
    usernames = sorted({e["user"] for e in actor_events})
    duration_seconds = int((_parse_ts(actor_events[-1]) - _parse_ts(actor_events[0])).total_seconds())

    return {
        "actor": actor,
        "ip": actor,
        "first_seen": actor_events[0]["timestamp"],
        "last_seen": actor_events[-1]["timestamp"],
        "duration_seconds": duration_seconds,
        "total_attempts": len(actor_events),
        "failed_attempts": len(failed),
        "accepted_attempts": len(accepted),
        "unique_usernames": len(usernames),
        "usernames": usernames,
        "breached": len(accepted) > 0,
    }


def unique_usernames_tried(events):
    return Counter(event["user"] for event in events)
