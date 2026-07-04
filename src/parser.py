import gzip
import re
from datetime import datetime

PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"port\s+(?P<port>\d+)"
)


def open_log(log_path):
    path_str = str(log_path)
    if path_str.endswith(".gz"):
        return gzip.open(path_str, "rt", errors="replace")
    return open(path_str, errors="replace")


def parse_timestamp(raw_ts, reference_year=None):
    year = reference_year or datetime.now().year
    raw = f"{year} {raw_ts}"
    return datetime.strptime(raw, "%Y %b %d %H:%M:%S")


def parse_log(log_path, reference_year=None):
    events = []

    with open_log(log_path) as file:
        for line in file:
            match = PATTERN.search(line)
            if not match:
                continue

            groups = match.groupdict()
            timestamp = parse_timestamp(groups.pop("timestamp"), reference_year)

            events.append(
                {
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": groups["status"],
                    "invalid_user": groups["invalid"] is not None,
                    "user": groups["user"],
                    "ip": groups["ip"],
                    "port": groups["port"],
                    "source_file": str(log_path),
                }
            )

    return events


def parse_logs(log_paths, reference_year=None):
    events = []
    for path in log_paths:
        events.extend(parse_log(path, reference_year))

    events.sort(key=lambda e: e["timestamp"])
    return events
