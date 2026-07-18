import gzip
import re
from datetime import datetime

SYSLOG_PREFIX = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?(?P<program>sshd|sudo|su)(?:\[\d+\])?:\s*"
    r"(?P<message>.*)"
)

SSHD_PATTERN = re.compile(
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"port\s+(?P<port>\d+)"
)

SUDO_FAIL_PATTERN = re.compile(
    r"pam_unix\(sudo:auth\):\s+authentication failure;.*?\buser=(?P<user>\S*)"
)

SUDO_SUCCESS_PATTERN = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

SU_FAIL_PATTERN = re.compile(
    r"pam_unix\(su:auth\):\s+authentication failure;.*?\buser=(?P<user>\S*)"
)

SU_SUCCESS_PATTERN = re.compile(
    r"^Successful su for (?P<target_user>\S+) by (?P<user>\S+)$"
)

ACTOR_TYPE_BY_LOG_TYPE = {
    "sshd": "ip",
    "sudo": "user",
    "su": "user",
}

EVENT_FIELDS = (
    "timestamp", "log_type", "status", "actor", "actor_type",
    "user", "ip", "port", "invalid_user", "source_file", "raw_line",
)


def _base_event(log_type, ts_str, source_file, raw_line, reference_year):
    timestamp = parse_timestamp(ts_str, reference_year)
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "log_type": log_type,
        "actor_type": ACTOR_TYPE_BY_LOG_TYPE[log_type],
        "source_file": source_file,
        "raw_line": raw_line,
        "ip": None,
        "port": None,
        "invalid_user": False,
    }


def _extract_sshd(message, base):
    m = SSHD_PATTERN.search(message)
    if not m:
        return None
    g = m.groupdict()
    base.update({
        "status": g["status"],
        "actor": g["ip"],
        "user": g["user"],
        "ip": g["ip"],
        "port": g["port"],
        "invalid_user": g["invalid"] is not None,
    })
    return base


def _extract_sudo(message, base):
    m = SUDO_FAIL_PATTERN.search(message)
    if m:
        user = m.group("user") or "unknown"
        base.update({"status": "Failed", "actor": user, "user": user})
        return base

    m = SUDO_SUCCESS_PATTERN.search(message)
    if m:
        user = m.group("user")
        base.update({"status": "Accepted", "actor": user, "user": user})
        return base

    return None


def _extract_su(message, base):
    m = SU_FAIL_PATTERN.search(message)
    if m:
        target = m.group("user") or "unknown"
        base.update({"status": "Failed", "actor": target, "user": target})
        return base

    m = SU_SUCCESS_PATTERN.search(message)
    if m:
        caller = m.group("user")
        base.update({"status": "Accepted", "actor": caller, "user": caller})
        return base

    return None


EXTRACTORS = {
    "sshd": _extract_sshd,
    "sudo": _extract_sudo,
    "su": _extract_su,
}


def open_log(log_path):
    path_str = str(log_path)
    if path_str.endswith(".gz"):
        return gzip.open(path_str, "rt", errors="replace")
    return open(path_str, errors="replace")


def parse_timestamp(raw_ts, reference_year=None):
    year = reference_year or datetime.now().year
    raw = f"{year} {raw_ts}"
    return datetime.strptime(raw, "%Y %b %d %H:%M:%S")


def parse_line(line, source_file, reference_year=None):
    prefix_match = SYSLOG_PREFIX.search(line)
    if not prefix_match:
        return None

    program = prefix_match.group("program")
    extractor = EXTRACTORS.get(program)
    if extractor is None:
        return None

    base = _base_event(program, prefix_match.group("timestamp"), str(source_file), line.rstrip("\n"), reference_year)
    event = extractor(prefix_match.group("message"), base)
    return event


def parse_log(log_path, reference_year=None, log_type=None):
    events = []

    with open_log(log_path) as file:
        for line in file:
            if log_type is not None:
                prefix_match = SYSLOG_PREFIX.search(line)
                if not prefix_match or prefix_match.group("program") != log_type:
                    continue
                base = _base_event(log_type, prefix_match.group("timestamp"), str(log_path), line.rstrip("\n"), reference_year)
                event = EXTRACTORS[log_type](prefix_match.group("message"), base)
            else:
                event = parse_line(line, log_path, reference_year)

            if event is not None:
                events.append(event)

    return events


def parse_logs(log_paths, reference_year=None, log_type=None):
    events = []
    for path in log_paths:
        events.extend(parse_log(path, reference_year, log_type=log_type))

    events.sort(key=lambda e: e["timestamp"])
    return events
