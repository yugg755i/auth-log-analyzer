import gzip

import pytest


def sshd_line(month_day_time, status, ip, port, user="root", invalid=False, pid=1234):
    user_part = f"invalid user {user}" if invalid else user
    return f"{month_day_time} host sshd[{pid}]: {status} password for {user_part} from {ip} port {port} ssh2"


@pytest.fixture
def write_log(tmp_path):
    def _write(lines, name="auth.log"):
        path = tmp_path / name
        path.write_text("\n".join(lines) + "\n")
        return path
    return _write


@pytest.fixture
def write_gz_log(tmp_path):
    def _write(lines, name="auth.log.gz"):
        path = tmp_path / name
        with gzip.open(path, "wt") as f:
            f.write("\n".join(lines) + "\n")
        return path
    return _write


def make_event(timestamp, status, ip, user="root", port="50356", invalid_user=False,
                source_file="auth.log", raw_line=None):
    return {
        "timestamp": timestamp,
        "status": status,
        "invalid_user": invalid_user,
        "user": user,
        "ip": ip,
        "port": port,
        "source_file": source_file,
        "raw_line": raw_line or f"{timestamp} host sshd[1234]: {status} password for {user} from {ip} port {port} ssh2",
    }
