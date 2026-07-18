import gzip

import pytest


def sshd_line(month_day_time, status, ip, port, user="root", invalid=False, pid=1234):
    user_part = f"invalid user {user}" if invalid else user
    return f"{month_day_time} host sshd[{pid}]: {status} password for {user_part} from {ip} port {port} ssh2"


def sudo_fail_line(month_day_time, user="alice", host="host", pid=1234):
    return (
        f"{month_day_time} {host} sudo[{pid}]: pam_unix(sudo:auth): authentication failure; "
        f"logname={user} uid=1000 euid=0 tty=/dev/pts/0 ruser={user} rhost=  user={user}"
    )


def sudo_success_line(month_day_time, user="alice", target_user="root", command="/usr/bin/whoami", host="host"):
    return f"{month_day_time} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER={target_user} ; COMMAND={command}"


def su_fail_line(month_day_time, target_user="root", host="host", pid=1234):
    return (
        f"{month_day_time} {host} su[{pid}]: pam_unix(su:auth): authentication failure; "
        f"logname= uid=1000 euid=0 tty=pts/1 ruser= rhost=  user={target_user}"
    )


def su_success_line(month_day_time, user="alice", target_user="root", host="host", pid=1234):
    return f"{month_day_time} {host} su[{pid}]: Successful su for {target_user} by {user}"


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
                source_file="auth.log", raw_line=None, log_type="sshd", actor=None, actor_type="ip"):
    return {
        "timestamp": timestamp,
        "log_type": log_type,
        "status": status,
        "actor": actor if actor is not None else ip,
        "actor_type": actor_type,
        "invalid_user": invalid_user,
        "user": user,
        "ip": ip,
        "port": port,
        "source_file": source_file,
        "raw_line": raw_line or f"{timestamp} host sshd[1234]: {status} password for {user} from {ip} port {port} ssh2",
    }
