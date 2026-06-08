import os
from pathlib import Path


def get_latest_log(log_dir):
    path_dir = Path(log_dir)
    logs = list(path_dir.rglob("*.log"))
    if not logs:
        return None
    recent_log = max(logs, key=lambda x: x.stat().st_mtime)
    return recent_log
