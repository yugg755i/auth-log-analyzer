import glob as glob_module
from pathlib import Path

LOG_SUFFIXES = (".log", ".log.gz", ".gz")


def _is_log_file(path):
    name = path.name
    return name.endswith(LOG_SUFFIXES) or ".log." in name


def resolve_log_paths(target):
    path = Path(target)

    if path.is_file():
        matches = [path]
    elif path.is_dir():
        matches = [p for p in path.rglob("*") if p.is_file() and _is_log_file(p)]
    else:
        matches = [Path(p) for p in glob_module.glob(target, recursive=True)]
        matches = [p for p in matches if p.is_file()]

    if not matches:
        raise FileNotFoundError(f"no log files found for input: {target}")

    return sorted(matches, key=lambda p: p.stat().st_mtime)
