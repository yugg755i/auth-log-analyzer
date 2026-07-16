import json
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_CACHE_PATH = "data/enrichment_cache.json"


def load_cache(cache_path=DEFAULT_CACHE_PATH):
    path = Path(cache_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache, cache_path=DEFAULT_CACHE_PATH):
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2))


def get_cached(cache, namespace, key, ttl_hours):
    entry = cache.get(namespace, {}).get(key)
    if entry is None:
        return None
    cached_at = datetime.fromisoformat(entry["cached_at"])
    if datetime.now() - cached_at > timedelta(hours=ttl_hours):
        return None
    return entry["data"]


def set_cached(cache, namespace, key, data):
    cache.setdefault(namespace, {})[key] = {
        "data": data,
        "cached_at": datetime.now().isoformat(),
    }
