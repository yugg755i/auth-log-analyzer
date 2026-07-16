import requests

from log_analyzer.cache import get_cached, set_cached
from log_analyzer.enrichment import is_public_ip

BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,query"


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def lookup_geoip_batch(ips):
    results = {}
    for chunk in _chunks(list(ips), BATCH_SIZE):
        payload = [{"query": ip, "fields": FIELDS} for ip in chunk]
        try:
            response = requests.post(BATCH_URL, json=payload, timeout=15)
            response.raise_for_status()
            for entry in response.json():
                if entry.get("status") == "success":
                    results[entry["query"]] = entry
        except requests.exceptions.RequestException as e:
            print(f"GeoIP batch lookup error: {e}")
    return results


def enrich_geoip(ips, cache=None, cache_ttl_hours=168):
    public_ips = [ip for ip in ips if is_public_ip(ip)]

    results = {}
    to_fetch = public_ips

    if cache is not None:
        to_fetch = []
        for ip in public_ips:
            cached = get_cached(cache, "geoip", ip, cache_ttl_hours)
            if cached is not None:
                results[ip] = cached
            else:
                to_fetch.append(ip)

    if to_fetch:
        fetched = lookup_geoip_batch(to_fetch)
        results.update(fetched)
        if cache is not None:
            for ip, data in fetched.items():
                set_cached(cache, "geoip", ip, data)

    return results
