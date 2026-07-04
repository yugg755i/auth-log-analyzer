import ipaddress

import requests


def is_public_ip(ip):
    return not ipaddress.ip_address(ip).is_private


def check_abuseipdb(ip, api_key):
    try:
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": api_key, "Accept": "application/json"}

        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params=params,
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()["data"]

    except requests.exceptions.HTTPError as e:
        print(f"AbuseIPDB HTTP error for {ip}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB request error for {ip}: {e}")
        return None


def enrich_ips(ips, api_key):
    results = {}

    for ip in ips:
        if not is_public_ip(ip):
            continue

        data = check_abuseipdb(ip, api_key)
        if data is not None:
            results[ip] = data

    return results


def is_malicious(abuse_data, confidence_threshold=50):
    return abuse_data is not None and abuse_data.get("abuseConfidenceScore", 0) > confidence_threshold
