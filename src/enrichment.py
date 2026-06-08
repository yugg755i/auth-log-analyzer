import ipaddress
import json
from pathlib import Path

import requests


def is_public_ip(ip):
    return not ipaddress.ip_address(ip).is_private


def load_alerts(json_path):
    p = Path(json_path)
    if not p.exists():
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None


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
        # return {"abuseConfidenceScore": 85} - for test

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")

        if e.response is not None:
            print(e.response.text)
        return None

    except requests.exceptions.RequestException as e:
        print(f"error: {e}")
        return None


def is_malicious(ip, api_key):

    ipdata = check_abuseipdb(ip, api_key)

    # if not isinstance(ipdata, dict) or "abuseConfidenceScore" not in ipdata:
    if ipdata is None:
        return None

    if ipdata["abuseConfidenceScore"] > 50:
        return True
    else:
        return False


def enrich_alerts(json_path, api_key):
    file = load_alerts(json_path)
    if file is None:
        return None
    malicious_list = []
    for alert_dict in file:
        if not is_public_ip(alert_dict["ip"]):
            continue
        value = is_malicious(alert_dict["ip"], api_key)
        if value is True:
            malicious_list.append(alert_dict)
        elif value is False:
            continue
        else:
            continue
    return malicious_list
