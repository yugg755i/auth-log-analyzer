SIGNAL_POINTS = {
    "malicious_ip": 40,
    "bruteforce": 30,
    "username_enum": 20,
    "breach": 10,
}

MITRE_TECHNIQUES = {
    "bruteforce": {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    "username_enum": {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    "malicious_ip": {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    "breach": {"id": "T1078", "name": "Valid Accounts"},
}

THREAT_LEVEL_BANDS = (
    (70, "Critical"),
    (40, "High"),
    (20, "Medium"),
    (1, "Low"),
)


def threat_level(score):
    for floor, label in THREAT_LEVEL_BANDS:
        if score >= floor:
            return label
    return "Informational"


def score_ip(ip, bruteforce, username_enum, malicious_ips, timeline):
    checklist = []
    techniques = []
    score = 0

    if ip in malicious_ips:
        data = malicious_ips[ip]
        pts = SIGNAL_POINTS["malicious_ip"]
        score += pts
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": f"{data.get('abuseConfidenceScore', 0)}% confidence, "
                      f"{data.get('totalReports', 0)} report(s), country {data.get('countryCode') or 'unknown'}",
            "points": pts,
            "met": True,
        })
        techniques.append(MITRE_TECHNIQUES["malicious_ip"])
    else:
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": "no match, or enrichment skipped",
            "points": 0,
            "met": False,
        })

    if ip in bruteforce:
        bf = bruteforce[ip]
        pts = SIGNAL_POINTS["bruteforce"]
        score += pts
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": f"{bf['count']} failed attempts, {bf['window_start']} \u2192 {bf['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(MITRE_TECHNIQUES["bruteforce"])
    else:
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": "not observed",
            "points": 0,
            "met": False,
        })

    if ip in username_enum:
        ue = username_enum[ip]
        pts = SIGNAL_POINTS["username_enum"]
        score += pts
        checklist.append({
            "signal": "Username enumeration",
            "detail": f"{ue['distinct_usernames']} distinct usernames, {ue['window_start']} \u2192 {ue['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(MITRE_TECHNIQUES["username_enum"])
    else:
        checklist.append({
            "signal": "Username enumeration",
            "detail": "not observed",
            "points": 0,
            "met": False,
        })

    breached = bool(timeline and timeline.get("breached"))
    if breached:
        pts = SIGNAL_POINTS["breach"]
        score += pts
        checklist.append({
            "signal": "Successful login on this IP",
            "detail": "at least one Accepted authentication recorded",
            "points": pts,
            "met": True,
        })
        techniques.append(MITRE_TECHNIQUES["breach"])
    else:
        checklist.append({
            "signal": "Successful login on this IP",
            "detail": "no successful login",
            "points": 0,
            "met": False,
        })

    score = min(score, 100)

    return {
        "ip": ip,
        "score": score,
        "level": threat_level(score),
        "checklist": checklist,
        "mitre": techniques,
        "attack_type": _attack_type(ip, bruteforce, username_enum, malicious_ips, breached),
    }


def _attack_type(ip, bruteforce, username_enum, malicious_ips, breached):
    if breached and ip in bruteforce:
        return "Brute-force with successful compromise"
    if ip in bruteforce and ip in username_enum:
        return "Credential stuffing / brute-force with username enumeration"
    if ip in bruteforce:
        return "SSH brute-force"
    if ip in username_enum:
        return "Username enumeration"
    if ip in malicious_ips:
        return "Known malicious source (no local pattern match)"
    return "Unclassified"


def build_narrative(ip, bruteforce, username_enum, malicious_ips, timeline):
    clauses = []

    if ip in bruteforce:
        bf = bruteforce[ip]
        clauses.append(
            f"{ip} attempted {bf['count']} failed logins within a "
            f"{bf['window_start']} \u2192 {bf['window_end']} window, consistent with automated brute-force."
        )

    if ip in username_enum:
        ue = username_enum[ip]
        clauses.append(
            f"It also tried {ue['distinct_usernames']} distinct usernames "
            f"({', '.join(ue['usernames'][:5])}{'...' if len(ue['usernames']) > 5 else ''}) "
            f"in a single window, suggesting username enumeration rather than a single targeted account."
        )

    if timeline:
        if timeline["breached"]:
            clauses.append(
                f"The attack succeeded \u2014 a login was accepted after "
                f"{timeline['failed_attempts']} failed attempt(s), indicating a compromised or guessed credential."
            )
        else:
            clauses.append(
                f"No successful login was recorded across {timeline['total_attempts']} attempt(s) "
                f"over {timeline['duration_seconds']}s."
            )

    if ip in malicious_ips:
        data = malicious_ips[ip]
        country = data.get("countryCode")
        country_clause = f", originating from {country}" if country else ""
        clauses.append(
            f"{ip} is independently flagged by AbuseIPDB at {data.get('abuseConfidenceScore', 0)}% "
            f"confidence based on {data.get('totalReports', 0)} prior report(s){country_clause}."
        )

    if not clauses:
        return f"{ip} did not meet any detection threshold; included for context only."

    return " ".join(clauses)


def build_executive_summary(ip_scores):
    if not ip_scores:
        return {
            "threat_level": "Informational",
            "confidence": 0,
            "primary_attack_type": "No significant activity detected",
            "mitre_techniques": [],
            "headline_ip": None,
        }

    ranked = sorted(ip_scores.values(), key=lambda s: s["score"], reverse=True)
    top = ranked[0]

    seen = set()
    techniques = []
    for result in ranked:
        for tech in result["mitre"]:
            if tech["id"] not in seen:
                seen.add(tech["id"])
                techniques.append(tech)

    return {
        "threat_level": top["level"],
        "confidence": top["score"],
        "primary_attack_type": top["attack_type"],
        "mitre_techniques": techniques,
        "headline_ip": top["ip"],
    }
