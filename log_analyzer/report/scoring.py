SIGNAL_POINTS = {
    "malicious_ip": 40,
    "bruteforce": 30,
    "username_enum": 20,
    "breach": 10,
}

MITRE_TECHNIQUES = {
    ("sshd", "bruteforce"): {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    ("sshd", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("sshd", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("sshd", "breach"): {"id": "T1078", "name": "Valid Accounts"},

    ("sudo", "bruteforce"): {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    ("sudo", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("sudo", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("sudo", "breach"): {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},

    ("su", "bruteforce"): {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    ("su", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("su", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("su", "breach"): {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},
}

THREAT_LEVEL_BANDS = (
    (70, "Critical"),
    (40, "High"),
    (20, "Medium"),
    (1, "Low"),
)


def _technique(log_type, signal):
    return MITRE_TECHNIQUES.get((log_type, signal), MITRE_TECHNIQUES[("sshd", signal)])


def threat_level(score):
    for floor, label in THREAT_LEVEL_BANDS:
        if score >= floor:
            return label
    return "Informational"


def score_ip(actor, log_type, bruteforce, username_enum, malicious_ips, timeline):
    checklist = []
    techniques = []
    score = 0

    if actor in malicious_ips:
        data = malicious_ips[actor]
        pts = SIGNAL_POINTS["malicious_ip"]
        score += pts
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": f"{data.get('abuseConfidenceScore', 0)}% confidence, "
                      f"{data.get('totalReports', 0)} report(s), country {data.get('countryCode') or 'unknown'}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "malicious_ip"))
    else:
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": "no match, or enrichment skipped",
            "points": 0,
            "met": False,
        })

    if actor in bruteforce:
        bf = bruteforce[actor]
        pts = SIGNAL_POINTS["bruteforce"]
        score += pts
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": f"{bf['count']} failed attempts, {bf['window_start']} \u2192 {bf['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "bruteforce"))
    else:
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": "not observed",
            "points": 0,
            "met": False,
        })

    if actor in username_enum:
        ue = username_enum[actor]
        pts = SIGNAL_POINTS["username_enum"]
        score += pts
        checklist.append({
            "signal": "Username enumeration",
            "detail": f"{ue['distinct_usernames']} distinct usernames, {ue['window_start']} \u2192 {ue['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "username_enum"))
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
        techniques.append(_technique(log_type, "breach"))
    else:
        checklist.append({
            "signal": "Successful login on this IP",
            "detail": "no successful login",
            "points": 0,
            "met": False,
        })

    score = min(score, 100)

    return {
        "ip": actor,
        "actor": actor,
        "log_type": log_type,
        "score": score,
        "level": threat_level(score),
        "checklist": checklist,
        "mitre": techniques,
        "attack_type": _attack_type(actor, log_type, bruteforce, username_enum, malicious_ips, breached),
    }


def _attack_type(actor, log_type, bruteforce, username_enum, malicious_ips, breached):
    if log_type == "sshd":
        if breached and actor in bruteforce:
            return "Brute-force with successful compromise"
        if actor in bruteforce and actor in username_enum:
            return "Credential stuffing / brute-force with username enumeration"
        if actor in bruteforce:
            return "SSH brute-force"
        if actor in username_enum:
            return "Username enumeration"
        if actor in malicious_ips:
            return "Known malicious source (no local pattern match)"
        return "Unclassified"

    label = "sudo" if log_type == "sudo" else "su"
    if breached and actor in bruteforce:
        return f"Local privilege escalation via {label} with successful compromise"
    if actor in bruteforce:
        return f"Repeated failed {label} attempts (possible local brute-force)"
    return "Unclassified"


def build_narrative(actor, log_type, bruteforce, username_enum, malicious_ips, timeline, geoip=None):
    clauses = []
    verb = {"sshd": "logins", "sudo": "sudo authentication attempts", "su": "su attempts"}[log_type]

    if actor in bruteforce:
        bf = bruteforce[actor]
        clauses.append(
            f"{actor} attempted {bf['count']} failed {verb} within a "
            f"{bf['window_start']} \u2192 {bf['window_end']} window, consistent with automated brute-force."
        )

    if actor in username_enum:
        ue = username_enum[actor]
        clauses.append(
            f"It also tried {ue['distinct_usernames']} distinct usernames "
            f"({', '.join(ue['usernames'][:5])}{'...' if len(ue['usernames']) > 5 else ''}) "
            f"in a single window, suggesting username enumeration rather than a single targeted account."
        )

    if timeline:
        if timeline["breached"]:
            if log_type == "sshd":
                clauses.append(
                    f"The attack succeeded \u2014 a login was accepted after "
                    f"{timeline['failed_attempts']} failed attempt(s), indicating a compromised or guessed credential."
                )
            else:
                clauses.append(
                    f"Privilege escalation succeeded \u2014 a {log_type} session was authorized after "
                    f"{timeline['failed_attempts']} failed attempt(s)."
                )
        else:
            clauses.append(
                f"No successful login was recorded across {timeline['total_attempts']} attempt(s) "
                f"over {timeline['duration_seconds']}s."
            )

    if actor in malicious_ips:
        data = malicious_ips[actor]
        country = data.get("countryCode")
        country_clause = f", originating from {country}" if country else ""
        clauses.append(
            f"{actor} is independently flagged by AbuseIPDB at {data.get('abuseConfidenceScore', 0)}% "
            f"confidence based on {data.get('totalReports', 0)} prior report(s){country_clause}."
        )

    if geoip and actor in geoip:
        g = geoip[actor]
        bits = [b for b in [g.get("city"), g.get("regionName"), g.get("country")] if b]
        if bits:
            clauses.append(f"GeoIP places this host in {', '.join(bits)}.")

    if not clauses:
        return f"{actor} did not meet any detection threshold; included for context only."

    return " ".join(clauses)


def build_executive_summary(ip_scores):
    if not ip_scores:
        return {
            "threat_level": "Informational",
            "confidence": 0,
            "primary_attack_type": "No significant activity detected",
            "mitre_techniques": [],
            "headline_ip": None,
            "headline_actor_type": None,
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
        "headline_ip": top["actor"],
        "headline_actor_type": "ip" if top["log_type"] == "sshd" else "user",
    }
