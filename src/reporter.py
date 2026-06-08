import json
from datetime import datetime

from detector import detect_bruteforce, top_ips


def save_json(data, output_path):
    with open(output_path, "w") as file:
        json.dump(data, file, indent=4)


def generate_report(alerts, malicious_alerts, output_path):

    report = f"""
LOG ANALYZER REPORT

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SUMMARY
-------
Total Alerts Parsed: {len(alerts)}
Unique Source IPs: {len(set(alert["ip"] for alert in alerts))}
Potential Brute Force Sources: {len(detect_bruteforce(alerts))}
Malicious IPs Identified: {len(malicious_alerts)}

TOP SOURCE IPS
--------------
"""

    for ip, count in top_ips(alerts):
        report += f"{ip} : {count} attempts\n"

    report += "\nBRUTE FORCE DETECTIONS\n"
    report += "----------------------\n"

    brute_force = detect_bruteforce(alerts)

    if brute_force:
        for ip, count in brute_force.items():
            report += f"{ip} : {count} attempts\n"
    else:
        report += "None detected.\n"

    report += "\nTHREAT INTELLIGENCE\n"
    report += "-------------------\n"

    if malicious_alerts:
        for alert in malicious_alerts:
            report += f"{alert['ip']} - user: {alert['user']}\n"
    else:
        report += "No malicious IPs detected.\n"

    with open(output_path, "w") as file:
        file.write(report)
