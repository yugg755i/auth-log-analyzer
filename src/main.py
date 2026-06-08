import os

from database import clear_alerts, create_database, get_all_alerts, insert_alerts
from detector import detect_bruteforce, top_ips
from dotenv import load_dotenv
from enrichment import enrich_alerts
from parser import parse_log
from reporter import generate_report, save_json
from utils import get_latest_log


def main():
    print("Log Analyzer")
    latest_log = get_latest_log("logs")

    if latest_log is None:
        print("no log files found...")
        return

    alerts = parse_log(latest_log)
    create_database()
    clear_alerts()
    insert_alerts(alerts)
    print(f"Parsed {len(alerts)} alerts")
    print(get_all_alerts())
    print("\ntop-ips:")
    print(top_ips(alerts))

    save_json(alerts, "data/parsed_alerts.json")

    load_dotenv()
    API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    malicious_alerts = enrich_alerts("data/parsed_alerts.json", API_KEY)
    print(f"\nmalicious alerts: {malicious_alerts}\n")

    # print(check_abuseipdb("8.8.8.8", API_KEY))
    print("potential bruteforce detected:")
    bruteforce_alerts = detect_bruteforce(alerts)
    print(bruteforce_alerts)

    save_json(malicious_alerts, "data/malicious_alerts.json")

    generate_report(alerts, malicious_alerts, "data/report.txt")


if __name__ == "__main__":
    main()
