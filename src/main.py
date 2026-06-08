import argparse
import os

from database import clear_alerts, create_database, insert_alerts
from detector import detect_bruteforce, top_ips
from dotenv import load_dotenv
from enrichment import enrich_alerts
from parser import parse_log
from reporter import generate_report, save_json
from utils import get_latest_log


def main():

    parser = argparse.ArgumentParser(description="Log Analyzer")
    parser.add_argument("--top-ips", action="store_true", help="show top source IPs")
    parser.add_argument(
        "--bruteforce", action="store_true", help="show bruteforce attempts"
    )
    parser.add_argument(
        "--malicious-alerts", action="store_true", help="show malicious alerts"
    )
    parser.add_argument("--report", action="store_true", help="generate report")

    args = parser.parse_args()

    print("Log Analyzer")

    latest_log = get_latest_log("logs")
    if latest_log is None:
        print("no log files found...")
        return

    alerts = parse_log(latest_log)
    create_database()
    clear_alerts()
    insert_alerts(alerts)
    print(f"\nParsed {len(alerts)} alerts")

    if args.top_ips:
        print(f"\nTop IPs: {top_ips(alerts)}")

    save_json(alerts, "data/parsed_alerts.json")

    load_dotenv()
    API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    malicious_alerts = enrich_alerts("data/parsed_alerts.json", API_KEY)

    if args.malicious_alerts:
        print(f"\nmalicious alerts: {malicious_alerts}\n")
        save_json(malicious_alerts, "data/malicious_alerts.json")

    if args.bruteforce:
        print(f"potential bruteforce detected: {detect_bruteforce(alerts)}")

    if args.report:
        generate_report(alerts, malicious_alerts, "data/report.txt")
        with open("data/report.txt") as f:
            file = f.read()
            print(file)


if __name__ == "__main__":
    main()
