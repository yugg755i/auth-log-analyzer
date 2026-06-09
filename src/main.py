import argparse
import os

from database import clear_alerts, create_database, export_csv, insert_alerts
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
    parser.add_argument(
        "--export-csv", action="store_true", help="export alerts to CSV"
    )
    parser.add_argument("--report", action="store_true", help="generate report")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    print("Log Analyzer")

    latest_log = get_latest_log("logs")
    if latest_log is None:
        print("no log files found...")
        return

    alerts = parse_log(latest_log)
    create_database()
    clear_alerts()
    insert_alerts(alerts)
    print(f"\nParsed {len(alerts)} alerts\n")

    if args.top_ips:
        print(f"Top IPs: {top_ips(alerts)}\n")

    save_json(alerts, "data/parsed_alerts.json")

    if args.malicious_alerts or args.report:
        load_dotenv()
        API_KEY = os.getenv("ABUSEIPDB_API_KEY")

        if not API_KEY:
            print("Error: ABUSEIPDB_API_KEY not found.")
            return

        malicious_alerts = enrich_alerts(
            "data/parsed_alerts.json",
            API_KEY,
        )

    if args.bruteforce:
        print(f"Potential Bruteforce Detected: {detect_bruteforce(alerts)}\n")

    if args.export_csv:
        export_csv("data/alerts.csv")
        print("\nCSV exported to data/alerts.csv")

    if args.report:
        generate_report(alerts, malicious_alerts, "data/report.txt")
        with open("data/report.txt") as f:
            file = f.read()
            print(file)
        print("\nReport saved to data/report.txt")


if __name__ == "__main__":
    main()
