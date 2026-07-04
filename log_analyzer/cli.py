#!/usr/bin/env python3

import argparse
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from log_analyzer import database
from log_analyzer.detector import filter_by_time
from log_analyzer.enrichment import enrich_ips
from log_analyzer.input_resolver import resolve_log_paths
from log_analyzer.parser import parse_logs
from log_analyzer.report.builder import build_report_context
from log_analyzer.report.renderer import render_report


def parse_date_arg(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"invalid date '{value}', use YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS'"
    )


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Single-command SSH auth log forensic triage tool.",
    )
    parser.add_argument("path", help="log file, directory, or glob pattern (supports .gz)")
    parser.add_argument("-o", "--output", default="report.html", help="report output path (default: report.html)")
    parser.add_argument("--since", type=parse_date_arg, help="only include events on/after this time")
    parser.add_argument("--until", type=parse_date_arg, help="only include events on/before this time")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts within the window to flag brute-force (default: 5)")
    parser.add_argument("--window", type=int, default=2, metavar="MINUTES", help="brute-force sliding window size in minutes (default: 2)")
    parser.add_argument("--enum-threshold", type=int, default=5, help="distinct usernames within the window to flag enumeration (default: 5)")
    parser.add_argument("--enum-window", type=int, default=2, metavar="MINUTES", help="username-enumeration sliding window size in minutes (default: 2)")
    parser.add_argument("--no-enrich", action="store_true", help="skip AbuseIPDB threat intel lookups")
    parser.add_argument("--export-csv", metavar="PATH", help="also export parsed events to CSV")
    parser.add_argument("--export-db", action="store_true", help="also persist parsed events to data/alerts.db")
    return parser


def main():
    args = build_arg_parser().parse_args()

    try:
        log_paths = resolve_log_paths(args.path)
    except FileNotFoundError as e:
        print(f"error: {e}")
        sys.exit(1)

    print(f"Log Analyzer — parsing {len(log_paths)} file(s)...")
    events = parse_logs(log_paths)
    events = filter_by_time(events, since=args.since, until=args.until)

    if not events:
        print("no matching SSH auth events found in the given input/time window.")
        sys.exit(0)

    print(f"Parsed {len(events)} events across {len(log_paths)} file(s).")

    abuse_data = {}
    if not args.no_enrich:
        load_dotenv()
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if api_key:
            unique_ips = {e["ip"] for e in events}
            print(f"Checking {len(unique_ips)} unique IP(s) against AbuseIPDB...")
            abuse_data = enrich_ips(unique_ips, api_key)
        else:
            print("no ABUSEIPDB_API_KEY set — skipping threat intel enrichment.")

    ctx = build_report_context(
        events,
        source_files=log_paths,
        bruteforce_threshold=args.threshold,
        bruteforce_window_minutes=args.window,
        enum_threshold=args.enum_threshold,
        enum_window_minutes=args.enum_window,
        abuse_data=abuse_data,
    )

    render_report(ctx, args.output)
    print(f"\nReport written to {args.output}")
    print(ctx["verdict"])

    if args.export_csv:
        database.export_csv(events, args.export_csv)
        print(f"CSV exported to {args.export_csv}")

    if args.export_db:
        os.makedirs("data", exist_ok=True)
        database.create_database()
        database.insert_events(events)
        print("Events persisted to data/alerts.db")


if __name__ == "__main__":
    main()
