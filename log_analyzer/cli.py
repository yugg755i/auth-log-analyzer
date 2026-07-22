#!/usr/bin/env python3

import argparse
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from log_analyzer import database
from log_analyzer.config import ConfigError, load_config
from log_analyzer.detector import filter_by_time
from log_analyzer.enrichment import enrich_ips
from log_analyzer.input_resolver import resolve_log_paths
from log_analyzer.parser import parse_logs
from log_analyzer.report.builder import build_report_context
from log_analyzer.report.renderer import render_report
from log_analyzer.cache import load_cache, save_cache
from log_analyzer.geoip import enrich_geoip

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
    parser.add_argument("--log-type", choices=["sshd", "sudo", "su"], default=None,
                         help="force parsing as a single log format instead of auto-detecting per line")
    parser.add_argument("--since", type=parse_date_arg, help="only include events on/after this time")
    parser.add_argument("--until", type=parse_date_arg, help="only include events on/before this time")

    parser.add_argument(
        "--config", metavar="PATH",
        help="path to a YAML config file for thresholds (default: auto-detect config/loganalyzer.yaml)"
    )
    parser.add_argument("--threshold", type=int, default=None,
                         help="failed attempts within the window to flag brute-force (default: 5)")
    parser.add_argument("--window", type=int, default=None, metavar="MINUTES",
                         help="brute-force sliding window size in minutes (default: 2)")
    parser.add_argument("--enum-threshold", type=int, default=None,
                         help="distinct usernames within the window to flag enumeration (default: 5)")
    parser.add_argument("--enum-window", type=int, default=None, metavar="MINUTES",
                         help="username-enumeration sliding window size in minutes (default: 2)")
    parser.add_argument("--confidence-threshold", type=int, default=None,
                         help="AbuseIPDB confidence score above which an IP is treated as malicious (default: 50)")

    parser.add_argument("--no-enrich", action="store_true", help="skip AbuseIPDB threat intel lookups")
    parser.add_argument("--export-csv", metavar="PATH", help="also export parsed events to CSV")
    parser.add_argument("--export-json", metavar="PATH", help="also export parsed events to JSON")
    parser.add_argument("--export-db", action="store_true", help="also persist parsed events to data/alerts.db")
    parser.add_argument("--no-geoip", action="store_true", help="skip GeoIP enrichment")
    parser.add_argument("--no-cache", action="store_true", help="disable enrichment caching")
    parser.add_argument("--cache-ttl-hours", type=int, default=None,
                        help="reuse cached AbuseIPDB/GeoIP results younger than this (default: 168 = 1 week)")
    parser.add_argument("--export-pdf", metavar="PATH", help="also export the report as PDF (requires playwright)")
    return parser


def resolve_thresholds(args, config):
    return {
        "bruteforce_threshold": args.threshold if args.threshold is not None else config["bruteforce_threshold"],
        "bruteforce_window_minutes": args.window if args.window is not None else config["bruteforce_window_minutes"],
        "enum_threshold": args.enum_threshold if args.enum_threshold is not None else config["enum_threshold"],
        "enum_window_minutes": args.enum_window if args.enum_window is not None else config["enum_window_minutes"],
        "confidence_threshold": args.confidence_threshold if args.confidence_threshold is not None else config["confidence_threshold"],
        "cache_ttl_hours": args.cache_ttl_hours if args.cache_ttl_hours is not None else config["cache_ttl_hours"],
    }

def validate_thresholds(thresholds):
    for key in ("bruteforce_threshold", "bruteforce_window_minutes", "enum_threshold", "enum_window_minutes"):
        if thresholds[key] <= 0:
            print(f"error: {key.replace('_', ' ')} must be greater than 0 (got {thresholds[key]})")
            sys.exit(1)
    if not (0 <= thresholds["confidence_threshold"] <= 100):
        print(f"error: confidence threshold must be between 0 and 100 (got {thresholds['confidence_threshold']})")
        sys.exit(1)

def main():
    args = build_arg_parser().parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"error: {e}")
        sys.exit(1)

    thresholds = resolve_thresholds(args, config)
    validate_thresholds(thresholds)

    try:
        log_paths = resolve_log_paths(args.path)
    except FileNotFoundError as e:
        print(f"error: {e}")
        sys.exit(1)

    print(f"Log Analyzer — parsing {len(log_paths)} file(s)...")
    events = parse_logs(log_paths, log_type=args.log_type)
    events = filter_by_time(events, since=args.since, until=args.until)

    if not events:
        print("no matching SSH auth events found in the given input/time window.")
        sys.exit(0)

    print(f"Parsed {len(events)} events across {len(log_paths)} file(s).")

    cache = None if args.no_cache else load_cache()

    abuse_data = {}
    geoip_data = {}
    if not args.no_enrich:
        load_dotenv()
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if api_key:
            unique_ips = { e["ip"] for e in events if e["ip"] is not None }
            print(f"Checking {len(unique_ips)} unique IP(s) against AbuseIPDB...")
            abuse_data = enrich_ips(unique_ips, api_key, cache=cache, cache_ttl_hours=thresholds["cache_ttl_hours"])
        else:
            print("no ABUSEIPDB_API_KEY set — skipping threat intel enrichment.")

    if not args.no_geoip:
        for e in events:
            if e["log_type"] == "sshd" and e["ip"] is None:
                print(e)
        unique_ips = { e["ip"] for e in events if e["ip"] is not None }
        print(f"Looking up GeoIP for {len(unique_ips)} unique IP(s)...")
        geoip_data = enrich_geoip(unique_ips, cache=cache, cache_ttl_hours=thresholds["cache_ttl_hours"])

    if cache is not None:
        save_cache(cache)

    ctx = build_report_context(
        events,
        source_files=log_paths,
        bruteforce_threshold=thresholds["bruteforce_threshold"],
        bruteforce_window_minutes=thresholds["bruteforce_window_minutes"],
        enum_threshold=thresholds["enum_threshold"],
        enum_window_minutes=thresholds["enum_window_minutes"],
        abuse_data=abuse_data,
        geoip_data=geoip_data,
        confidence_threshold=thresholds["confidence_threshold"],
    )

    render_report(ctx, args.output)
    print(f"\nReport written to {args.output}")
    print(ctx["verdict"])

    if args.export_pdf:
        from log_analyzer.pdf_export import export_pdf
        try:
            export_pdf(args.output, args.export_pdf)
            print(f"PDF exported to {args.export_pdf}")
        except RuntimeError as e:
            print(f"warning: {e}")

    if args.export_csv:
        database.export_csv(events, args.export_csv)
        print(f"CSV exported to {args.export_csv}")

    if args.export_json:
        database.export_json(events, args.export_json)
        print(f"JSON exported to {args.export_json}")

    if args.export_db:
        os.makedirs("data", exist_ok=True)
        database.create_database()
        database.insert_events(events)
        print("Events persisted to data/alerts.db")


if __name__ == "__main__":
    main()
