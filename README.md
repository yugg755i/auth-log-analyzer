# Log Analyzer

A single-command CLI tool for SSH auth log forensic triage. Point it at
one or more logs, get a self-contained HTML report back.

```
logs in -> parse -> detect -> enrich -> one HTML report out
```

Built for the workflow an analyst actually has during incident
response.

## Features

- Single-command CLI — one file, one report
- Parses SSH auth logs, distinguishing failed / accepted / invalid-user attempts
- Accepts a single file, a directory, or a glob — including `.gz` / rotated logs
- Time-range filtering (`--since` / `--until`)
- Brute-force detection with a configurable threshold
- Flags the highest-signal case: an accepted login from an IP that also brute-forced
- AbuseIPDB threat intelligence enrichment for public IPs
- Self-contained HTML report — inline charts, no CDN, no external calls to render it
- Optional CSV / SQLite export for anyone who wants a queryable record

## Setup

```bash
git clone https://github.com/yugg755i/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

Create a `.env` file with your AbuseIPDB key (optional — the tool runs
fine without it, it just skips threat intel enrichment):

```
ABUSEIPDB_API_KEY=your_key_here
```

## Usage

```bash
# a single log file
python loganalyzer.py logs/auth.log

# a directory of logs (rotated / .gz included)
python loganalyzer.py logs/ -o incident_report.html

# a glob, restricted to a time window
python loganalyzer.py "logs/*.log.gz" --since 2026-06-01 --until 2026-06-09

# skip AbuseIPDB, adjust the brute-force threshold
python loganalyzer.py logs/auth.log --no-enrich --threshold 8

# also keep a queryable record
python loganalyzer.py logs/auth.log --export-csv out.csv --export-db
```

Full flag list: `python loganalyzer.py --help`

## Project Structure

```text
log-analyzer/
├── loganalyzer.py          # CLI entrypoint — the whole tool starts here
├── requirements.txt
├── README.md
├── logs/                   # drop SSH auth logs here (plain or .gz)
├── src/
│   ├── parser.py           # log parsing, status/invalid-user aware, gz support
│   ├── input_resolver.py   # file / directory / glob resolution
│   ├── detector.py         # brute-force detection, IP counting, time filtering
│   ├── enrichment.py       # AbuseIPDB threat intelligence
│   ├── database.py         # optional CSV / SQLite export
│   └── report/
│       ├── builder.py      # assembles report context
│       ├── renderer.py     # renders the self-contained HTML file
│       └── template.html   # report layout, styling, inline charts
├── data/                   # generated reports / exports (gitignored)
└── tests/
```

## Stack

- Python 3
- Jinja2 (report templating)
- Requests
- python-dotenv
- SQLite (optional export only)
- AbuseIPDB API
