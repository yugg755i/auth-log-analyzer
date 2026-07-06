# Log Analyzer

A single-command CLI tool for SSH authentication log forensic triage.
Analyze one or more log files and generate a self-contained HTML incident report with detection results, threat intelligence enrichment, and investigation context.

```
logs → parse → detect → enrich → report
```

Built around a real incident response workflow: given a collection of SSH authentication logs, quickly identify suspicious activity and produce a report suitable for analyst review.

## Features

- Single-command CLI installed as a native `loganalyzer` command
- Parses SSH authentication logs, distinguishing failed, accepted, and invalid-user attempts
- Supports individual files, directories, glob patterns, rotated logs, and `.gz` archives
- Configurable detection thresholds via YAML configuration
- Time-range filtering (`--since` / `--until`)
- Sliding-window SSH brute-force detection
- Username enumeration detection
- Session reconstruction with first seen, last seen, attempt counts, and authentication outcomes
- Detects successful logins following brute-force activity
- AbuseIPDB threat intelligence enrichment for public IPs
- Executive summary with threat level, primary attack type, and MITRE ATT&CK technique mapping
- Per-IP confidence scoring with a signal-by-signal checklist breakdown
- Deterministic, template-based per-IP attack narratives (no AI/LLM calls, no network calls)
- Visual timeline flow per flagged IP, plus the raw log lines behind each finding as evidence
- Self-contained HTML incident report with inline charts
- Optional CSV and SQLite export
- Unit-tested parser, detector, scoring, and configuration modules using pytest

## Install

```bash
git clone https://github.com/yugg755i/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
pip install -e .
```

That installs `loganalyzer` as a command available from anywhere, not
just inside the repo:

```bash
loganalyzer -h
```

Create a `.env` file with your AbuseIPDB key (optional — the tool runs
fine without it, it just skips threat intel enrichment):

```
ABUSEIPDB_API_KEY=your_key_here
```

## Usage

```bash
# a single log file
loganalyzer logs/auth.log

# a directory of logs (rotated / .gz included)
loganalyzer logs/ -o incident_report.html

# a glob, restricted to a time window
loganalyzer "logs/*.log.gz" --since 2026-06-01 --until 2026-06-09

# tune brute-force detection: 8 failures inside a 5-minute window
loganalyzer logs/auth.log --threshold 8 --window 5

# tune username enumeration: 3 distinct usernames inside a 5-minute window
loganalyzer logs/auth.log --enum-threshold 3 --enum-window 5

# skip AbuseIPDB
loganalyzer logs/auth.log --no-enrich

# also keep a queryable record
loganalyzer logs/auth.log --export-csv out.csv --export-db

# use a custom configuration
loganalyzer logs/ --config config/loganalyzer.yaml
```

Full flag list: `loganalyzer --help`

## Configuration

Detection thresholds can be customized using a YAML configuration file.

By default the application looks for:

config/loganalyzer.yaml

Example:

```yaml
bruteforce_threshold: 5
bruteforce_window: 5

enum_threshold: 5
enum_window: 5

confidence_threshold: 90
```

Command-line arguments override configuration values when both are provided.

## Project Structure

```text
log-analyzer/
├── pyproject.toml          # packaging + loganalyzer console script
├── requirements.txt
├── README.md
├── config/
│   └── loganalyzer.yaml    # optional detection thresholds and application settings
├── logs/                   # SSH authentication logs (plain or .gz)
├── log_analyzer/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point and application orchestration
│   ├── config.py           # configuration loading, validation, and defaults
│   ├── parser.py           # SSH log parsing with .gz support
│   ├── input_resolver.py   # file, directory, and glob resolution
│   ├── detector.py         # brute-force detection, username enumeration, session analysis
│   ├── enrichment.py       # AbuseIPDB threat intelligence enrichment
│   ├── database.py         # optional CSV / SQLite export
│   └── report/
│       ├── __init__.py
│       ├── builder.py      # assembles report context
│       ├── scoring.py      # confidence scoring, MITRE mapping, narrative generation
│       ├── renderer.py     # renders the self-contained HTML report
│       └── template.html   # report template, styling, and inline charts
├── data/                   # generated reports and exports (gitignored)
├── tests/
│   ├── __init__.py
│   ├── conftest.py         # shared pytest fixtures
│   ├── test_config.py      # configuration tests
│   ├── test_detector.py    # detection engine tests
│   ├── test_parser.py      # parser tests
│   └── test_scoring.py     # confidence scoring / narrative tests
└── screenshots/
    └── report.png          # README preview image
```

## Stack

- Python 3
- Jinja2
- Requests
- PyYAML
- python-dotenv
- pytest
- SQLite (optional)
- AbuseIPDB API

## Report Preview

![Report preview](screenshots/incident-report-overview.png)
