# Log Analyzer

Log Analyzer is a Python project that processes SSH authentication logs and extracts useful security-related information from failed login attempts.

The project parses raw log data, identifies the most active source IPs, detects potential brute-force activity, enriches public IP addresses using AbuseIPDB, and generates investigation reports.

The goal of this project was to practice Python, log parsing, basic detection engineering concepts, and threat intelligence enrichment while building something closer to a real-world security workflow than a standalone script.

## Features

* Parse SSH authentication logs using regular expressions
* Extract timestamps, usernames, source IP addresses, and ports
* Convert timestamps into a consistent format
* Count login attempts by source IP
* Identify the most active source IPs
* Detect potential brute-force activity based on configurable thresholds
* Automatically locate the newest log file in a directory
* Check public IP reputation using the AbuseIPDB API
* Export parsed and enriched findings to JSON
* Generate a text-based investigation report
* Store parsed alerts in SQLite
* Command-line interface using argparse
* Export alerts to CSV

## Project Structure

```text
src/
├── parser.py
├── detector.py
├── enrichment.py
├── reporter.py
├── database.py
├── utils.py
└── main.py
```
Generated output:
- alerts.db
- parsed_alerts.json
- malicious_alerts.json
- alerts.csv
- report.txt

## Installation

```bash
git clone https://github.com/yugg755i/log-analyzer.git
cd log-analyzer

pip install -r requirements.txt
```

Create a `.env` file:

```env
ABUSEIPDB_API_KEY=YOUR_API_KEY
```

## Usage

Show top source IPs:

```bash
python src/main.py --top-ips
```
Detect brute-force activity:

```bash
python src/main.py --bruteforce
```
Show malicious alerts:

```bash
python src/main.py --malicious-alerts
```
Export alerts to CSV:

```bash
python src/main.py --export-csv
```
Generate a report:

```bash
python src/main.py --report
```

## Technologies Used

- Python
- SQLite
- Regular Expressions (`re`)
- Requests
- JSON
- Pathlib
- Collections (`Counter`)
- Datetime
- AbuseIPDB API

## Future Improvements

* HTML report generation
* Severity scoring
* Flask dashboard
* Search functionality
* Alert visualizations
