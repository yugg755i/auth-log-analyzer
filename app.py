import json

from flask import Flask, render_template, request
from src.database import get_all_alerts, search_by_ip, search_by_user
from src.detector import detect_bruteforce, top_ips
from src.pipeline import process_logs

parsed_alerts = process_logs()
app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = get_all_alerts()

    total_alerts = len(alerts)
    unique_ips = len(set(alert[3] for alert in alerts))

    top_ips_list = top_ips(parsed_alerts)
    brute_force_count = len(detect_bruteforce(parsed_alerts))

    try:
        with open("data/malicious_alerts.json") as f:
            malicious_alerts = json.load(f)

        malicious_count = len(set(alert["ip"] for alert in malicious_alerts))
    except (FileNotFoundError, json.JSONDecodeError):
        malicious_count = 0

    return render_template(
        "dashboard.html",
        alerts=alerts,
        total_alerts=total_alerts,
        unique_ips=unique_ips,
        top_ips=top_ips_list,
        brute_force_count=brute_force_count,
        malicious_count=malicious_count,
    )


@app.route("/search")
def search():
    ip = request.args.get("ip", "")
    user = request.args.get("user", "")
    searched = bool(ip or user)

    results = []

    if ip:
        results = search_by_ip(ip)
    elif user:
        results = search_by_user(user)
    else:
        results = get_all_alerts()
    return render_template(
        "search.html",
        results=results,
        ip=ip,
        user=user,
        searched=searched,
    )


if __name__ == "__main__":
    app.run(debug=True)
