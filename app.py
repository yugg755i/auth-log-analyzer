from flask import Flask, render_template, request
from src.database import get_all_alerts, search_by_ip
from src.detector import top_ips

app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = get_all_alerts()

    total_alerts = len(alerts)

    unique_ips = len(set(alert[3] for alert in alerts))

    top_ips_list = top_ips([{"ip": alert[3]} for alert in alerts])

    return render_template(
        "dashboard.html",
        title="Log Analyzer Dashboard",
        alerts=alerts,
        total_alerts=total_alerts,
        unique_ips=unique_ips,
        top_ips=top_ips_list,
    )


@app.route("/search")
def search():
    ip = request.args.get("ip")

    results = []

    if ip:
        results = search_by_ip(ip)
    return render_template("search.html", results=results, ip=ip)


@app.route("/alerts")
def alerts():
    return str(get_all_alerts())


if __name__ == "__main__":
    app.run(debug=True)
