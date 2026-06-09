from src.database import clear_alerts, create_database, insert_alerts
from src.parser import parse_log
from src.utils import get_latest_log


def process_logs():
    latest_log = get_latest_log("logs")
    alerts = parse_log(latest_log)

    create_database()
    clear_alerts()
    insert_alerts(alerts)

    return alerts
