import csv
import sqlite3


def export_csv(output_path):

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT timestamp, user, ip, port
        FROM alerts
        """
    )

    rows = cursor.fetchall()

    conn.close()

    with open(output_path, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["timestamp", "user", "ip", "port"])

        writer.writerows(rows)


def create_database():

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user TEXT,
        ip TEXT,
        port TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_alerts(alerts):

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    for alert in alerts:
        cursor.execute(
            """
        INSERT INTO alerts (
            timestamp,
            user,
            ip,
            port
        )
        VALUES (?, ?, ?, ?)
        """,
            (alert["timestamp"], alert["user"], alert["ip"], alert["port"]),
        )

    conn.commit()
    conn.close()


def get_all_alerts():

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM alerts
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def clear_alerts():

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM alerts
        """
    )

    conn.commit()
    conn.close()


def search_by_ip(ip):

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM alerts WHERE ip LIKE ?
        ORDER BY timestamp DESC
        """,
        ("%" + ip + "%",),
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def search_by_user(user):

    conn = sqlite3.connect("data/alerts.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM alerts WHERE user LIKE ?
        ORDER BY timestamp DESC
        """,
        ("%" + user + "%",),
    )

    rows = cursor.fetchall()

    conn.close()

    return rows
