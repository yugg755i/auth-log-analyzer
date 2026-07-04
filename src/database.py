import csv
import sqlite3

DEFAULT_DB_PATH = "data/alerts.db"


def create_database(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            status TEXT,
            invalid_user INTEGER,
            user TEXT,
            ip TEXT,
            port TEXT,
            source_file TEXT
        )
    """)
    conn.commit()
    conn.close()


def insert_events(events, db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO events (timestamp, status, invalid_user, user, ip, port, source_file)
        VALUES (:timestamp, :status, :invalid_user, :user, :ip, :port, :source_file)
        """,
        [{**e, "invalid_user": int(e["invalid_user"])} for e in events],
    )
    conn.commit()
    conn.close()


def export_csv(events, output_path):
    with open(output_path, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["timestamp", "status", "invalid_user", "user", "ip", "port", "source_file"],
        )
        writer.writeheader()
        writer.writerows(events)
