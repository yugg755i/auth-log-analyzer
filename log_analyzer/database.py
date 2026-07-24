import csv
import json
import sqlite3

DEFAULT_DB_PATH = "data/alerts.db"

CSV_FIELDNAMES = [
    "timestamp", "log_type", "status", "actor", "actor_type",
    "invalid_user", "user", "ip", "port", "source_file",
]


def create_database(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_type TEXT,
            status TEXT,
            actor TEXT,
            actor_type TEXT,
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
        INSERT INTO events (timestamp, log_type, status, actor, actor_type, invalid_user, user, ip, port, source_file)
        VALUES (:timestamp, :log_type, :status, :actor, :actor_type, :invalid_user, :user, :ip, :port, :source_file)
        """,
        [{**e, "invalid_user": int(e["invalid_user"])} for e in events],
    )
    conn.commit()
    conn.close()


def export_csv(events, output_path):
    with open(output_path, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)

def export_json(events, output_path):
    with open(output_path, "w") as file:
        json.dump(
            [{field: e.get(field) for field in CSV_FIELDNAMES} for e in events],
            file,
            indent=2,
            default=str,
        )
