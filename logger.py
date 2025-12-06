import json
import sqlite3
import os
from datetime import datetime
from config import LOG_MODE, JSON_LOG_FILE, SQLITE_DB_FILE


# -----------------------
# JSON Logging
# -----------------------
def log_json(record):
    if not os.path.exists(JSON_LOG_FILE):
        with open(JSON_LOG_FILE, "w") as f:
            json.dump([], f, indent=2)

    with open(JSON_LOG_FILE, "r") as f:
        data = json.load(f)

    data.append(record)

    with open(JSON_LOG_FILE, "w") as f:
        json.dump(data, f, indent=2)


# -----------------------
# SQLite Logging
# -----------------------
def ensure_sqlite_setup():
    conn = sqlite3.connect(SQLITE_DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            file_path TEXT,
            url TEXT,
            hashes TEXT,
            vt_result TEXT
        );
    """)
    conn.commit()
    conn.close()


def log_sqlite(record):
    ensure_sqlite_setup()
    conn = sqlite3.connect(SQLITE_DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (timestamp, event_type, file_path, url, hashes, vt_result)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        record.get("timestamp"),
        record.get("event_type"),
        record.get("file_path"),
        record.get("url"),
        json.dumps(record.get("hashes")),
        json.dumps(record.get("vt_result")),
    ))

    conn.commit()
    conn.close()


# -----------------------
# Unified Logging API
# -----------------------
def log_event(event_type, file_path=None, url=None, hashes=None, vt_result=None):
    record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "event_type": event_type,
        "file_path": file_path,
        "url": url,
        "hashes": hashes,
        "vt_result": vt_result,
    }

    if LOG_MODE == "json":
        log_json(record)
    elif LOG_MODE == "sqlite":
        log_sqlite(record)
    else:
        raise ValueError("Invalid LOG_MODE specified.")

    return record
