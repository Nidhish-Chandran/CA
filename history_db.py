# history_db.py
import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_FILE = "scan_history.db"

def init_db():
    os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        key TEXT PRIMARY KEY,        -- sha256 or URL
        key_type TEXT,               -- 'sha256' or 'url'
        result_json TEXT,
        last_scanned TEXT
    );
    """)
    conn.commit()
    conn.close()

def get_cached_result(key, key_type):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT result_json, last_scanned FROM scan_history WHERE key=? AND key_type=?", (key, key_type))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    try:
        return {"result": json.loads(row[0]), "last_scanned": row[1]}
    except Exception:
        return None

def add_or_update_cache(key, key_type, result_obj):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_history (key, key_type, result_json, last_scanned)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET result_json=excluded.result_json, last_scanned=excluded.last_scanned
    """, (key, key_type, json.dumps(result_obj), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def purge_older_than(days=30):
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM scan_history WHERE last_scanned < ?", (cutoff,))
    conn.commit()
    conn.close()
    
def list_all(limit=200):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT key, key_type, result_json, last_scanned FROM scan_history ORDER BY last_scanned DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows