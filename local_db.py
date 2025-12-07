# local_db.py
import sqlite3
import os
from datetime import datetime

DB_FILE = "malware_hashes.db"

def init_db():
    os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS malware_hashes (
        sha256 TEXT PRIMARY KEY,
        added_at TEXT
    );
    """)
    conn.commit()
    conn.close()

def is_malicious_local(sha256):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM malware_hashes WHERE sha256 = ?", (sha256,))
    row = cur.fetchone()
    conn.close()
    return row is not None

def add_malicious_hash(sha256):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO malware_hashes (sha256, added_at) VALUES (?, ?)",
                (sha256, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def list_hashes(limit=100):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT sha256, added_at FROM malware_hashes ORDER BY added_at DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows
