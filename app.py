# app.py
import os
import json
import time
from flask import Flask, request, render_template, Response
from hashing import compute_hashes
from vt import check_url_virustotal, check_filehash_virustotal
from logger import log_event
from notifier import notify

from history_db import list_all, get_cached_result
from flask import send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io
import json

# DB modules
import local_db
import history_db

# initialize DBs
local_db.init_db()
history_db.init_db()

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SETTINGS_FILE = "settings.json"

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {
            "vt_api_key": "",
            "watchdog_folders": "",
            "discord_webhook": "",
            "email_to": "",
            "scanning_enabled": "yes"
        }
    return json.load(open(SETTINGS_FILE, "r"))

def save_settings(data):
    json.dump(data, open(SETTINGS_FILE, "w"), indent=4)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/settings")
def settings_page():
    settings = load_settings()
    return render_template("settings.html", settings=settings)
@app.route("/history")
def view_history():
    rows = history_db.list_all(limit=200)

    # rows = [(key, key_type, result_json, last_scanned), ...]
    parsed = []
    for key, key_type, result_json, last_scanned in rows:
        try:
            result_obj = json.loads(result_json)
        except Exception:
            result_obj = {}
        parsed.append({
            "key": key,
            "type": key_type,
            "result": result_obj,
            "date": last_scanned
        })

    return render_template("history.html", items=parsed)

@app.route("/download_pdf/<key>")
def download_pdf(key):
    entry = history_db.get_cached_result(key, "sha256") or history_db.get_cached_result(key, "url")

    if not entry:
        return "No such record."

    result = entry["result"]
    date = entry["last_scanned"]

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 750, "Cyber Security Analyzer - Scan Report")

    p.setFont("Helvetica", 12)
    p.drawString(50, 720, f"Key: {key}")
    p.drawString(50, 700, f"Scanned: {date}")

    p.drawString(50, 670, "Summary:")
    y = 650

    counts = result.get("counts", {})
    for k, v in counts.items():
        p.drawString(70, y, f"{k.capitalize()}: {v}")
        y -= 20

    p.drawString(50, y - 10, "Engine Results:")
    y -= 40

    engines = result.get("engines", {})
    for eng, data in engines.items():
        if y < 50:  # new page if space too small
            p.showPage()
            y = 750
        p.drawString(70, y, f"{eng}: {data.get('result', 'unknown')}")
        y -= 20

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"scan_report_{key}.pdf",
        mimetype="application/pdf"
    )

@app.route("/save_settings", methods=["POST"])
def save_settings_route():
    data = {
        "vt_api_key": request.form.get("vt_api_key"),
        "watchdog_folders": request.form.get("watchdog_folders"),
        "discord_webhook": request.form.get("discord_webhook"),
        "email_to": request.form.get("email_to"),
        "scanning_enabled": request.form.get("scanning_enabled", "yes")
    }
    save_settings(data)
    return render_template("settings_saved.html")

@app.route("/watch_log")
def watch_log():
    return render_template("watch_log.html")

@app.route("/stream_events")
def stream_events():
    def event_stream():
        last_len = 0
        while True:
            events = []  # If you have get_events
            try:
                from event_store import get_events
                events = get_events()
            except Exception:
                events = []
            if len(events) != last_len:
                last_len = len(events)
                yield f"data: {json.dumps(events)}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")

# ---------------- URL SCAN ----------------
@app.route("/check_url", methods=["POST"])
def check_url():
    settings = load_settings()
    if settings.get("scanning_enabled") == "no":
        return render_template("disabled.html")

    url = request.form.get("url", "").strip()
    if not url:
        return render_template("empty_input.html")

    # Check history cache for URL
    cached = history_db.get_cached_result(url, "url")
    if cached:
        cached_obj = cached["result"]
        # cached_obj expected to be normalized dict { "counts": {...}, "engines": {...} }
        counts = cached_obj.get("counts", {})
        engines = cached_obj.get("engines", {})
        # log and notify (optional)
        log_event(event_type="manual_url_scan", url=url, vt_result=cached_obj)
        notify(event_type="manual_url_scan", url=url, vt_result=cached_obj)
        return render_template("result.html", vt_result=engines, counts=counts, hashes=None)

    # Not cached -> query VT
    engines = check_url_virustotal(url)
    # normalize counts
    counts = {"malicious":0,"suspicious":0,"clean":0,"harmless":0}
    for eng, info in engines.items():
        cat = info.get("result") or info.get("category") or "clean"
        if cat == "malicious":
            counts["malicious"] += 1
        elif cat == "suspicious":
            counts["suspicious"] += 1
        elif cat == "harmless":
            counts["harmless"] += 1
        else:
            counts["clean"] += 1

    normalized = {"counts": counts, "engines": engines}
    # cache it
    history_db.add_or_update_cache(url, "url", normalized)

    log_event(event_type="manual_url_scan", url=url, vt_result=normalized)
    notify(event_type="manual_url_scan", url=url, vt_result=normalized)

    return render_template("result.html", vt_result=engines, counts=counts, hashes=None)

# ---------------- FILE SCAN ----------------
@app.route("/upload_file", methods=["POST"])
def upload_file():
    settings = load_settings()
    if settings.get("scanning_enabled") == "no":
        return render_template("disabled.html")

    file = request.files.get("file")
    if not file or file.filename.strip() == "":
        return render_template("empty_input.html")

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    # compute hashes
    hashes = compute_hashes(path)
    sha256 = hashes.get("sha256")

    # 1) Local signature check
    if local_db.is_malicious_local(sha256):
        counts = {"malicious":1,"suspicious":0,"clean":0,"harmless":0}
        engines = {"LocalDB": {"result": "malicious", "engine_name": "Local Signature DB"}}
        log_event(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result={"counts":counts,"engines":engines})
        notify(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result={"counts":counts,"engines":engines})
        return render_template("file_result.html", vt_result=engines, counts=counts, hashes=hashes)

    # 2) History/cache check
    cached = history_db.get_cached_result(sha256, "sha256")
    if cached:
        cached_obj = cached["result"]
        counts = cached_obj.get("counts", {})
        engines = cached_obj.get("engines", {})
        log_event(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result=cached_obj)
        notify(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result=cached_obj)
        return render_template("file_results.html", vt_result=engines, counts=counts, hashes=hashes)

    # 3) Not found locally -> query VT
    raw = check_filehash_virustotal(sha256)
    if not raw:
        # VT failed or no API key -> show partial info
        counts = {"malicious":0,"suspicious":0,"clean":0,"harmless":0}
        engines = {}
        # Optionally cache empty result
        history_db.add_or_update_cache(sha256, "sha256", {"counts":counts,"engines":engines})
        log_event(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result={})
        notify(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result={})
        return render_template("file_results.html", vt_result=engines, counts=counts, hashes=hashes)

    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    results = raw.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

    counts = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "clean": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0)
    }

    engines = {
        eng: {
            "result": details.get("category") or details.get("result") or "clean",
            "engine_name": details.get("engine_name", eng)
        }
        for eng, details in (results or {}).items()
    }

    normalized = {"counts": counts, "engines": engines}
    # cache result
    history_db.add_or_update_cache(sha256, "sha256", normalized)

    # enrichment: add to local DB if VT consensus strong
    if counts.get("malicious", 0) >= 3:
        local_db.add_malicious_hash(sha256)

    log_event(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result=raw)
    notify(event_type="manual_file_scan", file_path=path, hashes=hashes, vt_result=raw)

    return render_template("file_results.html", vt_result=engines, counts=counts, hashes=hashes)

@app.route("/logs")
def logs_page():
    # adapt as before
    from bakup.log_config import LOG_MODE, JSON_LOG_FILE, SQLITE_DB_FILE
    import sqlite3

    logs = []
    if LOG_MODE == "json":
        if os.path.exists(JSON_LOG_FILE):
            logs = json.load(open(JSON_LOG_FILE))
    else:
        conn = sqlite3.connect(SQLITE_DB_FILE)
        cursor = conn.cursor()
        rows = cursor.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
        conn.close()
        for row in rows:
            logs.append({
                "timestamp": row[1],
                "event_type": row[2],
                "file_path": row[3],
                "url": row[4],
                "hashes": row[5],
                "vt_result": row[6]
            })
    return render_template("logs.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
