import os
import json
from flask import Flask, request, render_template
from hashing import compute_hashes
from vt import check_url_virustotal, check_filehash_virustotal
from logger import log_event
import time
from flask import Response
from event_store import get_events
from notifier import notify
import requests  # used for exception type catching

# ---------------- SETTINGS SYSTEM ---------------- #

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


# ---------------- FLASK APP ---------------- #

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- HOME PAGE ---------------- #

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- SETTINGS PAGE ---------------- #

@app.route("/settings")
def settings_page():
    settings = load_settings()
    return render_template("settings.html", settings=settings)


@app.route("/save_settings", methods=["POST"])
def save_settings_route():

    data = {
        "vt_api_key": request.form.get("vt_api_key"),

        "watchdog_folders": request.form.get("watchdog_folders"),

        "enable_discord": request.form.get("enable_discord"),
        "discord_webhook": request.form.get("discord_webhook"),

        "enable_telegram": request.form.get("enable_telegram"),
        "telegram_bot": request.form.get("telegram_bot"),
        "telegram_chat_id": request.form.get("telegram_chat_id"),

        "enable_email": request.form.get("enable_email"),
        "email_to": request.form.get("email_to"),

        "scanning_enabled": request.form.get("scanning_enabled")
    }

    save_settings(data)
    return render_template("settings_saved.html")


# ---------------- WATCH LOG PAGE ---------------- #

@app.route("/watch_log")
def watch_log():
    return render_template("watch_log.html")


@app.route("/stream_events")
def stream_events():
    def event_stream():
        last_len = 0
        while True:
            events = get_events()
            if len(events) != last_len:
                last_len = len(events)
                yield f"data: {json.dumps(events)}\n\n"
            time.sleep(1)

    return Response(event_stream(), mimetype="text/event-stream")


# ---------------- URL SCAN ---------------- #
# NOTE: vt.check_url_virustotal(url) returns RAW engine table for URL scans.
# We normalize here into counts + engines to match file-scan format.

@app.route("/check_url", methods=["POST"])
def check_url():
    settings = load_settings()

    # If scanning disabled
    if settings["scanning_enabled"] == "no":
        return render_template("disabled.html")

    url = request.form.get("url")

    # If empty
    if not url or url.strip() == "":
        return render_template("empty_input.html")

    try:
        raw_result = check_url_virustotal(url)
    except requests.exceptions.SSLError as e:
        # SSL problem occurred connecting to VirusTotal — show friendly page
        return render_template("error_ssl.html", message=str(e))
    except Exception as e:
        # Generic error — friendly message
        return render_template("error_generic.html", message=str(e))

    # raw_result may already be normalized (unlikely) or be raw engine table.
    # If it's already a dict with 'counts' and 'engines' use as-is; otherwise normalize.
    if isinstance(raw_result, dict) and "counts" in raw_result and "engines" in raw_result:
        counts = raw_result.get("counts", {"malicious":0,"suspicious":0,"clean":0,"harmless":0})
        engines = raw_result.get("engines", {})
    else:
        # raw_result is expected to be the VirusTotal engine table:
        # { "EngineName": { "category": "...", "engine_name": "...", ... }, ... }
        counts = {"malicious": 0, "suspicious": 0, "clean": 0, "harmless": 0}
        engines = {}
        if isinstance(raw_result, dict):
            for eng, info in raw_result.items():
                cat = info.get("category", "clean")
                if cat == "malicious":
                    counts["malicious"] += 1
                elif cat == "suspicious":
                    counts["suspicious"] += 1
                elif cat == "harmless":
                    counts["harmless"] += 1
                else:
                    counts["clean"] += 1

                engines[eng] = {
                    "result": cat,
                    "engine_name": info.get("engine_name", eng)
                }

    # Log + notify (we pass the normalized structure)
    normalized = {"counts": counts, "engines": engines}
    log_event(event_type="manual_url_scan", url=url, vt_result=normalized)
    notify(event_type="manual_url_scan", url=url, vt_result=normalized)

    # Render template: pass both vt_result and counts so both old/new templates work
    return render_template(
        "result.html",
        vt_result=engines,    # for templates that expect vt_result (engine table)
        counts=counts,
        engines=engines
    )


# ---------------- FILE SCAN ---------------- #

@app.route("/upload_file", methods=["POST"])
def upload_file():
    settings = load_settings()

    # If scanning disabled
    if settings["scanning_enabled"] == "no":
        return render_template("disabled.html")

    file = request.files.get("file")
    if not file or file.filename.strip() == "":
        return render_template("empty_input.html")

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    hashes = compute_hashes(path)

    try:
        raw = check_filehash_virustotal(hashes["sha256"])
    except requests.exceptions.SSLError as e:
        return render_template("error_ssl.html", message=str(e))
    except Exception as e:
        return render_template("error_generic.html", message=str(e))

    # raw is the full VirusTotal file response JSON — extract counts+engines safely
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
            "result": details.get("category"),
            "engine_name": details.get("engine_name")
        }
        for eng, details in results.items()
    }

    log_event(
        event_type="manual_file_scan",
        file_path=path,
        hashes=hashes,
        vt_result=raw
    )
    notify(
        event_type="manual_file_scan",
        file_path=path,
        hashes=hashes,
        vt_result=raw
    )

    # Pass vt_result and counts (vt_result keeps identical name used in templates)
    return render_template(
        "file_results.html",
        vt_result=engines,
        counts=counts,
        hashes=hashes
    )


# ---------------- LOGS PAGE ---------------- #

@app.route("/logs")
def logs_page():
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


# ---------------- START APP ---------------- #

if __name__ == "__main__":
    app.run(debug=True)
