import os
import json
from flask import Flask, request, render_template
from hashing import compute_hashes
from vt import check_url_virustotal, check_filehash_virustotal
from logger import log_event
import time
from flask import Response, render_template
from event_store import get_events
from notifier import notify




app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET"])
def home():

    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/history")
def history():
    event_type = request.args.get("type")
    filter_by = {"event_type": event_type} if event_type else None
    logs = fetch_logs(filter_by)
    return render_template("history.html", logs=logs)

@app.route("/scan", methods=["GET", "POST"])
def scan():
    result = None
    if request.method == "POST":
        if "file" in request.files:
            f = request.files["file"]
            f.save(f.filename)
            hashes = compute_hashes(f.filename)
            vt_result = check_filehash_virustotal(hashes["sha256"])
            log_event("manual_file_scan", file_path=f.filename, hashes=hashes, vt_result=vt_result)
            notify("manual_file_scan", file_path=f.filename, hashes=hashes, vt_result=vt_result)
            result = {"file": f.filename, "hashes": hashes, "vt_result": vt_result}
        elif "url" in request.form:
            url = request.form["url"]
            vt_result = check_filehash_virustotal(url)  # Or URL check API
            log_event("manual_url_scan", url=url, vt_result=vt_result)
            notify("manual_url_scan", url=url, vt_result=vt_result)
            result = {"url": url, "vt_result": vt_result}
    return render_template("scan.html", result=result)

@app.route("/stream_events")
def stream_events():
    def event_stream():
        seen_ids = set()
        while True:
            events = get_events()
            for e in events:
                if e["id"] not in seen_ids:
                    yield f"data: {json.dumps(e)}\n\n"
                    seen_ids.add(e["id"])
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")
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

@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form.get("url")
    result = check_url_virustotal(url)
    log_event(
        event_type="manual_url_scan",
        url=url,
        vt_result=result
    )
    notify(
        event_type="manual_url_scan",
        url=url,
        vt_result=result
    )

    return render_template(
        "result.html",
        result=json.dumps(result, indent=4),
        hashes=None
    )


@app.route("/upload_file", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if not file:
        return render_template(
            "result.html",
            result="No file uploaded",
            hashes=None
        )

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    hashes = compute_hashes(path)
    vt_result = check_filehash_virustotal(hashes["sha256"])
    log_event(
        event_type="manual_file_scan",
        file_path=path,
        hashes=hashes,
        vt_result=vt_result
    )

    notify(
        event_type="manual_file_scan",
        file_path=path,
        hashes=hashes,
        vt_result=vt_result
    )



    return render_template(
        "result.html",
        result=json.dumps(vt_result, indent=4),
        hashes=json.dumps(hashes, indent=4)
    )

@app.route("/logs")
def logs_page():
    from log_config import LOG_MODE, JSON_LOG_FILE, SQLITE_DB_FILE
    import json, sqlite3

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
