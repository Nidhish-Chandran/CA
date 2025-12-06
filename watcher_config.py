# watcher_config.py
import json
import os

SETTINGS_FILE = "settings.json"

def load_watch_folders():
    if not os.path.exists(SETTINGS_FILE):
        return []

    data = json.load(open(SETTINGS_FILE, "r"))

    # Convert textarea into list
    raw = data.get("watchdog_folders", "")
    folders = [f.strip() for f in raw.split("\n") if f.strip()]

    return folders

WATCH_FOLDERS = load_watch_folders()
