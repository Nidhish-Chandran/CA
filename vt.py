# vt.py
import time
import requests
import json
import os
from typing import Dict, Any

# prefer a config.py VT_API_KEY, fallback to settings.json if present
try:
    from config import VT_API_KEY as CONFIG_VT_KEY
except Exception:
    CONFIG_VT_KEY = ""

SETTINGS_FILE = "settings.json"

def get_vt_api_key():
    # config takes precedence
    if CONFIG_VT_KEY:
        return CONFIG_VT_KEY
    if os.path.exists(SETTINGS_FILE):
        try:
            data = json.load(open(SETTINGS_FILE, "r"))
            key = data.get("vt_api_key", "")
            if key:
                return key
        except Exception:
            pass
    return ""

def check_url_virustotal(url: str, poll_interval: float = 1.0) -> Dict[str, Any]:
    """
    Submit URL to VT and wait for analysis completion.
    Returns normalized engine table: { engine_name: { "category": "...", "engine_name": "..." }, ... }
    If error occurs, returns {}.
    """
    api_key = get_vt_api_key()
    if not api_key:
        return {}

    submit_ep = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.post(submit_ep, data={"url": url}, headers=headers, timeout=15)
    except Exception:
        return {}

    if resp.status_code not in (200, 201):
        return {}

    data = resp.json()
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        return {}

    result_ep = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    # poll until 'completed' or until timeout cycles
    for _ in range(120):  # 120 * 1s = 2 minutes max
        try:
            r = requests.get(result_ep, headers=headers, timeout=15)
            d = r.json()
        except Exception:
            time.sleep(poll_interval)
            continue

        status = d.get("data", {}).get("attributes", {}).get("status", "")
        if status == "completed":
            results = d.get("data", {}).get("attributes", {}).get("results", {})
            # normalize to engine table
            engines = {}
            for eng, info in results.items():
                category = info.get("category") or info.get("result") or "clean"
                engines[eng] = {
                    "result": category,
                    "engine_name": info.get("engine_name", eng)
                }
            return engines
        time.sleep(poll_interval)

    return {}

def check_filehash_virustotal(file_hash: str) -> Dict[str, Any]:
    """
    Query VT files endpoint for the hash. Returns raw JSON response (dict).
    If there's an error or not found, returns {}.
    """
    api_key = get_vt_api_key()
    if not api_key:
        return {}

    ep = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(ep, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {}
        return resp.json()
    except Exception:
        return {}
