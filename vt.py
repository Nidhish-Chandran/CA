import time
import requests
from config import VT_API_KEY


# Normalize results into the structure your HTML expects
def normalize(results, stats):
    return {
        "counts": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0)
        },
        "engines": {
            engine: {
                "result": info.get("category", "clean"),
                "engine_name": info.get("engine_name", engine)
            }
            for engine, info in results.items()
        }
    }


# ------------------ URL SCAN ------------------
def check_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    submit_ep = "https://www.virustotal.com/api/v3/urls"
    resp = requests.post(submit_ep, data={"url": url}, headers=headers)

    if resp.status_code != 200:
        return {"counts": {}, "engines": {}}

    analysis_id = resp.json()["data"]["id"]
    result_ep = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    while True:
        res = requests.get(result_ep, headers=headers).json()
        attr = res["data"]["attributes"]

        if attr["status"] == "completed":
            stats = attr["stats"]
            results = attr["results"]
            return normalize(results, stats)

        time.sleep(1)


# ------------------ FILE SCAN ------------------
def check_filehash_virustotal(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    res = requests.get(url, headers=headers).json()
    attr = res.get("data", {}).get("attributes", {})

    stats = attr.get("last_analysis_stats", {})
    results = attr.get("last_analysis_results", {})

    return normalize(results, stats)
