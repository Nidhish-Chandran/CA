import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import *

MAX_DISCORD_MESSAGE = 1900  # Discord limit buffer

def summarize_threats(scan_results, limit=5):
    threats = []

    for engine, data in scan_results.items():
        category = data.get("category", "").lower()
        result = data.get("result", "")
        if category in ("malicious", "suspicious"):
            threats.append((engine, result))

    threats.sort(key=lambda x: x[0])
    total = len(threats)
    summary = threats[:limit]

    return total, summary

def send_email(subject, body):
    if not ENABLE_EMAIL:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USERNAME
        msg['To'] = ", ".join(EMAIL_TO)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USERNAME, EMAIL_TO, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[Email] Failed: {e}")


def send_telegram(message):
    if not ENABLE_TELEGRAM:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        requests.post(url, data=data)
    except Exception as e:
        print(f"[Telegram] Failed: {e}")


def send_discord(message):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        print(f"[Discord] HTTP {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[Discord] Exception: {e}")

def notify(event_type, file_path=None, url=None, hashes=None, vt_result=None):
    if not vt_result:
        return

    # Extract counts safely
    counts = vt_result.get("counts", {})
    malicious = counts.get("malicious", 0)
    suspicious = counts.get("suspicious", 0)

    # Only notify if malicious or suspicious found
    if malicious == 0 and suspicious == 0:
        print("[Notify] Clean. No Discord alert.")
        return

    msg = f"⚠️ Threat Detected — {event_type}\n"

    if file_path:
        msg += f"File: `{file_path}`\n"
    if url:
        msg += f"URL: {url}\n"
    if hashes:
        msg += f"SHA256: `{hashes.get('sha256')}`\n"

    msg += f"\nDetection Summary: {malicious} malicious, {suspicious} suspicious"

    send_discord(msg)  # <- IMPORTANT change