import json
import os

SETTINGS_FILE = "settings.json"


# -----------------------
# LOAD SETTINGS.JSON
# -----------------------
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            return json.load(open(SETTINGS_FILE))
        except:
            return {}
    return {}


settings = load_settings()


# -----------------------
# VIRUSTOTAL API
# -----------------------
VT_API_KEY = settings.get("vt_api_key", "")


# -----------------------
# WATCHDOG FOLDERS
# -----------------------
WATCH_FOLDERS = [
    f.strip() for f in settings.get("watchdog_folders", "").split("\n")
    if f.strip()
]


# -----------------------
# NOTIFICATION SETTINGS
# -----------------------
ENABLE_EMAIL = settings.get("enable_email", "no") == "yes"
ENABLE_TELEGRAM = settings.get("enable_telegram", "no") == "yes"
ENABLE_DISCORD = settings.get("enable_discord", "no") == "yes"

EMAIL_TO = [settings.get("email_to")] if settings.get("email_to") else []

TELEGRAM_BOT_TOKEN = settings.get("telegram_bot", "")
TELEGRAM_CHAT_ID = settings.get("telegram_chat_id", "")

DISCORD_WEBHOOK_URL = settings.get("discord_webhook", "")


# -----------------------
# SYSTEM CONTROL
# -----------------------
SCANNING_ENABLED = settings.get("scanning_enabled", "yes")


# -----------------------
# LOGGER CONFIG (STATIC)
# -----------------------
LOG_MODE = "json"             # "json" or "sqlite"
JSON_LOG_FILE = "logs.json"
SQLITE_DB_FILE = "logs.db"
