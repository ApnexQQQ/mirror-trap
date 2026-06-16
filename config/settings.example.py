import os
from dotenv import load_dotenv

load_dotenv()

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# DB
DB_PATH = os.path.expanduser("~/mirror-trap/data/fingerprints.db")
USER_DB = os.path.expanduser("~/mirror-trap/data/users.db")

# Honeypot
HONEYPOT_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
PASS = os.environ.get("DASHBOARD_PASSWORD", "mirrortrap123")
