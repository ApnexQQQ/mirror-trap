"""MODULE — TELEGRAM ALERTS
Sends you a message when an attacker is detected.
"""

import json
import urllib.request


def send_alert(session: dict, classification: dict = {}):
    """Send Telegram alert with attacker session summary."""
    from config.settings import TELEGRAM_BOT_TOKEN as bot_token, TELEGRAM_CHAT_ID as chat_id

    if not bot_token or not chat_id:
        print("[ALERT] Telegram not configured - printing to console:")
        print(session)
        return

    lines = [
        "\U0001f6a8 *LIAR'S ECHO \u2014 ATTACKER DETECTED*",
        f"IP: `{session.get('ip', 'unknown')}`",
        f"Probes: {session.get('probe_count', 0)}",
        f"Ports: {session.get('ports', [])}",
        f"Fingerprint: `{session.get('fingerprint', 'none')}`",
        f"First seen: {session.get('first_seen', '')}",
    ]

    if classification and "error" not in classification:
        lines += [
            "",
            "\U0001f916 *AI CLASSIFICATION*",
            f"Type: {classification.get('attacker_type', '?')}",
            f"Tool: {classification.get('likely_tool', '?')}",
            f"Objective: {classification.get('objective', '?')}",
            f"Skill: {classification.get('skill_level', '?')}",
            f"Next moves: {', '.join(classification.get('next_moves', []))}",
        ]

    message = "\n".join(lines)

    payload = json.dumps({
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "Markdown"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[ALERT] Telegram send failed: {e}")
