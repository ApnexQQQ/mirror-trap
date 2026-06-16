"""
MODULE 8 — SELF-LEARNING ENGINE
After each attack session, DeepSeek reviews what was probed
and automatically generates new traps in those areas.
System gets smarter after every attack.
"""

import json
import urllib.request

DEEPSEEK_API_KEY = ""  # set from settings.py at runtime


def learn_from_session(session: dict, classification: dict) -> dict:
    """
    After an attack session ends, analyze what was probed
    and generate new deception assets targeting that attacker type.
    """
    if not DEEPSEEK_API_KEY:
        return _static_recommendations(classification)

    prompt = f"""
You are a defensive cybersecurity AI.
An attacker just probed a server. Analyze what they did and
recommend new deception traps to deploy for next time.

Session summary:
- Ports probed: {session.get('ports', [])}
- Probe count: {session.get('probe_count', 0)}
- Attacker type: {classification.get('attacker_type', 'unknown')}
- Tool used: {classification.get('likely_tool', 'unknown')}
- Objective: {classification.get('objective', 'unknown')}
- Predicted next moves: {classification.get('next_moves', [])}

Respond ONLY in JSON, no other text:
{{
    "new_fake_ports": [list of port numbers to add fake services on],
    "new_fake_files": [
        {{"path": "/fake/path", "content_hint": "what this file should pretend to contain"}}
    ],
    "new_fake_credentials": [
        {{"username": "fake", "password": "fake", "service": "where to plant this"}}
    ],
    "trap_positions": ["description of where to place next traps based on attacker behavior"],
    "reasoning": "why these traps will work against this attacker type"
}}
"""

    payload = json.dumps({
        "model":      "deepseek-chat",
        "max_tokens": 600,
        "messages":   [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.deepseek.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data  = json.loads(resp.read().decode("utf-8"))
            raw   = data["choices"][0]["message"]["content"]
            clean = raw.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
    except Exception as e:
        return _static_recommendations(classification)


def _static_recommendations(classification: dict) -> dict:
    """Fallback when API unavailable."""
    obj = classification.get("objective", "")

    if "database" in obj or "data" in obj:
        return {
            "new_fake_ports":       [3306, 5432, 27017],
            "new_fake_files":       [{"path": "/var/backups/db_dump.sql",
                                      "content_hint": "fake database dump"}],
            "new_fake_credentials": [{"username": "dbroot",
                                      "password": "Db@Root2024!", "service": "mysql"}],
            "trap_positions":       ["plant fake DB credentials in /etc/mysql/my.cnf"],
            "reasoning":            "Attacker targeting databases — plant DB lures"
        }

    return {
        "new_fake_ports":       [8080, 8443, 9200],
        "new_fake_files":       [{"path": "/var/www/html/admin/config.php",
                                  "content_hint": "fake admin config with API keys"}],
        "new_fake_credentials": [{"username": "admin",
                                  "password": "Admin@2024!", "service": "web"}],
        "trap_positions":       ["expose fake admin panel on port 8080"],
        "reasoning":            "General recon detected — plant web admin lures"
    }
