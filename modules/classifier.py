"""MODULE 4 - AI INTENT CLASSIFIER"""

import json
import urllib.request
import urllib.error
import sys as _sys, os as _os

_key_path = _os.path.dirname(_os.path.dirname(__file__))
if _key_path not in _sys.path:
    _sys.path.insert(0, _key_path)
from config.settings import DEEPSEEK_API_KEY
del _key_path, _sys, _os


def classify_attacker(session: dict) -> dict:
    """
    Takes a session summary dict and returns AI classification.
    """
    if not DEEPSEEK_API_KEY:
        return {"error": "No API key set"}

    prompt = f'''
You are a cybersecurity threat analyst.
Analyze this attacker session and respond ONLY in JSON.

Session data:
- IP: {session.get("ip")}
- Probe count: {session.get("probe_count")}
- Ports probed: {session.get("ports")}
- Behavioral fingerprint: {session.get("fingerprint")}

Respond with EXACTLY this JSON format (no markdown, no backticks):
{{
    "attacker_type": "automated_scanner|human_hacker|botnet|script_kiddie",
    "likely_tool": "name of tool they are probably using",
    "objective": "what they are trying to achieve",
    "skill_level": "low|medium|high|nation_state",
    "next_moves": ["predicted move 1", "predicted move 2", "predicted move 3"],
    "recommended_deception": "what fake response would waste most of their time"
}}
'''

    payload = json.dumps({
        "model": "deepseek-chat",
        "max_tokens": 500,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.deepseek.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw = data["choices"][0]["message"]["content"]
            clean = raw.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
    except urllib.error.URLError as e:
        return {"error": f"API request failed: {e}"}
    except (json.JSONDecodeError, KeyError):
        return {"error": "Could not parse AI response"}
