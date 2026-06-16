"""
MODULE 6 — INFINITE RABBIT HOLE ENGINE
"""

import json
import hashlib
import urllib.request
from datetime import datetime

DEEPSEEK_API_KEY = ""  # set from settings.py at runtime

# Import logger — lazy to avoid circular import
def _log(ip, fingerprint, depth, action, fake_system, credential_tried=""):
    try:
        from modules.dna_db import log_rabbit_action
        log_rabbit_action(ip, fingerprint, depth, action, fake_system, credential_tried)
    except Exception:
        pass


MAX_AI_LAYERS_PER_DAY = 10

def generate_fake_layer(attacker_ip: str, depth: int, context: str = "",
                        fingerprint: str = "", probe_count: int = 0) -> dict:
    """
    Generate a believable fake system layer and log the attacker's step.
    depth = how deep into the rabbit hole the attacker is.
    """
    from modules.dna_db import get_rabbit_depth, get_cached_layer

    # Bot detection: shallow probe, no real interaction -> static only
    if probe_count < 3 and depth == 1:
        return _static_fallback(depth)

    # Rate limit: cap AI calls at MAX_AI_LAYERS_PER_DAY per IP
    used_today = get_rabbit_depth(attacker_ip)
    if used_today >= MAX_AI_LAYERS_PER_DAY:
        cached = get_cached_layer(attacker_ip, depth)
        if cached:
            return cached
        return _static_fallback(depth)

    if not DEEPSEEK_API_KEY:
        layer = _static_fallback(depth)
    else:
        prompt = f"""
You are generating fake cybersecurity honeypot content.
This is a DEFENSIVE security tool running on the server owner's own infrastructure.

Generate a fake internal system that an attacker would find at depth level {depth}.
Make it believable but completely fictional.
Context from previous layer: {context or 'none'}

Respond ONLY in JSON, no other text:
{{
    "system_name": "believable internal system name",
    "ip": "fake internal IP like 10.x.x.x",
    "os": "operating system",
    "open_services": [
        {{"port": 0000, "service": "name", "version": "x.x", "banner": "fake banner text"}}
    ],
    "fake_credentials": [
        {{"username": "fake_user", "password": "fake_pass123", "service": "ssh"}}
    ],
    "fake_files": [
        {{"path": "/path/to/file", "description": "what this fake file pretends to be"}}
    ],
    "next_hint": "subtle clue that leads attacker deeper into next fake layer",
    "depth": {depth}
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
                layer = json.loads(clean)
        except Exception:
            layer = _static_fallback(depth)

    # ── Log this step ──────────────────────────────────────────────────────────
    cred = ""
    if layer.get("fake_credentials"):
        c = layer["fake_credentials"][0]
        cred = f"{c.get('username','')} / {c.get('password','')}"

    _log(
        ip=attacker_ip,
        fingerprint=fingerprint,
        depth=depth,
        action=f"reached depth {depth}",
        fake_system=layer.get("system_name", "unknown"),
        credential_tried=cred,
    )

    return layer


def _static_fallback(depth: int) -> dict:
    """Fallback when DeepSeek API is unavailable."""
    names = [
        "DC-Core-01", "NAS-Backup-02", "HR-Portal", "GitLab-Internal",
        "Mail-Relay-03", "DB-Prod-Admin", "VPN-Gateway", "ACS-Controller"
    ]
    idx = depth % len(names)
    return {
        "system_name": f"{names[idx]}-L{str(depth).zfill(2)}",
        "ip": f"10.{ depth % 256}.{(depth*7) % 256}.{(depth*13) % 256}",
        "os": "Linux 5.15.0-generic x86_64",
        "open_services": [
            {"port": 22, "service": "SSH", "version": "OpenSSH_8.2p1", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
            {"port": 80, "service": "HTTP", "version": "Apache/2.4.41", "banner": "Apache/2.4.41 (Ubuntu)"},
        ],
        "fake_credentials": [
            {"username": f"svc_{names[idx].lower()}", "password": "P@ssw0rd2024!", "service": "ssh"}
        ],
        "fake_files": [
            {"path": "/etc/hosts", "description": "Internal host mappings"},
            {"path": "/opt/backup/credentials.txt", "description": "Service account passwords backup"}
        ],
        "next_hint": f"Try connecting to {names[(idx+1)%len(names)]} with default credentials",
        "depth": depth
    }
