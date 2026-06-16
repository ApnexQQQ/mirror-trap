"""
MODULE 1 — SESSION DETECTOR
Watches who connects to your server and flags suspicious behavior.
"""

import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime

logging.basicConfig(
    filename="/home/liarsecho/logs/honeypot.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# In-memory session store: { ip: session_data }
sessions = defaultdict(lambda: {
    "ports":      [],
    "times":      [],
    "count":      0,
    "flagged":    False,
    "first_seen": datetime.utcnow().isoformat(),
    "last_seen":  datetime.utcnow().isoformat(),
})

SUSPICION_THRESHOLD = 2


def record_probe(ip: str, port: int) -> bool:
    """
    Record a connection probe from an IP.
    Returns True if this IP just became suspicious.
    """
    # Whitelist check — never flag trusted IPs
    try:
        from config.settings import WHITELIST_IPS
        if ip in WHITELIST_IPS:
            return False
    except ImportError:
        pass

    s = sessions[ip]
    s["ports"].append(port)
    s["times"].append(time.time())
    s["count"] += 1
    s["last_seen"] = datetime.utcnow().isoformat()

    if s["count"] >= SUSPICION_THRESHOLD and not s["flagged"]:
        s["flagged"] = True
        logging.warning(
            f"ATTACKER FLAGGED: {ip} | "
            f"probes={s['count']} | ports={s['ports']}"
        )
        return True

    return s["flagged"]


def is_suspicious(ip: str) -> bool:
    return sessions[ip]["flagged"]


def build_fingerprint(ip: str) -> str:
    """
    Behavioral hash of probe pattern.
    Same attacker from different IP = same hash if behavior matches.
    """
    s = sessions[ip]
    if not s["ports"]:
        return ""

    gaps = []
    for i in range(1, len(s["times"])):
        gaps.append(round(s["times"][i] - s["times"][i - 1], 1))

    raw = f"{sorted(s['ports'])}:{gaps}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def summarize_session(ip: str) -> dict:
    s = sessions[ip]
    return {
        "ip":          ip,
        "probe_count": s["count"],
        "ports":       list(set(s["ports"])),
        "flagged":     s["flagged"],
        "fingerprint": build_fingerprint(ip),
        "first_seen":  s["first_seen"],
        "last_seen":   s["last_seen"],
    }


def all_flagged() -> list:
    """Return summaries of all flagged IPs."""
    return [
        summarize_session(ip)
        for ip, s in sessions.items()
        if s["flagged"]
    ]
