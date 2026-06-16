"""
MODULE 2 — SLOW POISON
Adds artificial delay to responses for flagged IPs.
Runs entirely on your own server. Never touches attacker machines.
"""

import time
import asyncio
from core.detector import is_suspicious

BASE_DELAY    = 2.5   # seconds added for suspicious IPs
JITTER_MAX    = 1.0   # random extra delay so it looks natural


def slow_poison_delay(ip: str):
    """Synchronous version — call inside normal request handlers."""
    if is_suspicious(ip):
        import random
        delay = BASE_DELAY + random.uniform(0, JITTER_MAX)
        time.sleep(delay)


async def slow_poison_delay_async(ip: str):
    """Async version — call inside async request handlers."""
    if is_suspicious(ip):
        import random
        delay = BASE_DELAY + random.uniform(0, JITTER_MAX)
        await asyncio.sleep(delay)
