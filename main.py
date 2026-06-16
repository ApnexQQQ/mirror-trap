"""
LIAR'S ECHO — REAL HONEYPOT
Listens on actual ports, accepts real connections,
logs attacker IPs, triggers Telegram alerts, saves to SQLite.

Run with:
    sudo python3 main.py

(sudo needed to bind ports 22, 80, 443)
"""

import socket
import threading
import time
import logging
import os, sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.detector             import record_probe, summarize_session, all_flagged
from modules.classifier        import classify_attacker
from modules.alerting          import send_alert
from modules.dna_db            import init_db, init_rabbit_log, init_fingerprint_db, save_session, find_by_fingerprint
from modules.fake_topology     import generate_fake_hosts, get_fake_banner
from modules.rabbit_hole       import generate_fake_layer
from modules.adversarial_noise import add_noise_to_port_response
from modules.self_learning     import learn_from_session
from modules.slow_poison       import slow_poison_delay

import config.settings as cfg
import modules.classifier  as classifier_mod
import modules.alerting    as alerting_mod
import modules.rabbit_hole as rh_mod
import modules.self_learning as sl_mod

classifier_mod.DEEPSEEK_API_KEY = cfg.DEEPSEEK_API_KEY
alerting_mod.TELEGRAM_BOT_TOKEN = cfg.TELEGRAM_BOT_TOKEN
alerting_mod.TELEGRAM_CHAT_ID   = cfg.TELEGRAM_CHAT_ID
rh_mod.DEEPSEEK_API_KEY         = cfg.DEEPSEEK_API_KEY
sl_mod.DEEPSEEK_API_KEY         = cfg.DEEPSEEK_API_KEY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/home/liarsecho/logs/honeypot.log")
    ]
)
log = logging.getLogger("liars_echo")

# ============================================
# FAKE BANNERS per port
# ============================================
BANNERS = {
    22:   b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    80:   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome</h1></body></html>",
    443:  b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body></body></html>",
    3306: b"\x4a\x00\x00\x00\x0a5.7.38-MySQL\x00",
    5432: b"R\x00\x00\x00\x08\x00\x00\x00\x00",
    6379: b"+PONG\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n",
    8443: b"HTTP/1.1 200 OK\r\nServer: Tomcat/9.0.56\r\n\r\n",
}

PORTS = cfg.MONITORED_PORTS

already_processed = set()  # still used to avoid duplicate pipeline runs in same session
processed_lock    = threading.Lock()


def classification_backfill():
    """
    Background thread — runs every 30 seconds.
    Finds any sessions still marked unknown and runs AI classifier on them.
    Fixes cases where classifier failed or was skipped.
    """
    from modules.dna_db import get_unclassified_sessions, update_classification
    import json

    while True:
        try:
            unclassified = get_unclassified_sessions()
            if unclassified:
                log.info(f"[BACKFILL] Found {len(unclassified)} unclassified sessions")
                for row in unclassified:
                    ip, fingerprint, ports_json, probe_count, first_seen, last_seen = row
                    try:
                        ports = json.loads(ports_json) if ports_json else []
                    except Exception:
                        ports = []

                    session = {
                        "ip":          ip,
                        "fingerprint": fingerprint,
                        "ports":       ports,
                        "probe_count": probe_count,
                        "first_seen":  first_seen,
                        "last_seen":   last_seen,
                    }
                    try:
                        classification = classify_attacker(session)
                        if classification and "error" not in classification:
                            update_classification(
                                ip,
                                classification.get("attacker_type", "unknown"),
                                classification.get("skill_level",   "unknown"),
                                classification.get("objective",     "unknown"),
                                classification.get("likely_tool",   "unknown"),
                            )
                            log.info(f"[BACKFILL] Classified {ip} → {classification.get('attacker_type','?')}")
                    except Exception as e:
                        log.error(f"[BACKFILL] Failed to classify {ip}: {e}")
        except Exception as e:
            log.error(f"[BACKFILL] Error: {e}")

        time.sleep(30)


def run_pipeline(ip: str, port: int):
    with processed_lock:
        if ip in already_processed:
            return
        already_processed.add(ip)

    log.info(f"[PIPELINE] Starting full analysis for {ip}")

    try:
        session = summarize_session(ip)

        fp = session.get("fingerprint", "")
        if fp:
            previous = find_by_fingerprint(fp)
            if previous:
                log.warning(f"[DNA MATCH] {ip} matches {len(previous)} previous session(s)")

        log.info(f"[AI] Classifying {ip}...")
        classification = classify_attacker(session)
        log.info(f"[AI] {ip} type={classification.get('attacker_type','?')} tool={classification.get('likely_tool','?')}")

        fake_hosts = generate_fake_hosts(seed=ip, count=4)
        log.info(f"[TOPOLOGY] {len(fake_hosts)} fake hosts ready for {ip}")

        rabbit = generate_fake_layer(attacker_ip=ip, depth=max(1, session.get("probe_count", 1) // 3), probe_count=session.get("probe_count", 0), attacker_type=session.get("attacker_type", "unknown"))
        log.info(f"[RABBIT] Layer 1 ready: {rabbit.get('system_name','?')}")

        new_traps = learn_from_session(session, classification)
        log.info(f"[LEARN] New traps: {new_traps.get('trap_positions', [])}")

        save_session(session, classification)
        log.info(f"[DB] Session saved for {ip}")

        send_alert(session, classification)
        log.info(f"[ALERT] Telegram sent for {ip}")

    except Exception as e:
        log.error(f"[PIPELINE ERROR] {ip}: {e}")


def handle_connection(conn: socket.socket, addr: tuple, port: int):
    ip = addr[0]
    log.info(f"[PROBE] {ip}:{addr[1]} -> port {port}")

    try:
        conn.settimeout(10)

        # Slow poison for known bad IPs
        slow_poison_delay(ip)

        # Send fake banner with adversarial noise applied
        banner = BANNERS.get(port, b"220 Service Ready\r\n")
        try:
            noisy  = add_noise_to_port_response(ip, port, banner.decode("utf-8", errors="ignore"))
            banner = noisy.encode("utf-8")
        except Exception:
            pass

        conn.sendall(banner)

        # Read attacker tool signature
        try:
            data = conn.recv(1024)
            if data:
                log.info(f"[DATA] {ip} sent on port {port}: {data[:80]!r}")
        except socket.timeout:
            pass

        # HTTP ports — serve rabbit hole page
        if port in [80, 443, 8080, 8443]:
            try:
                rabbit    = generate_fake_layer(attacker_ip=ip, depth=max(1, session.get("probe_count", 1) // 3), probe_count=session.get("probe_count", 0), attacker_type=session.get("attacker_type", "unknown"))
                fake_body = (
                    "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
                    f"<html><body>"
                    f"<h2>Internal — {rabbit.get('system_name','server')}</h2>"
                    f"<p>Host: {rabbit.get('ip','10.0.0.1')}</p>"
                    f"</body></html>"
                ).encode()
                conn.sendall(fake_body)
            except Exception:
                pass

    except Exception as e:
        log.debug(f"[CONN] {ip} port {port}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Record probe — triggers pipeline if threshold reached
    newly_flagged = record_probe(ip, port)
    if newly_flagged:
        t = threading.Thread(target=run_pipeline, args=(ip, port), daemon=True)
        t.start()


def start_listener(port: int):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(50)
        log.info(f"[LISTEN] Port {port} open")

        while True:
            try:
                conn, addr = server.accept()
                t = threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, port),
                    daemon=True
                )
                t.start()
            except Exception as e:
                log.error(f"[LISTEN ERROR] Port {port}: {e}")
                time.sleep(1)

    except PermissionError:
        log.error(f"[ERROR] Port {port} — run with: sudo python3 main.py")
    except OSError as e:
        log.error(f"[ERROR] Port {port} already in use: {e}")


def status_reporter():
    while True:
        time.sleep(60)
        flagged = all_flagged()
        log.info(f"[STATUS] Flagged: {len(flagged)} attackers | Ports: {len(PORTS)} active")
        for a in flagged[-5:]:
            log.info(f"  -> {a['ip']} probes={a['probe_count']} ports={a['ports']} fp={a['fingerprint']}")


def main():
    log.info("=" * 55)
    log.info("  LIAR'S ECHO — REAL HONEYPOT STARTING")
    log.info("=" * 55)

    init_db()
    init_rabbit_log()
    init_fingerprint_db()
    import modules.fingerprint_engine as fp_engine
    fp_engine.DEEPSEEK_API_KEY = cfg.DEEPSEEK_API_KEY
    fp_engine.DEPLOYMENT_ID    = 'default'
    log.info("[DB] Database ready")

    if os.geteuid() != 0:
        log.warning("[WARN] Not root — ports 22/80/443 need: sudo python3 main.py")

    # Start classification backfill thread
    bf = threading.Thread(target=classification_backfill, daemon=True)
    bf.start()
    log.info("[BACKFILL] Classification backfill thread started")

    for port in PORTS:
        t = threading.Thread(target=start_listener, args=(port,), daemon=True)
        t.start()
        time.sleep(0.1)

    log.info(f"[READY] Listening on ports: {PORTS}")
    log.info("[READY] Dashboard: python3 dashboard/app.py -> http://localhost:5000")
    log.info("[READY] Ctrl+C to stop")

    sr = threading.Thread(target=status_reporter, daemon=True)
    sr.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("\n[STOP] Shutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
