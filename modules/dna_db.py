"""
MODULE 5 — ATTACKER DNA DATABASE
PostgreSQL version — drop-in replacement for the SQLite version.
"""

import os, json, psycopg2, psycopg2.extras
from datetime import datetime

DB_URL = os.environ.get("DATABASE_URL", "postgresql://liarsecho:LiarEcho2026x@localhost:5432/liarsecho")

def _conn():
    return psycopg2.connect(DB_URL)


def init_db():
    conn = _conn(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id            SERIAL PRIMARY KEY,
            ip            TEXT,
            fingerprint   TEXT,
            ports         TEXT,
            probe_count   INTEGER,
            attacker_type TEXT,
            skill_level   TEXT,
            objective     TEXT,
            likely_tool   TEXT,
            first_seen    TEXT,
            last_seen     TEXT
        )
    """)
    conn.commit(); conn.close()


def init_rabbit_log():
    conn = _conn(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS rabbit_hole_sessions (
            id               SERIAL PRIMARY KEY,
            attacker_ip      TEXT,
            fingerprint      TEXT,
            depth            INTEGER,
            action           TEXT,
            fake_system      TEXT,
            credential_tried TEXT,
            timestamp        TEXT
        )
    """)
    conn.commit(); conn.close()


def init_fingerprint_db():
    conn = _conn(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS attacker_fingerprints (
            id                SERIAL PRIMARY KEY,
            fingerprint_hash  TEXT UNIQUE,
            first_seen        TEXT,
            last_seen         TEXT,
            deployment_count  INTEGER DEFAULT 1,
            total_sessions    INTEGER DEFAULT 1,
            likely_toolset    TEXT,
            target_ports      TEXT,
            threat_level      TEXT DEFAULT 'unknown',
            credential_patterns TEXT,
            behavior_summary  TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS fingerprint_sightings (
            id               SERIAL PRIMARY KEY,
            fingerprint_hash TEXT,
            attacker_ip      TEXT,
            deployment_id    TEXT,
            depth_reached    INTEGER,
            credentials_used TEXT,
            ports_tried      TEXT,
            timestamp        TEXT
        )
    """)
    conn.commit(); conn.close()


def save_session(session: dict, classification: dict = {}):
    conn = _conn(); c = conn.cursor()
    c.execute("""
        INSERT INTO sessions
        (ip, fingerprint, ports, probe_count,
         attacker_type, skill_level, objective, likely_tool,
         first_seen, last_seen)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        session.get("ip", ""),
        session.get("fingerprint", ""),
        json.dumps(session.get("ports", [])),
        session.get("probe_count", 0),
        classification.get("attacker_type", "unknown"),
        classification.get("skill_level", "unknown"),
        classification.get("objective", "unknown"),
        classification.get("likely_tool", "unknown"),
        session.get("first_seen", datetime.utcnow().isoformat()),
        session.get("last_seen", datetime.utcnow().isoformat()),
    ))
    conn.commit(); conn.close()


def find_by_fingerprint(fingerprint: str) -> list:
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE fingerprint=%s ORDER BY last_seen DESC", (fingerprint,))
    rows = c.fetchall(); conn.close()
    return rows


def get_all_attackers() -> list:
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT ip, fingerprint, attacker_type, skill_level, objective, likely_tool, last_seen FROM sessions ORDER BY last_seen DESC")
    rows = c.fetchall(); conn.close()
    return rows


def get_unclassified_sessions() -> list:
    conn = _conn(); c = conn.cursor()
    c.execute("""
        SELECT ip, fingerprint, ports, probe_count, first_seen, last_seen
        FROM sessions
        WHERE attacker_type = 'unknown' OR attacker_type IS NULL
        ORDER BY last_seen DESC
    """)
    rows = c.fetchall(); conn.close()
    return rows


def update_classification(ip: str, attacker_type: str, skill_level: str,
                          objective: str, likely_tool: str):
    conn = _conn(); c = conn.cursor()
    c.execute("""
        UPDATE sessions
        SET attacker_type=%s, skill_level=%s, objective=%s, likely_tool=%s
        WHERE ip=%s
    """, (attacker_type, skill_level, objective, likely_tool, ip))
    conn.commit(); conn.close()


def log_rabbit_action(ip: str, fingerprint: str, depth: int,
                      action: str, fake_system: str, credential_tried: str = ""):
    conn = _conn()
    conn.cursor().execute("""
        INSERT INTO rabbit_hole_sessions
        (attacker_ip, fingerprint, depth, action, fake_system, credential_tried, timestamp)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (ip, fingerprint, depth, action, fake_system,
          credential_tried, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()


def get_rabbit_sessions(ip: str = None) -> list:
    conn = _conn()
    conn.cursor
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if ip:
        c.execute("SELECT * FROM rabbit_hole_sessions WHERE attacker_ip=%s ORDER BY timestamp DESC LIMIT 50", (ip,))
    else:
        c.execute("SELECT * FROM rabbit_hole_sessions ORDER BY timestamp DESC LIMIT 50")
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_rabbit_depth(ip: str) -> int:
    conn = _conn(); c = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM rabbit_hole_sessions
        WHERE attacker_ip = %s
        AND timestamp >= (NOW() AT TIME ZONE 'UTC' - INTERVAL '24 hours')::TEXT
    """, (ip,))
    count = c.fetchone()[0]; conn.close()
    return count


def get_cached_layer(ip: str, depth: int) -> dict:
    conn = _conn()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    c.execute("""
        SELECT fake_system FROM rabbit_hole_sessions
        WHERE attacker_ip = %s AND depth = %s
        ORDER BY timestamp DESC LIMIT 1
    """, (ip, depth))
    row = c.fetchone(); conn.close()
    if row:
        return {"system_name": row["fake_system"], "cached": True}
    return {}


def save_fingerprint(fingerprint_hash, ip, deployment_id, depth, credentials, ports):
    conn = _conn()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    now = datetime.utcnow().isoformat()
    c.execute("""
        INSERT INTO fingerprint_sightings
        (fingerprint_hash,attacker_ip,deployment_id,depth_reached,credentials_used,ports_tried,timestamp)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (fingerprint_hash, ip, deployment_id, depth,
          ','.join(credentials), ','.join(str(p) for p in ports), now))
    c.execute("SELECT * FROM attacker_fingerprints WHERE fingerprint_hash=%s", (fingerprint_hash,))
    existing = c.fetchone()
    if existing:
        c.execute("""
            UPDATE attacker_fingerprints
            SET last_seen=%s, total_sessions=total_sessions+1, deployment_count=deployment_count+1
            WHERE fingerprint_hash=%s
        """, (now, fingerprint_hash))
    else:
        c.execute("""
            INSERT INTO attacker_fingerprints
            (fingerprint_hash,first_seen,last_seen,deployment_count,total_sessions,target_ports,credential_patterns)
            VALUES (%s,%s,%s,1,1,%s,%s)
        """, (fingerprint_hash, now, now,
              ','.join(str(p) for p in ports), ','.join(credentials)))
    conn.commit()
    c.execute("SELECT * FROM attacker_fingerprints WHERE fingerprint_hash=%s", (fingerprint_hash,))
    record = c.fetchone(); conn.close()
    return dict(record) if record else {}


def get_fingerprint(fingerprint_hash):
    conn = _conn()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    c.execute("SELECT * FROM attacker_fingerprints WHERE fingerprint_hash=%s", (fingerprint_hash,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else {}


def get_all_fingerprints():
    conn = _conn()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    c.execute("SELECT * FROM attacker_fingerprints ORDER BY deployment_count DESC, last_seen DESC LIMIT 100")
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows
