import json, hashlib, urllib.request
from datetime import datetime

DEEPSEEK_API_KEY=""
DEPLOYMENT_ID    = ""

def build_fingerprint_hash(ports: list, credentials: list, depth: int) -> str:
    normalized = {
        "ports":       sorted(ports),
        "cred_count":  len(credentials),
        "depth_band":  (depth // 3) * 3,
        "cred_sample": sorted(credentials)[:3]
    }
    raw = json.dumps(normalized, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def analyze_fingerprint(record: dict, session: dict) -> dict:
    if not DEEPSEEK_API_KEY:
        return _static_analysis(record)
    prompt = f'''You are a cybersecurity threat analyst.
Analyze this attacker fingerprint and respond ONLY in JSON:
{{
    "threat_level": "low|medium|high|critical",
    "likely_toolset": "specific tools",
    "attacker_type": "bot|script kiddie|manual operator|apt",
    "behavior_summary": "2 sentences max",
    "recommended_action": "monitor|alert team|block|escalate"
}}
Data: deployments={record.get("deployment_count",1)}, ports={record.get("target_ports","?")}, depth={session.get("depth",1)}, creds={record.get("credential_patterns","?")}'''
    payload = json.dumps({"model":"deepseek-chat","max_tokens":200,"messages":[{"role":"user","content":prompt}]}).encode()
    req = urllib.request.Request("https://api.deepseek.com/v1/chat/completions", data=payload,
        headers={"Content-Type":"application/json","Authorization":f"Bearer {DEEPSEEK_API_KEY}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            raw = data["choices"][0]["message"]["content"]
            return json.loads(raw.replace("```json","").replace("```","").strip())
    except Exception:
        return _static_analysis(record)

def process_session(ip: str, ports: list, credentials: list, depth: int) -> dict:
    from modules.dna_db import save_fingerprint, get_fingerprint
    hash_id  = build_fingerprint_hash(ports, credentials, depth)
    existing = get_fingerprint(hash_id)
    is_known = bool(existing)
    record   = save_fingerprint(hash_id, ip, DEPLOYMENT_ID or "default", depth, credentials, ports)
    if is_known or depth > 3:
        analysis = analyze_fingerprint(record, {"depth": depth})
        try:
            import sqlite3
            from modules.dna_db import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            conn.execute("UPDATE attacker_fingerprints SET threat_level=?,likely_toolset=?,behavior_summary=? WHERE fingerprint_hash=?",
                (analysis.get("threat_level","unknown"), analysis.get("likely_toolset",""), analysis.get("behavior_summary",""), hash_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
        record.update(analysis)
    record["is_known"]       = is_known
    record["fingerprint_id"] = hash_id
    return record

def _static_analysis(record: dict) -> dict:
    count = record.get("deployment_count", 1)
    return {
        "threat_level":       "high" if count > 3 else "medium" if count > 1 else "low",
        "likely_toolset":     "unknown",
        "attacker_type":      "unknown",
        "behavior_summary":   f"Seen across {count} deployment(s).",
        "recommended_action": "alert team" if count > 3 else "monitor"
    }
