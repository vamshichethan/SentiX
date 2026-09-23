"""
SentiX Database Module (SQLite)
Manages Alerts, Containment Ledger, Multi-Agent Mesh Telemetry, and Incident Dossiers.
"""

import sqlite3
import json
import datetime
from typing import List, Dict, Any, Optional
from backend.config import DB_PATH


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
    if not cursor.fetchone():
        init_db()
    else:
        conn.close()



def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Alerts table (Slide 11 Live Alert Stream & Investigation Dossier)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        src_ip TEXT,
        dest_ip TEXT,
        asset TEXT,
        mitre_technique TEXT,
        status TEXT DEFAULT 'ACTIVE',
        details_json TEXT,
        if_score REAL DEFAULT 0.0,
        ae_score REAL DEFAULT 0.0,
        confidence INTEGER DEFAULT 95,
        vt_score TEXT DEFAULT '8/72',
        abuse_score TEXT DEFAULT '34% (Suspicious)',
        otx_matches INTEGER DEFAULT 14
    )
    """)

    # Containment Ledger table (Slide 13 Action History - Containment Ledger)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS containment_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        severity TEXT NOT NULL,
        mode TEXT NOT NULL,
        executed_by TEXT NOT NULL,
        status TEXT DEFAULT 'COMPLETED'
    )
    """)

    # Autonomous Agent Mesh Pipeline (Slide 13)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_mesh (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        load_pct INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        last_heartbeat TEXT NOT NULL
    )
    """)

    # Correlation Incidents table (Fig 6 Cross-Context Recommendation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correlation_incidents (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        title TEXT NOT NULL,
        agents_involved TEXT NOT NULL,
        correlation_confidence INTEGER NOT NULL,
        narrative TEXT NOT NULL,
        recommended_actions TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN'
    )
    """)

    conn.commit()
    seed_initial_data(conn)
    conn.close()


def seed_initial_data(conn):
    cursor = conn.cursor()

    # 1. Seed 12 Autonomous Agents exactly matching Slide 13
    agents_data = [
        ("01", "Aegis-Guard-01", "Perimeter IDS & Packet Inspection", "ONLINE", 42, 12),
        ("02", "ShieldNet-02", "WAF & API Gateway Sentinel", "ONLINE", 68, 8),
        ("03", "Chronos-Mesh-03", "Behavioral Anomaly Detector", "ACTIVE", 89, 15),
        ("04", "Spectre-Intel-04", "Threat Intelligence Feeds Scraper", "ONLINE", 31, 24),
        ("05", "Cerberus-Core-05", "Host EDR & Memory Forensics", "ACTIVE", 94, 5),
        ("06", "Kube-Shield-06", "Container & Service Mesh Guard", "ONLINE", 55, 11),
        ("07", "Vortex-Stream-07", "Real-time Log Aggregator & Parser", "ONLINE", 76, 9),
        ("08", "Phalanx-Zero-08", "Zero-Day Heuristic Sandbox", "ACTIVE", 91, 19),
        ("09", "Sentinel-AI-09", "LLM Dossier & Root Cause Engine", "ONLINE", 82, 14),
        ("10", "Auto-Contain-10", "Autonomous Firewall & Isolation Enforcer", "READY", 22, 4),
        ("11", "Crypton-Guard-11", "Data Exfiltration DLP Monitor", "ONLINE", 48, 16),
        ("12", "Omega-Master-12", "Global Mesh Coordinator & Consensus", "ONLINE", 60, 7),
    ]

    now_iso = datetime.datetime.utcnow().isoformat() + "Z"
    for agent_id, name, role, status, load_pct, latency_ms in agents_data:
        cursor.execute("""
        INSERT OR REPLACE INTO agent_mesh (id, name, role, status, load_pct, latency_ms, last_heartbeat)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (agent_id, name, role, status, load_pct, latency_ms, now_iso))

    # 2. Seed Initial Alerts matching Slide 11
    cursor.execute("SELECT COUNT(*) FROM alerts")
    if cursor.fetchone()[0] == 0:
        seed_alerts = [
            (
                "3be282e8-2d03-4882-b589-fe2785f071e0",
                "1m ago",
                "Mass S3 object enumeration by dormant access key",
                "CLOUD_SECURITY",
                "CRITICAL",
                89,
                "203.175.188.1",
                "10.0.4.10",
                "10.0.4.10 (Core-DB)",
                "Privilege Escalation / Enumeration",
                "ACTIVE",
                json.dumps({
                    "evidence": "Access key AKIA999DORMANT performed 1,420 GetObject calls in 45s.",
                    "mitre_id": "T1078.004",
                    "cve": "CVE-2024-4288",
                    "tactics": ["Defense Evasion", "Discovery"]
                }),
                87.5,
                82.0,
                98,
                "12/72",
                "78% (Malicious)",
                22
            ),
            (
                "e1518b91-630e-48b1-b599-3e917523089b",
                "1m ago",
                "Zero-day RCE buffer overflow on edge API gateway",
                "NETWORK",
                "LOW",
                68,
                "203.175.188.1",
                "10.0.4.10",
                "10.0.4.10 (Edge-GW)",
                "Initial Access / Exploit Public-Facing App",
                "ACTIVE",
                json.dumps({
                    "evidence": "Payload matched heap overflow canary pattern on port 8443.",
                    "mitre_id": "T1190",
                    "cve": "CVE-2025-2198",
                    "tactics": ["Initial Access"]
                }),
                64.0,
                58.0,
                91,
                "4/72",
                "22% (Low Risk)",
                5
            ),
            (
                "0ae0f1da-7f59-4e0a-a394-3bb7c56155f6",
                "1m ago",
                "Kerberoasting - mass TGS-REQ with RC4 encryption",
                "IDENTITY",
                "CRITICAL",
                77,
                "103.224.182.9",
                "10.0.4.10",
                "10.0.4.10 (Core-DB)",
                "Privilege Escalation",
                "ACTIVE",
                json.dumps({
                    "evidence": "12 service principal names requested with downgrade to RC4-HMAC cipher.",
                    "mitre_id": "T1558.003",
                    "cve": "CVE-2024-38077",
                    "tactics": ["Credential Access"]
                }),
                87.0,
                79.0,
                99,
                "8/72",
                "34% (Suspicious)",
                14
            ),
            (
                "4c8e43c7-5d78-4bf8-888e-56f956068f9f",
                "2m ago",
                "Phishing lure delivery with obfuscated reverse shell URL",
                "EMAIL_THREAT",
                "CRITICAL",
                84,
                "185.220.101.5",
                "10.0.2.14",
                "10.0.2.14 (Workstation-HR)",
                "Phishing: Spearphishing Attachment",
                "ACTIVE",
                json.dumps({
                    "evidence": "Email subject 'Urgent Payroll Invoice' containing malicious domain 'pay-support-portal.net'.",
                    "mitre_id": "T1566.002",
                    "cve": "N/A",
                    "tactics": ["Initial Access"]
                }),
                89.0,
                85.0,
                97,
                "26/72",
                "88% (High Threat)",
                31
            ),
            (
                "7a9b0c1d-1122-3344-5566-778899aabbcc",
                "4m ago",
                "High frequency SYN flood targeting production authentication endpoint",
                "NETWORK",
                "HIGH",
                72,
                "45.154.255.88",
                "10.0.1.5",
                "10.0.1.5 (Auth-Server)",
                "Denial of Service / Network DoS",
                "ACTIVE",
                json.dumps({
                    "evidence": "22,000 SYN packets/sec with spoofed window sizes on port 443.",
                    "mitre_id": "T1498.001",
                    "cve": "N/A",
                    "tactics": ["Impact"]
                }),
                74.0,
                68.0,
                94,
                "15/72",
                "61% (Malicious)",
                18
            )
        ]

        cursor.executemany("""
        INSERT INTO alerts (
            id, timestamp, title, category, severity, risk_score, src_ip, dest_ip,
            asset, mitre_technique, status, details_json, if_score, ae_score,
            confidence, vt_score, abuse_score, otx_matches
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_alerts)

    # 3. Seed Containment Ledger matching Slide 13
    cursor.execute("SELECT COUNT(*) FROM containment_ledger")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO containment_ledger (timestamp, action, target, severity, mode, executed_by, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "2026-08-07 18:35:18",
            "BLOCK_IP",
            "185.220.101.5",
            "CRITICAL",
            "AUTO",
            "Auto-Contain-10",
            "COMPLETED"
        ))

    conn.commit()


def get_all_alerts(limit: int = 50, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if severity_filter and severity_filter.upper() != "ALL":
        cursor.execute("SELECT * FROM alerts WHERE UPPER(severity) = ? ORDER BY risk_score DESC LIMIT ?",
                       (severity_filter.upper(), limit))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY risk_score DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def insert_alert(alert: Dict[str, Any]) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO alerts (
        id, timestamp, title, category, severity, risk_score, src_ip, dest_ip,
        asset, mitre_technique, status, details_json, if_score, ae_score,
        confidence, vt_score, abuse_score, otx_matches
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["id"],
        alert.get("timestamp", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        alert["title"],
        alert.get("category", "SECURITY_ALERT"),
        alert.get("severity", "HIGH"),
        alert.get("risk_score", 75),
        alert.get("src_ip", "0.0.0.0"),
        alert.get("dest_ip", "10.0.4.10"),
        alert.get("asset", "Internal Asset"),
        alert.get("mitre_technique", "Unknown Technique"),
        alert.get("status", "ACTIVE"),
        json.dumps(alert.get("details", {})),
        alert.get("if_score", 70.0),
        alert.get("ae_score", 65.0),
        alert.get("confidence", 95),
        alert.get("vt_score", "10/72"),
        alert.get("abuse_score", "45% (Suspicious)"),
        alert.get("otx_matches", 12)
    ))
    conn.commit()
    conn.close()
    return alert["id"]


def get_agent_mesh() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agent_mesh ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_containment_ledger(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM containment_ledger ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_containment_action(action: str, target: str, severity: str, mode: str, executed_by: str) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO containment_ledger (timestamp, action, target, severity, mode, executed_by, status)
    VALUES (?, ?, ?, ?, ?, ?, 'COMPLETED')
    """, (ts, action, target, severity, mode, executed_by))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical_count = cursor.fetchone()[0] or 212

    cursor.execute("SELECT COUNT(*) FROM containment_ledger")
    contained_count = cursor.fetchone()[0] or 42

    cursor.execute("SELECT AVG(risk_score) FROM alerts")
    mean_risk = int(round(cursor.fetchone()[0] or 78))

    conn.close()
    return {
        "critical_incidents": critical_count,
        "auto_contained": contained_count,
        "mean_risk_score": mean_risk,
        "mean_time_to_respond": "41s",
        "defcon_level": 2,
        "events_processed_today": 18513
    }


# Ensure tables exist on module load
ensure_db()

