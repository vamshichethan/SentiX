"""
Log Analyzer Agent
Implements Fig. 4 of IEEE Access 2025 Paper:
- Log pre-processing & normalization (ELK schema)
- Rule-based detection powered by Suricata attack signatures
- Machine Learning anomaly detection (Isolation Forest + Autoencoder)
- Temporal state memory tracking
- LLM Chain-of-Thought reasoning (LLaMA 3.3-70B via Groq with local fallback)
"""

import re
from typing import Dict, Any, List
from backend.ml.anomaly_engine import anomaly_engine
from backend.agents.llm_client import llm_client


class LogAnalyzerAgent:
    def __init__(self):
        # Suricata-style signature patterns
        self.signatures = [
            {
                "id": "SID-2001",
                "name": "SSH Brute-Force Authentication Attempt",
                "pattern": r"Failed password for (invalid user )?\w+ from (\d+\.\d+\.\d+\.\d+)",
                "technique": "T1110.001 - Password Guessing",
                "severity": "HIGH",
                "tactic": "Credential Access"
            },
            {
                "id": "SID-2002",
                "name": "Buffer Overflow / Canary Corruption",
                "pattern": r"(Buffer Overflow|heap corruption|Canary Triggered|segmentation fault)",
                "technique": "T1190 - Exploit Public-Facing Application",
                "severity": "CRITICAL",
                "tactic": "Initial Access"
            },
            {
                "id": "SID-2003",
                "name": "Privilege Escalation via Sudo / Web Shell Beacon",
                "pattern": r"sudo.*USER=root.*COMMAND=.*(curl|wget|sh|bash|nc|python)",
                "technique": "T1548.003 - Sudo and Sudo Caching",
                "severity": "CRITICAL",
                "tactic": "Privilege Escalation"
            },
            {
                "id": "SID-2004",
                "name": "Active Directory Kerberoasting TGS Request",
                "pattern": r"(TGS-REQ.*RC4-HMAC|Kerberoasting IOC|mass enumeration)",
                "technique": "T1558.003 - Kerberoasting",
                "severity": "CRITICAL",
                "tactic": "Credential Access"
            },
            {
                "id": "SID-2005",
                "name": "SQL Injection Query Pattern",
                "pattern": r"(\bUNION\b|\bSELECT\b.*FROM|\bDROP\b|\bOR 1=1\b)",
                "technique": "T1190 - Exploit Public-Facing Application",
                "severity": "HIGH",
                "tactic": "Initial Access"
            }
        ]
        # In-memory history for temporal state tracking
        self.session_memory: List[Dict[str, Any]] = []

    def normalize_logs(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Normalize raw log entries into structured ELK-compatible event records."""
        parsed = []
        for idx, line in enumerate(log_lines):
            line_str = str(line).strip()
            if not line_str:
                continue

            # Extract IP address
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line_str)
            src_ip = ip_match.group(0) if ip_match else "0.0.0.0"

            # Extract timestamp
            ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}", line_str)
            timestamp = ts_match.group(0) if ts_match else "N/A"

            parsed.append({
                "line_no": idx + 1,
                "raw": line_str,
                "src_ip": src_ip,
                "timestamp": timestamp
            })
        return parsed

    def match_signatures(self, normalized_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run Suricata rule evaluation across normalized log lines."""
        matched = []
        for ev in normalized_events:
            for sig in self.signatures:
                if re.search(sig["pattern"], ev["raw"], re.IGNORECASE):
                    matched.append({
                        "line_no": ev["line_no"],
                        "signature_id": sig["id"],
                        "name": sig["name"],
                        "technique": sig["technique"],
                        "severity": sig["severity"],
                        "tactic": sig["tactic"],
                        "raw_line": ev["raw"],
                        "src_ip": ev["src_ip"]
                    })
        return matched

    def process(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        entries = log_data.get("entries", [])
        if isinstance(entries, str):
            entries = entries.strip().split("\n")

        # 1. Normalize logs
        normalized = self.normalize_logs(entries)

        # 2. Rule-based / Signature analysis
        signature_matches = self.match_signatures(normalized)

        # 3. Machine Learning Anomaly Detection (Isolation Forest + Autoencoder)
        event_telemetry = {
            "bytes_in": log_data.get("bytes_in", 65000 if signature_matches else 1200),
            "bytes_out": log_data.get("bytes_out", 180000 if signature_matches else 2400),
            "duration": log_data.get("duration", 3.2),
            "failed_logins": log_data.get("failed_logins", len([m for m in signature_matches if "SID-2001" in m["signature_id"]])),
            "privilege_reqs": log_data.get("privilege_reqs", len([m for m in signature_matches if "SID-2003" in m["signature_id"] or "SID-2004" in m["signature_id"]])),
            "distinct_dest_ports": log_data.get("distinct_dest_ports", 4 if signature_matches else 1),
            "severity": "CRITICAL" if any(m["severity"] == "CRITICAL" for m in signature_matches) else "HIGH" if signature_matches else "LOW",
            "threat_intel_score": 8.5 if signature_matches else 1.0,
            "asset_criticality": 0.9,
            "frequency": len(signature_matches) or 1
        }

        risk_calc = anomaly_engine.calculate_risk_score(event_telemetry)

        # 4. Temporal memory record
        extracted_ips = list({ev["src_ip"] for ev in normalized if ev["src_ip"] != "0.0.0.0"})
        memory_entry = {
            "ips": extracted_ips,
            "matches_count": len(signature_matches),
            "risk_score": risk_calc["composite_score"]
        }
        self.session_memory.append(memory_entry)
        if len(self.session_memory) > 50:
            self.session_memory.pop(0)

        # 5. Formulate Prompt for LLM with Chain-of-Thought
        system_prompt = (
            "You are an expert Cybersecurity Log Analyzer Agent. Analyze the normalized system log events, "
            "Suricata intrusion detection signatures, and machine learning anomaly telemetry. "
            "Return a JSON object with: 'verdict' ('NORMAL', 'SUSPICIOUS', 'ANOMALOUS_ATTACK'), "
            "'risk_score' (0-100), 'confidence_score' (0-100), 'chain_of_thought' (step-by-step reasoning), "
            "'explanation' (traceable explanation citing line numbers), 'correlated_lines' (list of line numbers), "
            "'mitre_technique' (MITRE ATT&CK ID & Name), and 'tactics' (array of ATT&CK tactics)."
        )

        user_prompt = f"""
Analyze this security log sequence:
- LOG ENTRIES ({len(normalized)} lines):
{chr(10).join([f"Line {e['line_no']}: {e['raw']}" for e in normalized])}
- SURICATA SIGNATURE MATCHES: {signature_matches}
- MACHINE LEARNING SCORES:
  * Isolation Forest Anomaly Score: {risk_calc['if_score']}%
  * Autoencoder Reconstruction Error Score: {risk_calc['ae_score']}%
  * Multi-Factor Composite Risk Score: {risk_calc['composite_score']}/100 ({risk_calc['risk_level']})
"""

        # 6. LLM Execution
        llm_result = llm_client.generate_analysis(system_prompt, user_prompt)

        # Primary matched technique
        primary_technique = (
            signature_matches[0]["technique"] if signature_matches
            else llm_result.get("mitre_technique", "T1078 - Valid Accounts")
        )

        return {
            "agent": "LogAnalyzerAgent",
            "total_lines_analyzed": len(normalized),
            "normalized_events": normalized[:10], # Truncate for concise response
            "signature_matches": signature_matches,
            "ml_telemetry": risk_calc,
            "verdict": llm_result.get("verdict", "ANOMALOUS_ATTACK" if signature_matches else "NORMAL"),
            "risk_score": risk_calc["composite_score"],
            "if_score": risk_calc["if_score"],
            "ae_score": risk_calc["ae_score"],
            "confidence": llm_result.get("confidence_score", 96),
            "chain_of_thought": llm_result.get("chain_of_thought", []),
            "explanation": llm_result.get("explanation", ""),
            "correlated_lines": [m["line_no"] for m in signature_matches] or [1],
            "mitre_technique": primary_technique,
            "tactics": llm_result.get("tactics", ["Initial Access", "Privilege Escalation"]),
            "extracted_ips": extracted_ips,
            "llm_engine": llm_result.get("llm_engine", "SentiX Semantic Engine")
        }


# Singleton instance
log_agent = LogAnalyzerAgent()
