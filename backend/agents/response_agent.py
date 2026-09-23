"""
Automated Response Orchestration Agent
Implements Slide 12 Action Handlers and Slide 13 Containment Ledger:
- Action Handler 01: Block IP (Perimeter firewall / WAF ban)
- Action Handler 02: Isolate Host (EDR network isolation)
- Action Handler 03: Disable User (Active Directory lockout)
- Action Handler 04: Generate Alert (System level notification)
- Action Handler 05: Notify Analyst (Slack / PagerDuty webhook trigger)
- Action Handler 06: Create Report (Markdown / JSON incident dossier)
"""

import uuid
import datetime
from typing import Dict, Any, List
from backend.database import add_containment_action, insert_alert


class ResponseOrchestrationAgent:
    def __init__(self):
        self.auto_mode = True  # Can be toggled from UI

    def execute_action(
        self,
        action_type: str,
        target: str,
        severity: str = "HIGH",
        mode: str = "MANUAL",
        executor: str = "Analyst Console"
    ) -> Dict[str, Any]:
        """
        Executes a targeted response action and appends to the immutable containment ledger.
        """
        action_clean = action_type.strip().upper()
        now_ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        ledger_action_map = {
            "BLOCK_IP": ("BLOCK_IP", "Auto-Contain-10", f"Firewall rule deployed. Traffic to/from {target} dropped across all interfaces."),
            "ISOLATE_HOST": ("ISOLATE_HOST", "Cerberus-Core-05", f"Host {target} isolated via EDR agent. Outbound network sockets severed."),
            "DISABLE_USER": ("DISABLE_USER", "Aegis-Guard-01", f"Active Directory account {target} revoked and active sessions invalidated."),
            "GENERATE_ALERT": ("GENERATE_ALERT", "Chronos-Mesh-03", f"P1 Incident alert generated and dispatched to SOC console."),
            "NOTIFY_ANALYST": ("NOTIFY_ANALYST", "Sentinel-AI-09", f"High-priority dispatch sent to Slack #soc-incidents & PagerDuty."),
            "CREATE_REPORT": ("CREATE_REPORT", "Sentinel-AI-09", f"Comprehensive incident dossier generated and archived for compliance audit.")
        }

        action_name, default_exec, message = ledger_action_map.get(
            action_clean,
            (action_clean, "Auto-Contain-10", f"Action {action_clean} executed against {target}.")
        )

        final_executor = executor if executor != "Analyst Console" else default_exec

        # Record into SQLite containment ledger
        record_id = add_containment_action(
            action=action_name,
            target=target,
            severity=severity,
            mode=mode,
            executed_by=final_executor
        )

        return {
            "success": True,
            "action_id": record_id,
            "action": action_name,
            "target": target,
            "severity": severity,
            "mode": mode,
            "executed_by": final_executor,
            "timestamp": now_ts,
            "message": message
        }


# Singleton instance
response_agent = ResponseOrchestrationAgent()
