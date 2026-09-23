"""
Task Dispatcher Agent
Implements Fig. 2 of IEEE Access 2025 Paper:
- Input validation (ensures syntactic & structural correctness)
- Task type classification (Email Verification, Log Analysis, IP Range Scanning)
- Secure, modular routing to domain-specific agent pipelines
"""

import re
from typing import Dict, Any, Tuple
from backend.agents.email_agent import email_agent
from backend.agents.log_agent import log_agent
from backend.agents.ip_agent import ip_agent


class TaskDispatcherAgent:
    def __init__(self):
        pass

    def classify_task(self, payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Classifies incoming user/system submission into one of 3 domains:
        - 'email'
        - 'log'
        - 'ip_range'
        """
        # Explicit task type provided
        task_type = str(payload.get("task_type", "")).lower()
        if task_type in ["email", "log", "logs", "ip", "ip_range", "network"]:
            clean_type = "email" if task_type == "email" else ("log" if "log" in task_type else "ip_range")
            return clean_type, {"valid": True}

        # Heuristic inference from keys and content
        if "subject" in payload or "sender" in payload or "headers" in payload:
            return "email", {"valid": True}

        if "entries" in payload or "log_file" in payload or "raw_logs" in payload:
            return "log", {"valid": True}

        if "range" in payload or "cidr" in payload or "target_ip" in payload or "network" in payload:
            return "ip_range", {"valid": True}

        # Inspect arbitrary text
        raw_text = str(payload.get("text") or payload.get("data") or "")
        if "From:" in raw_text or "Subject:" in raw_text or "@" in raw_text:
            return "email", {"valid": True}
        if re.search(r"sshd\[\d+\]|sudo:|kernel:|HTTP/\d", raw_text):
            return "log", {"valid": True}
        if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", raw_text.strip()):
            return "ip_range", {"valid": True}

        return "unknown", {"valid": False, "error": "Unable to determine cybersecurity task classification"}

    def dispatch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates, classifies, and routes task to domain agent.
        """
        task_type, validation = self.classify_task(payload)
        if not validation["valid"]:
            return {
                "dispatcher_status": "REJECTED",
                "error": validation.get("error", "Malformed input data"),
                "task_type": "UNKNOWN"
            }

        if task_type == "email":
            result = email_agent.process(payload)
        elif task_type == "log":
            result = log_agent.process(payload)
        elif task_type == "ip_range":
            result = ip_agent.process(payload)
        else:
            return {
                "dispatcher_status": "REJECTED",
                "error": f"Unsupported task type: {task_type}"
            }

        return {
            "dispatcher_status": "ROUTED_AND_EXECUTED",
            "routed_agent": result.get("agent"),
            "task_type": task_type,
            "analysis_result": result
        }


# Singleton instance
dispatcher_agent = TaskDispatcherAgent()
