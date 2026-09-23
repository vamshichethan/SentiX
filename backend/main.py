"""
SentiX - Multi-Agent Autonomous Security Operations Center (SOC)
FastAPI Backend Gateway & Orchestrator
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Query, Body, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.database import (
    init_db, get_all_alerts, get_alert_by_id, insert_alert,
    get_agent_mesh, get_containment_ledger, add_containment_action, get_stats
)
from backend.agents.dispatcher import dispatcher_agent
from backend.agents.email_agent import email_agent
from backend.agents.log_agent import log_agent
from backend.agents.ip_agent import ip_agent
from backend.agents.correlation_agent import correlation_system
from backend.agents.response_agent import response_agent
from backend.data.samples import SAMPLE_EMAILS, SAMPLE_LOGS, SAMPLE_IP_SCANS, NVD_DATABASE

app = FastAPI(
    title="SentiX - Autonomous Multi-Agent SOC",
    description="Multi-Agent System for Cybersecurity Threat Detection, Correlation, and Autonomous Response",
    version="2.0.0"
)

# Enable CORS for local testing and decoupled frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


# Pydantic Request Models
class DispatchPayload(BaseModel):
    task_type: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    entries: Optional[Any] = None
    range: Optional[str] = None
    target: Optional[str] = None
    text: Optional[str] = None


class ActionPayload(BaseModel):
    action: str
    target: str
    severity: Optional[str] = "HIGH"
    mode: Optional[str] = "MANUAL"
    executed_by: Optional[str] = "Analyst Console"


class CorrelatePayload(BaseModel):
    email: Optional[Dict[str, Any]] = None
    log: Optional[Dict[str, Any]] = None
    ip_scan: Optional[Dict[str, Any]] = None


class KeysPayload(BaseModel):
    gemini_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    slack_webhook_url: Optional[str] = None



@app.on_event("startup")
def startup_event():
    init_db()


api_router = APIRouter()

# ---------------- API ENDPOINTS ---------------- #

@api_router.get("/health")
def health_check():
    return {
        "status": "OPERATIONAL",
        "system": "SentiX Autonomous SOC",
        "version": "2.0.0",
        "mesh_agents_active": 12,
        "database": "SQLite Initialized"
    }


@api_router.get("/stats")
def get_soc_statistics():
    return get_stats()


@api_router.get("/samples")
def get_sample_datasets():
    """Returns sample benchmark data for one-click testing."""
    return {
        "emails": SAMPLE_EMAILS,
        "logs": SAMPLE_LOGS,
        "ip_scans": SAMPLE_IP_SCANS,
        "cves": NVD_DATABASE
    }


@api_router.get("/settings/keys")
def get_key_status():
    from backend.agents.llm_client import llm_client
    return {
        "gemini_active": llm_client.is_gemini_available(),
        "groq_active": llm_client.is_groq_available(),
        "active_engine": "Google Gemini" if llm_client.is_gemini_available() else ("Groq LLaMA 3.3" if llm_client.is_groq_available() else "Local Heuristic Engine")
    }


@api_router.post("/settings/keys")
def update_api_keys(payload: KeysPayload):
    from backend.agents.llm_client import llm_client
    env_file = Path(__file__).resolve().parent.parent / ".env"
    env_lines = []
    if env_file.exists():
        with open(env_file, "r") as f:
            env_lines = f.readlines()

    updates = {}
    if payload.gemini_api_key is not None:
        key = payload.gemini_api_key.strip()
        os.environ["GEMINI_API_KEY"] = key
        llm_client.gemini_key = key
        updates["GEMINI_API_KEY"] = key

    if payload.groq_api_key is not None:
        key = payload.groq_api_key.strip()
        os.environ["GROQ_API_KEY"] = key
        llm_client.groq_key = key
        updates["GROQ_API_KEY"] = key

    # Persist to .env
    existing_keys = set()
    new_content = []
    for line in env_lines:
        k = line.split("=")[0].strip()
        if k in updates:
            new_content.append(f"{k}={updates[k]}\n")
            existing_keys.add(k)
        else:
            new_content.append(line)

    for k, v in updates.items():
        if k not in existing_keys:
            new_content.append(f"{k}={v}\n")

    with open(env_file, "w") as f:
        f.writelines(new_content)

    return {
        "success": True,
        "gemini_active": llm_client.is_gemini_available(),
        "groq_active": llm_client.is_groq_available(),
        "active_engine": "Google Gemini" if llm_client.is_gemini_available() else ("Groq LLaMA 3.3" if llm_client.is_groq_available() else "Local Heuristic Engine")
    }


@api_router.post("/dispatch")
def dispatch_task(payload: Dict[str, Any]):
    """Task Dispatcher Agent (Fig 2 of paper) validates and routes request."""
    return dispatcher_agent.dispatch(payload)


@api_router.post("/email/analyze")
def analyze_email(payload: Dict[str, Any]):
    """Email Verification Agent (Fig 3 of paper)."""
    return email_agent.process(payload)


@api_router.post("/logs/analyze")
def analyze_logs(payload: Dict[str, Any]):
    """Log Analyzer Agent (Fig 4 of paper)."""
    return log_agent.process(payload)


@api_router.post("/ip/scan")
def scan_ip_range(payload: Dict[str, Any]):
    """IP Range Analyzer Agent (Fig 5 of paper)."""
    return ip_agent.process(payload)


@api_router.post("/correlate")
def correlate_threats(payload: CorrelatePayload):
    """Contextual Recommendation System (Fig 6 of paper)."""
    email_res = None
    log_res = None
    ip_res = None

    if payload.email:
        email_res = email_agent.process(payload.email)
    if payload.log:
        log_res = log_agent.process(payload.log)
    if payload.ip_scan:
        ip_res = ip_agent.process(payload.ip_scan)

    result = correlation_system.correlate(
        email_result=email_res,
        log_result=log_res,
        ip_result=ip_res
    )
    return result


@api_router.get("/alerts")
def list_alerts(severity: Optional[str] = Query(None)):
    """Slide 11 Live Alert Stream."""
    return get_all_alerts(limit=50, severity_filter=severity)


@api_router.get("/alerts/{alert_id}")
def get_alert_dossier(alert_id: str):
    """Slide 11 AI Investigation Dossier details."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@api_router.get("/agents/status")
def get_mesh_status():
    """Slide 13 Autonomous Agent Mesh Pipeline status."""
    return get_agent_mesh()


@api_router.get("/actions/history")
def get_containment_history():
    """Slide 13 Action History - Containment Ledger."""
    return get_containment_ledger(limit=50)


@api_router.post("/actions/execute")
def execute_response_action(payload: ActionPayload):
    """Slide 12 Automated Response Orchestration handler."""
    return response_agent.execute_action(
        action_type=payload.action,
        target=payload.target,
        severity=payload.severity or "HIGH",
        mode=payload.mode or "MANUAL",
        executor=payload.executed_by or "Analyst Console"
    )


@api_router.post("/simulation/run")
def trigger_attack_simulation():
    """
    Executes an end-to-end multi-vector attack scenario:
    1. Ingests spear-phishing payload referencing C2 185.220.101.5
    2. Ingests auth & web log sequence showing brute-force and RCE on 10.0.4.10
    3. Scans subnet 192.168.14.0/24 mapping CVE-2024-38077 and CVE-2025-2198
    4. Triggers Contextual Correlation System
    5. Executes automated containment action (IP Block + Host Isolation)
    """
    email_res = email_agent.process(SAMPLE_EMAILS[0])
    log_res = log_agent.process(SAMPLE_LOGS[0])
    ip_res = ip_agent.process({"range": "192.168.14.0/24"})

    correlated = correlation_system.correlate(
        email_result=email_res,
        log_result=log_res,
        ip_result=ip_res
    )

    # Automated containment action execution
    action_1 = response_agent.execute_action(
        action_type="BLOCK_IP",
        target="185.220.101.5",
        severity="CRITICAL",
        mode="AUTO",
        executor="Auto-Contain-10"
    )
    action_2 = response_agent.execute_action(
        action_type="ISOLATE_HOST",
        target="10.0.4.10",
        severity="CRITICAL",
        mode="AUTO",
        executor="Cerberus-Core-05"
    )

    return {
        "simulation_status": "COMPLETED",
        "scenario": "Multi-Vector Coordinated APT Intrusion",
        "correlated_incident": correlated,
        "automated_containment": [action_1, action_2]
    }

# Include routes both with and without /api prefix
app.include_router(api_router, prefix="/api")
app.include_router(api_router)


# Static Frontend Mount & Root Index
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "SentiX Backend Active. Frontend files pending initialization."}

