import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "backend" / "data"
if os.getenv("VERCEL"):
    DB_PATH = Path("/tmp/sentix_soc.db")
    source_db = BASE_DIR / "sentix_soc.db"
    if source_db.exists() and not DB_PATH.exists():
        import shutil
        try:
            shutil.copy2(source_db, DB_PATH)
        except Exception:
            pass
else:
    DB_PATH = BASE_DIR / "sentix_soc.db"

# Load .env file if present
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    with open(ENV_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

# LLM Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")


# Live External Threat Intelligence Feeds
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
NIST_NVD_API_KEY = os.getenv("NIST_NVD_API_KEY", "")



# Risk Scoring Weights (from Slide 10: Risk Scoring Algorithm)
# Risk Score = w1*IF + w2*AE + w3*Severity + w4*ThreatIntel + w5*AssetCrit + w6*Freq
WEIGHTS = {
    "w_if": 0.20,          # Isolation Forest score
    "w_ae": 0.20,          # Autoencoder anomaly score
    "w_severity": 0.25,    # Rule/Signature severity
    "w_threat_intel": 0.15,# Threat Intel (VirusTotal, AbuseIPDB, NVD)
    "w_asset_crit": 0.10,  # Asset Criticality (Crown jewel DB vs worker)
    "w_frequency": 0.10    # Event recurrence frequency
}

# Risk Thresholds (Slide 10)
# 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical
RISK_LEVELS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100)
}
