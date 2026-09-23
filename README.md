# SentiX: Multi-Agent Autonomous Security Operations Center (SOC)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![IEEE Access](https://img.shields.io/badge/IEEE%20Access-2025.3602681-informational.svg)](https://doi.org/10.1109/ACCESS.2025.3602681)
[![AI/ML Anomaly](https://img.shields.io/badge/ML-Isolation%20Forest%20%2B%20Autoencoder-purple.svg)]()
[![LLM](https://img.shields.io/badge/LLM-LLaMA%203.3--70B%20Versatile%20(Groq)-orange.svg)]()

> **SentiX** (SentinelX) is an advanced, production-grade, AI-powered autonomous Security Operations Center (SOC) and threat correlation platform. It combines specialized multi-agent workflows, machine learning anomaly detection (Isolation Forest and Neural Autoencoder), and Large Language Models (LLMs via Groq / LLaMA 3.3-70B) to detect, correlate, explain, and autonomously mitigate complex multi-vector cyber threats in real time.

---

## Academic & Research Foundations

This system integrates the theoretical framework, mathematical models, and operational pipelines from:
1. **IEEE Access Research Publication (2025)**:  
   *"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"*, authored by Yasser Hmimou, Mohamed Tabaa, Azeddine Khiat, and Zineb Hidila (*IEEE Access, Vol. 13, 2025*).
2. **SentinelX Major Project Architecture**:  
   *Department of Computer Science & Engineering (AI & ML), R L Jalappa Institute of Technology (RLJIT)*, under the guidance of Mrs. Nandini K V.

### Performance Benchmarks (Empirical Paper Results)
| Metric | Benchmark Result | Traditional SIEM Baseline | Relative Improvement |
| :--- | :--- | :--- | :--- |
| **System-Wide Detection Accuracy** | **93.6%** | ~82.0% | +11.6% |
| **Threat Correlation Precision** | **87.0%** | Single-domain siloed | Cross-domain multi-vector |
| **False Positive Reduction** | **41.3%** | Reference Baseline | **41.3% reduction** |
| **Analyst Triage Time Reduction** | **38.5%** | Manual investigation | **38.5% faster response** |
| **Analyst Trust Confidence Score** | **4.6 / 5.0** | N/A | High transparency (XAI) |

---

## System Architecture

```
                                  +-------------------------------------------------------+
                                  |                     Web Browser                       |
                                  |         High-Tech SOC Console (Slides 11, 12, 13)     |
                                  |  Alert Stream | Dossier | Threat Map | Agent Mesh UI  |
                                  +---------------------------+---------------------------+
                                                              | REST & JSON Telemetry
                                  +---------------------------v---------------------------+
                                  |               FastAPI Backend Gateway                 |
                                  |             Task Dispatcher & REST APIs               |
                                  +----+--------------------+-----------------------+-----+
                                       |                    |                       |
                     +-----------------v----+      +--------v-----------+     +-----v----------------+
                     | Email Verification   |      | Log Analyzer Agent |     | IP Range Analyzer    |
                     | Agent (Fig. 3)       |      | (Suricata + ELK)   |     | Agent (Fig. 5)       |
                     | - Preprocessing      |      | - Normalization    |     | - ipaddress parser   |
                     | - RegEx / tldextract |      | - Rule matching    |     | - Port/service probe |
                     | - FAISS / TF-IDF sim |      | - IF + AE ML model |     | - CVE & CVSS lookup  |
                     | - Sentiment/Urgency  |      | - Temporal Memory  |     | - Risk prioritization|
                     | - Groq / LLaMA 3.3   |      | - Groq / LLaMA 3.3 |     | - Groq / LLaMA 3.3   |
                     +-----------------+----+      +--------+-----------+     +-----+----------------+
                                       |                    |                       |
                                       +--------------------+-----------------------+
                                                            | Domain Reports
                                  +-------------------------v-----------------------------+
                                  |         Cross-Context Recommendation System           |
                                  | - Multi-Domain Entity Correlator (IP, Domain, URL)    |
                                  | - Temporal Pattern Linking (Phishing -> Login -> RCE) |
                                  | - Mathematical Risk Scoring Engine (Slide 10)         |
                                  | - Chain-of-Thought LLM Narrative Synthesis (Fig 6)    |
                                  +-------------------------+-----------------------------+
                                                            |
                                  +-------------------------v-----------------------------+
                                  |     Automated Response & Storage Engine (SQLite)      |
                                  | - Containment Ledger & Simulated IP / Host Isolation  |
                                  | - Incident Ticket Generator & Dossier Archiving       |
                                  +-------------------------------------------------------+
```

---

## Core Modules & Functionality

### 1. Task Dispatcher Agent (Fig. 2)
- Performs structural validation and completeness checking on all incoming submissions.
- Classifies tasks into `email`, `log`, or `ip_range` pipelines.
- Asynchronously dispatches data to specialized analytical units.

### 2. Email Verification Agent (Fig. 3)
- Ingests headers, sender information, and email text.
- Executes vector similarity against pre-indexed SpamAssassin & phishing corpora.
- Symbolic RegEx analysis for brand spoofing, urgent coercive language, and suspicious TLDs.
- Evaluates psychological urgency and coercion levels.
- Chains LLaMA 3.3-70B for explainable Chain-of-Thought (CoT) classification (Safe / Suspicious / Phishing).

### 3. Log Analyzer Agent (Fig. 4)
- Normalizes logs from diverse sources (auth logs, web access, firewalls) into standardized ELK schemas.
- High-performance signature matching using Suricata-style intrusion rules (Brute-Force, SQL Injection, Kerberoasting, Buffer Overflows).
- State memory module for tracking temporal attacker progression.
- Machine Learning Anomaly Detection using Isolation Forest and Autoencoder reconstruction loss.

### 4. IP Range Analyzer Agent (Fig. 5)
- Validates IPv4 and CIDR subnet syntax (`ipaddress` module).
- Network surface enumeration and active service fingerprinting (Nmap format).
- Cross-references exposed daemons against the National Vulnerability Database (NVD) with CVSS v3 metrics.
- Formulates role-tailored remediation strategies for both Security Engineers and Risk Managers.

### 5. Contextual Recommendation System (Fig. 6)
- Evaluates outputs across all three domain agents simultaneously.
- Cross-domain entity matching (shared IP addresses, domains, and compromised host assets).
- Temporal sequence alignment (e.g. initial phishing lure $\to$ authentication spike $\to$ gateway exploit).
- Generates a unified incident narrative and prioritized action plan.

### 6. Mathematical Risk Scoring Engine (Slide 10)
Computes a composite multi-factor risk score normalized between `0` and `100`:
$$\text{Risk Score} = w_1 \times \text{IF Score} + w_2 \times \text{AE Score} + w_3 \times \text{Severity} + w_4 \times \text{Threat Intel} + w_5 \times \text{Asset Criticality} + w_6 \times \text{Frequency}$$

**Risk Tiers:**
- `0 - 24`: **LOW**
- `25 - 49`: **MEDIUM**
- `50 - 74`: **HIGH**
- `75 - 100`: **CRITICAL**

### 7. Automated Response Orchestration & Containment Ledger (Slides 12 & 13)
- **Action Handler 01**: Block IP (WAF & edge firewall ban)
- **Action Handler 02**: Isolate Host (EDR network isolation)
- **Action Handler 03**: Disable User (Active Directory lockout)
- **Action Handler 04**: Generate Alert (System-wide alert notification)
- **Action Handler 05**: Notify Analyst (Slack & PagerDuty webhook dispatch)
- **Action Handler 06**: Create Report (Markdown / JSON incident dossier)
- Immutable Containment Ledger recording timestamp, action, target, severity, mode, and executing agent.

---

## SOC Console Dashboard (Slides 11, 12, 13)

The web dashboard is built with a responsive tactical dark cyberpunk theme:
- **Slide 11 Replica**: Live Alert Stream (filtering by `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), AI Investigation Dossier with live progress bars for Composite Risk Score, Isolation Forest index, model confidence, and Threat Intel feeds (VirusTotal, AbuseIPDB, OTX).
- **Slide 12 Replica**: Live Global Attack Origin Geolocation canvas map with animated threat vectors, 60-Minute Detection Volume area chart, and Automated Response Orchestration action handlers with manual/auto modes.
- **Slide 13 Replica**: Autonomous Agent Mesh Pipeline (12 agents: Aegis-Guard, ShieldNet, Chronos-Mesh, Spectre-Intel, Cerberus-Core, Kube-Shield, Vortex-Stream, Phalanx-Zero, Sentinel-AI, Auto-Contain, Crypton-Guard, Omega-Master) and Action History Containment Ledger.
- **Simulation Lab**: One-click multi-vector attack scenario runner demonstrating end-to-end detection and autonomous containment.

---

## Quick Start & Installation

### Option 1: Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/vamshichethan/SentiX.git
cd SentiX

# 2. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your Groq API key for live LLaMA 3.3-70B reasoning
cp .env.example .env
# Edit .env and insert your GROQ_API_KEY if desired.
# Note: SentiX operates seamlessly without an API key using its built-in semantic heuristic fallback!

# 5. Start the SentiX Autonomous SOC Platform
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser to:
👉 **`http://localhost:8000`**

### Option 2: Run in GitHub Codespaces

1. In GitHub, click the **Code** button and choose **Open with Codespaces**.
2. Run in the Codespaces terminal:
   ```bash
   pip install -r requirements.txt
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```
3. Click the popup to view the forwarded port `8000`.

---

## Running the Test Suite

Run the full automated test suite (unit and API integration tests):

```bash
source .venv/bin/activate
python3 -m unittest discover -s tests -p "test_*.py" -v
```

All 17 tests validate ML model training, feature extraction, anomaly scoring, individual agent pipelines, cross-context correlation, response actions, and REST endpoints.

---

## API Documentation

FastAPI provides an interactive OpenAPI / Swagger UI at:
👉 **`http://localhost:8000/docs`**

Key Endpoints:
- `GET /api/health` — System health and mesh status
- `GET /api/stats` — Real-time SOC metrics (Critical incidents, auto-contained, mean risk, MTTR)
- `POST /api/dispatch` — Task Dispatcher Agent (Fig. 2)
- `POST /api/email/analyze` — Email Verification Agent (Fig. 3)
- `POST /api/logs/analyze` — Log Analyzer Agent (Fig. 4)
- `POST /api/ip/scan` — IP Range Analyzer Agent (Fig. 5)
- `POST /api/correlate` — Contextual Recommendation System (Fig. 6)
- `GET /api/alerts` — Live Alert Stream (Slide 11)
- `GET /api/agents/status` — 12 Autonomous Agents Mesh Pipeline (Slide 13)
- `POST /api/actions/execute` — Execute response actions (Block IP, Isolate Host, etc.)
- `GET /api/actions/history` — Action History Containment Ledger (Slide 13)
- `POST /api/simulation/run` — End-to-end multi-vector attack simulation

---

## Project Team & Credits

- **Department of CSE (Artificial Intelligence and Machine Learning)**  
  *R L Jalappa Institute of Technology, Doddaballapura, Bangalore Rural District-561 203*
- **Project Team**:
  - Samarth G (1RL23CI052)
  - Varun Sai (1RL23CI061)
  - Vikas K M (1RL23CI062)
  - Yashaswini M (1RL23CI063)
- **Project Guide**: Mrs. Nandini K V, Assistant Professor, Dept. of CS&E (AI & ML)
- **Research Foundation**: Yasser Hmimou, Mohamed Tabaa, Azeddine Khiat, Zineb Hidila (*IEEE Access 2025*)

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
