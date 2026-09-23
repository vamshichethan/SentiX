/**
 * SentiX SOC Console Frontend Application
 * Interacts with FastAPI backend to render:
 * - Live Alert Stream (Slide 11)
 * - AI Investigation Dossier (Slide 11)
 * - Global Attack Origin Map & Volume Chart (Slide 12)
 * - Automated Response Handlers (Slide 12)
 * - Autonomous Agent Mesh Pipeline (Slide 13)
 * - Action History - Containment Ledger (Slide 13)
 */

let activeAlerts = [];
let selectedAlert = null;
let currentSeverityFilter = "ALL";
let isFeedPaused = false;
let autoContainmentMode = false;

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    loadDashboardStats();
    loadAlerts();
    loadAgentMesh();
    loadContainmentLedger();
    setupEventListeners();
    initAttackMap();
    initVolumeChart();

    // Polling loop for live telemetry every 5 seconds
    setInterval(() => {
        if (!isFeedPaused) {
            loadDashboardStats();
            loadAlerts(false);
            loadAgentMesh();
            loadContainmentLedger();
        }
    }, 5000);
});

/* UTC Live Clock */
function initClock() {
    const clockEl = document.getElementById("utc-clock-time");
    function update() {
        const now = new Date();
        const y = now.getUTCFullYear();
        const m = String(now.getUTCMonth() + 1).padStart(2, '0');
        const d = String(now.getUTCDate()).padStart(2, '0');
        const h = String(now.getUTCHours()).padStart(2, '0');
        const min = String(now.getUTCMinutes()).padStart(2, '0');
        const s = String(now.getUTCSeconds()).padStart(2, '0');
        if (clockEl) {
            clockEl.textContent = `${y}-${m}-${d} ${h}:${min}:${s} UTC`;
        }
    }
    update();
    setInterval(update, 1000);
}

/* Event Listeners */
function setupEventListeners() {
    // Feed control pause/resume
    const feedBtn = document.getElementById("btn-feed-toggle");
    if (feedBtn) {
        feedBtn.addEventListener("click", () => {
            isFeedPaused = !isFeedPaused;
            feedBtn.innerHTML = isFeedPaused 
                ? `<span class="icon">▶</span> RESUME FEED` 
                : `<span class="icon">⏸</span> PAUSE FEED`;
            feedBtn.style.color = isFeedPaused ? "#fbbf24" : "#e2e8f0";
        });
    }

    // Filter pills
    const pills = document.querySelectorAll(".pill-btn");
    pills.forEach(pill => {
        pill.addEventListener("click", (e) => {
            pills.forEach(p => p.classList.remove("active"));
            e.target.classList.add("active");
            currentSeverityFilter = e.target.getAttribute("data-sev");
            renderAlertList();
        });
    });

    // Search bar
    const searchInput = document.getElementById("search-alerts");
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            renderAlertList();
        });
    }

    // Mode Toggle (Manual / Auto)
    const modeToggle = document.getElementById("mode-toggle-btn");
    if (modeToggle) {
        modeToggle.addEventListener("click", () => {
            autoContainmentMode = !autoContainmentMode;
            modeToggle.textContent = autoContainmentMode ? "AUTO ON" : "AUTO OFF";
            modeToggle.style.background = autoContainmentMode ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)";
            modeToggle.style.color = autoContainmentMode ? "#34d399" : "#fca5a5";
            modeToggle.style.borderColor = autoContainmentMode ? "#10b981" : "#ef4444";
        });
    }

    // Action Handlers Test Execute
    document.querySelectorAll(".btn-test-exec").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const action = e.target.getAttribute("data-action");
            const target = e.target.getAttribute("data-target") || (selectedAlert ? selectedAlert.src_ip : "203.175.188.1");
            executeAction(action, target, "MANUAL");
        });
    });

    // Dossier quick action buttons
    const btnP1 = document.getElementById("btn-create-p1");
    if (btnP1) {
        btnP1.addEventListener("click", () => {
            if (selectedAlert) {
                executeAction("CREATE_REPORT", selectedAlert.asset || selectedAlert.src_ip, "MANUAL");
            }
        });
    }
    const btnEdr = document.getElementById("btn-edr-isolate");
    if (btnEdr) {
        btnEdr.addEventListener("click", () => {
            if (selectedAlert) {
                executeAction("ISOLATE_HOST", selectedAlert.dest_ip || selectedAlert.asset, "MANUAL");
            }
        });
    }

    // Simulation Modal
    const btnSim = document.getElementById("btn-open-sim");
    const modalSim = document.getElementById("sim-modal");
    const btnCloseModal = document.getElementById("btn-close-modal");
    const btnRunSim = document.getElementById("btn-run-sim-action");

    if (btnSim && modalSim) {
        btnSim.addEventListener("click", () => modalSim.classList.add("open"));
    }
    if (btnCloseModal && modalSim) {
        btnCloseModal.addEventListener("click", () => modalSim.classList.remove("open"));
    }
    if (btnRunSim) {
        btnRunSim.addEventListener("click", triggerAttackSimulation);
    }
}

/* API Calls */
async function loadDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        if (res.ok) {
            const data = await res.json();
            document.getElementById("stat-critical").textContent = data.critical_incidents;
            document.getElementById("stat-contained").textContent = data.auto_contained;
            document.getElementById("stat-risk").textContent = data.mean_risk_score;
            document.getElementById("stat-mttr").textContent = data.mean_time_to_respond;
            if (document.getElementById("events-today-badge")) {
                document.getElementById("events-today-badge").textContent = `${data.events_processed_today.toLocaleString()} events processed today`;
            }
        }
    } catch (err) {
        console.error("Error loading stats:", err);
    }
}

async function loadAlerts(reselect = true) {
    try {
        const res = await fetch("/api/alerts");
        if (res.ok) {
            activeAlerts = await res.json();
            renderAlertList();
            if (reselect && activeAlerts.length > 0 && !selectedAlert) {
                selectAlert(activeAlerts[0]);
            }
        }
    } catch (err) {
        console.error("Error loading alerts:", err);
    }
}

function renderAlertList() {
    const listEl = document.getElementById("alert-stream-list");
    if (!listEl) return;

    const searchTerm = (document.getElementById("search-alerts")?.value || "").toLowerCase();

    const filtered = activeAlerts.filter(item => {
        const matchSev = currentSeverityFilter === "ALL" || item.severity.toUpperCase() === currentSeverityFilter.toUpperCase();
        const matchSearch = !searchTerm || 
            item.title.toLowerCase().includes(searchTerm) ||
            (item.src_ip && item.src_ip.includes(searchTerm)) ||
            (item.asset && item.asset.toLowerCase().includes(searchTerm)) ||
            (item.mitre_technique && item.mitre_technique.toLowerCase().includes(searchTerm));
        return matchSev && matchSearch;
    });

    listEl.innerHTML = "";
    if (filtered.length === 0) {
        listEl.innerHTML = `<div style="padding:20px;text-align:center;color:#64748b;">No alerts matching criteria</div>`;
        return;
    }

    filtered.forEach(alert => {
        const item = document.createElement("div");
        const sevClass = alert.severity.toLowerCase();
        const isSelected = selectedAlert && selectedAlert.id === alert.id;

        item.className = `alert-item ${sevClass} ${isSelected ? 'selected' : ''}`;
        item.innerHTML = `
            <div class="alert-top">
                <span class="badge-sev ${sevClass}">${alert.severity}</span>
                <span class="alert-uuid">${alert.id.substring(0, 8)}...</span>
                <span class="alert-time">${alert.timestamp}</span>
            </div>
            <div class="alert-title-text">${alert.title}</div>
            <div class="alert-meta-row">
                <span>Asset: ${alert.asset || alert.dest_ip || 'N/A'}</span>
                <span>Src: ${alert.src_ip || 'N/A'}</span>
                <span class="alert-risk-badge">risk ${alert.risk_score}</span>
            </div>
        `;

        item.addEventListener("click", () => {
            selectAlert(alert);
        });

        listEl.appendChild(item);
    });
}

function selectAlert(alert) {
    selectedAlert = alert;
    renderAlertList();

    // Populate Dossier
    document.getElementById("dossier-alert-id").textContent = alert.id;
    document.getElementById("dossier-cat-badge").textContent = alert.category || "PRIVILEGE ESCALATION";
    document.getElementById("dossier-title").textContent = alert.title;

    document.getElementById("meta-asset").textContent = alert.asset || "10.0.4.10 (Core-DB)";
    document.getElementById("meta-src-ip").textContent = alert.src_ip || "203.175.188.1";
    document.getElementById("meta-protocol").textContent = alert.category === "EMAIL_THREAT" ? "SMTP / TLS" : "HTTPS / TCP";
    document.getElementById("meta-technique").textContent = alert.mitre_technique || "T1078 Valid Accounts";

    // Progress bars
    const compositeBar = document.getElementById("bar-composite");
    const compositeVal = document.getElementById("val-composite");
    if (compositeBar && compositeVal) {
        compositeBar.style.width = `${alert.risk_score}%`;
        compositeVal.textContent = alert.risk_score;
    }

    const ifBar = document.getElementById("bar-if");
    const ifVal = document.getElementById("val-if");
    if (ifBar && ifVal) {
        const ifValNum = alert.if_score || 87;
        ifBar.style.width = `${ifValNum}%`;
        ifVal.textContent = Math.round(ifValNum);
    }

    const confEl = document.getElementById("val-confidence");
    if (confEl) {
        confEl.textContent = `${alert.confidence || 99}%`;
    }

    // Threat Intel
    document.getElementById("intel-vt").textContent = alert.vt_score || "8/72";
    document.getElementById("intel-abuse").textContent = alert.abuse_score || "34% (Suspicious)";
    document.getElementById("intel-otx").textContent = `${alert.otx_matches || 14} Matches`;

    // Evidence & Chain of Thought
    let details = {};
    try {
        details = typeof alert.details_json === "string" ? JSON.parse(alert.details_json) : (alert.details_json || {});
    } catch (e) {
        details = {};
    }

    const cotContainer = document.getElementById("dossier-cot");
    if (cotContainer) {
        cotContainer.innerHTML = `
            <div class="cot-step">
                <span class="cot-step-icon">⚡</span>
                <span><strong>Ingestion & Parsing:</strong> Telemetry captured across perimeter sensors & normalized to ELK schema.</span>
            </div>
            <div class="cot-step">
                <span class="cot-step-icon">🛡</span>
                <span><strong>Signature & ML Anomaly:</strong> Isolation Forest computed anomaly index: ${alert.if_score || 87}%. Autoencoder loss: ${alert.ae_score || 79}%.</span>
            </div>
            <div class="cot-step">
                <span class="cot-step-icon">🤖</span>
                <span><strong>LLM Semantic Synthesis:</strong> ${details.evidence || 'Identified unauthorized authentication and privilege escalation attempt.'}</span>
            </div>
        `;
    }

    const expEl = document.getElementById("dossier-explanation");
    if (expEl) {
        expEl.textContent = details.narrative || `The entity ${alert.src_ip} initiated reconnaissance and exploited public-facing interfaces targeting internal asset ${alert.asset}. Immediate host containment and perimeter firewall blacklisting is recommended.`;
    }
}

async function loadAgentMesh() {
    try {
        const res = await fetch("/api/agents/status");
        if (res.ok) {
            const agents = await res.json();
            const grid = document.getElementById("agent-mesh-grid");
            if (!grid) return;
            grid.innerHTML = "";

            agents.forEach(agent => {
                const node = document.createElement("div");
                node.className = "agent-node";
                const dotClass = agent.status.toLowerCase();
                node.innerHTML = `
                    <div class="agent-top-row">
                        <span class="agent-id-name">${agent.name}</span>
                        <span class="agent-status-pill">
                            <span class="status-dot ${dotClass}"></span>
                            ${agent.status}
                        </span>
                    </div>
                    <div class="agent-role">${agent.role}</div>
                    <div class="agent-metrics-row">
                        <span>Load: ${agent.load_pct}%</span>
                        <span>Latency: ${agent.latency_ms}ms</span>
                    </div>
                `;
                grid.appendChild(node);
            });
        }
    } catch (err) {
        console.error("Error loading agent mesh:", err);
    }
}

async function loadContainmentLedger() {
    try {
        const res = await fetch("/api/actions/history");
        if (res.ok) {
            const ledger = await res.json();
            const tbody = document.getElementById("ledger-table-body");
            const countBadge = document.getElementById("ledger-count-badge");
            if (countBadge) countBadge.textContent = `${ledger.length} events logged`;
            if (!tbody) return;

            tbody.innerHTML = "";
            ledger.forEach(entry => {
                const tr = document.createElement("tr");
                const sevColor = entry.severity === "CRITICAL" ? "#f87171" : "#fbbf24";
                const modeColor = entry.mode === "AUTO" ? "#34d399" : "#38bdf8";

                tr.innerHTML = `
                    <td>${entry.timestamp}</td>
                    <td><strong>${entry.action}</strong></td>
                    <td style="color:#f1f5f9;">${entry.target}</td>
                    <td style="color:${sevColor};font-weight:700;">${entry.severity}</td>
                    <td style="color:${modeColor};">${entry.mode}</td>
                    <td>${entry.executed_by}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Error loading containment ledger:", err);
    }
}

async function executeAction(actionType, target, mode = "MANUAL") {
    try {
        const res = await fetch("/api/actions/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: actionType,
                target: target,
                severity: "CRITICAL",
                mode: mode,
                executed_by: "SOC Lead (Analyst Console)"
            })
        });
        if (res.ok) {
            const data = await res.json();
            loadContainmentLedger();
            loadDashboardStats();
            showNotification(`Action ${data.action} executed against ${data.target}`);
        }
    } catch (err) {
        console.error("Action execution error:", err);
    }
}

async function triggerAttackSimulation() {
    const btn = document.getElementById("btn-run-sim-action");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "EXECUTING SIMULATION PIPELINE...";
    }
    try {
        const res = await fetch("/api/simulation/run", { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            await loadAlerts();
            await loadDashboardStats();
            await loadContainmentLedger();
            document.getElementById("sim-modal")?.classList.remove("open");
            showNotification(`Multi-Vector APT Intrusion Simulated: Cross-domain correlation completed & threats auto-contained!`);
        }
    } catch (err) {
        console.error("Simulation error:", err);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "TRIGGER MULTI-VECTOR ATTACK SIMULATION";
        }
    }
}

function showNotification(msg) {
    const toast = document.createElement("div");
    toast.style.position = "fixed";
    toast.style.bottom = "24px";
    toast.style.right = "24px";
    toast.style.background = "#1e293b";
    toast.style.border = "1px solid #38bdf8";
    toast.style.color = "#fff";
    toast.style.padding = "12px 20px";
    toast.style.borderRadius = "8px";
    toast.style.boxShadow = "0 8px 24px rgba(0,0,0,0.5)";
    toast.style.fontFamily = "'JetBrains Mono', monospace";
    toast.style.fontSize = "12px";
    toast.style.zIndex = "1000";
    toast.innerHTML = `🛡 <strong>SentiX Orchestrator:</strong> ${msg}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

/* Canvas-based Geolocation Map (Slide 12) */
function initAttackMap() {
    const canvas = document.getElementById("attack-map-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    function resize() {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight || 240;
    }
    resize();
    window.addEventListener("resize", resize);

    // Target SOC Node (e.g., North America / Central)
    const target = { x: 0.28, y: 0.42, name: "Core SOC" };

    // Threat Vectors (Origins around globe)
    const origins = [
        { x: 0.52, y: 0.35, name: "Frankfurt (185.220.101.5)", color: "#ef4444" },
        { x: 0.78, y: 0.45, name: "East Asia (203.175.188.1)", color: "#f59e0b" },
        { x: 0.65, y: 0.28, name: "Moscow (45.154.255.88)", color: "#ef4444" },
        { x: 0.85, y: 0.78, name: "Sydney (103.224.182.9)", color: "#06b6d4" },
        { x: 0.18, y: 0.38, name: "San Jose (198.51.100.22)", color: "#f59e0b" }
    ];

    let t = 0;
    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Draw simplified grid / world outline dots
        ctx.fillStyle = "rgba(255, 255, 255, 0.05)";
        for (let x = 20; x < canvas.width; x += 24) {
            for (let y = 15; y < canvas.height; y += 24) {
                ctx.fillRect(x, y, 2, 2);
            }
        }

        const tx = canvas.width * target.x;
        const ty = canvas.height * target.y;

        // Draw target SOC node
        ctx.beginPath();
        ctx.arc(tx, ty, 6, 0, Math.PI * 2);
        ctx.fillStyle = "#10b981";
        ctx.fill();
        ctx.strokeStyle = "rgba(16, 185, 129, 0.4)";
        ctx.lineWidth = 4;
        ctx.stroke();

        // Draw attack vectors
        origins.forEach((o, idx) => {
            const ox = canvas.width * o.x;
            const oy = canvas.height * o.y;

            // Origin node
            ctx.beginPath();
            ctx.arc(ox, oy, 4, 0, Math.PI * 2);
            ctx.fillStyle = o.color;
            ctx.fill();

            // Pulsing ring
            const pulseR = 4 + (Math.sin(t * 0.05 + idx) + 1) * 4;
            ctx.beginPath();
            ctx.arc(ox, oy, pulseR, 0, Math.PI * 2);
            ctx.strokeStyle = o.color;
            ctx.lineWidth = 1;
            ctx.stroke();

            // Bezier curve to SOC
            ctx.beginPath();
            ctx.moveTo(ox, oy);
            const cx = (ox + tx) / 2;
            const cy = Math.min(oy, ty) - 30;
            ctx.quadraticCurveTo(cx, cy, tx, ty);
            ctx.strokeStyle = "rgba(239, 68, 68, 0.25)";
            ctx.lineWidth = 1.5;
            ctx.setLineDash([4, 4]);
            ctx.stroke();
            ctx.setLineDash([]);

            // Moving particle
            const progress = ((t * 0.015 + idx * 0.2) % 1);
            const px = (1 - progress) * (1 - progress) * ox + 2 * (1 - progress) * progress * cx + progress * progress * tx;
            const py = (1 - progress) * (1 - progress) * oy + 2 * (1 - progress) * progress * cy + progress * progress * ty;

            ctx.beginPath();
            ctx.arc(px, py, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = "#fff";
            ctx.fill();
        });

        t += 1;
        requestAnimationFrame(draw);
    }
    draw();
}

/* Detection Volume (60 Min) Canvas Chart (Slide 12) */
function initVolumeChart() {
    const canvas = document.getElementById("volume-chart-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    function resize() {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight || 240;
    }
    resize();
    window.addEventListener("resize", resize);

    // Mock 60 min points matching Slide 12 (amber line total, red line critical)
    const pointsTotal = [14, 15, 12, 11, 10, 9, 8, 9, 10, 12, 14, 17, 21, 25, 29, 31, 32];
    const pointsCrit = [8, 9, 7, 6, 7, 7, 8, 7, 8, 9, 11, 14, 16, 18, 19, 19, 20];

    function drawChart() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        const w = canvas.width - 60;
        const h = canvas.height - 40;
        const startX = 40;
        const startY = 15;

        // Grid lines
        ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = startY + (h / 4) * i;
            ctx.beginPath();
            ctx.moveTo(startX, y);
            ctx.lineTo(startX + w, y);
            ctx.stroke();

            // Label
            ctx.fillStyle = "#4b5563";
            ctx.font = "10px JetBrains Mono";
            ctx.fillText(String(32 - i * 8), 10, y + 3);
        }

        function drawCurve(data, strokeColor, fillColor) {
            ctx.beginPath();
            data.forEach((val, i) => {
                const x = startX + (w / (data.length - 1)) * i;
                const y = startY + h - (val / 35) * h;
                if (i === 0) ctx.moveTo(x, y);
                else {
                    const prevX = startX + (w / (data.length - 1)) * (i - 1);
                    const prevY = startY + h - (data[i - 1] / 35) * h;
                    const cX = (prevX + x) / 2;
                    ctx.bezierCurveTo(cX, prevY, cX, y, x, y);
                }
            });

            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = 2.5;
            ctx.stroke();

            // Area fill
            ctx.lineTo(startX + w, startY + h);
            ctx.lineTo(startX, startY + h);
            ctx.closePath();
            ctx.fillStyle = fillColor;
            ctx.fill();
        }

        // Draw Total Volume (Amber)
        const gradAmber = ctx.createLinearGradient(0, startY, 0, startY + h);
        gradAmber.addColorStop(0, "rgba(245, 158, 11, 0.25)");
        gradAmber.addColorStop(1, "rgba(245, 158, 11, 0.0)");
        drawCurve(pointsTotal, "#f59e0b", gradAmber);

        // Draw Critical Volume (Red)
        const gradRed = ctx.createLinearGradient(0, startY, 0, startY + h);
        gradRed.addColorStop(0, "rgba(239, 68, 68, 0.3)");
        gradRed.addColorStop(1, "rgba(239, 68, 68, 0.0)");
        drawCurve(pointsCrit, "#ef4444", gradRed);
    }

    drawChart();
}
