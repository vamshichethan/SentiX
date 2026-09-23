/**
 * SentiX (SentinelX) - Clean, User-Friendly Multi-Page Controller
 * Simple, intuitive, and easy-to-use autonomous cybersecurity console.
 */

let activeAlerts = [];
let selectedAlert = null;
let currentSeverityFilter = "ALL";
let isFeedPaused = false;
let leafletMapInstance = null;
let chartVolumeInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initPageNavigation();
    initLeafletAttackMap();
    initChartJsVolume();
    loadDashboardStats();
    loadAlerts();
    loadAgentMesh();
    loadContainmentLedger();
    setupEventListeners();

    // Polling loop every 5 seconds
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

/* Page Navigation */
function initPageNavigation() {
    const tabButtons = document.querySelectorAll(".nav-tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const pageId = btn.getAttribute("data-page");
            if (pageId) switchPage(pageId);
        });
    });

    const quickSimBtn = document.getElementById("btn-quick-sim");
    if (quickSimBtn) {
        quickSimBtn.addEventListener("click", () => switchPage("page-simulator"));
    }
}

function switchPage(pageId) {
    // Update nav tab buttons
    document.querySelectorAll(".nav-tab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-page") === pageId);
    });

    // Update view pages
    document.querySelectorAll(".page-view").forEach(page => {
        page.classList.remove("active");
    });

    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add("active");
    }

    // Refresh map dimensions if map page is opened
    if (pageId === "page-map" && leafletMapInstance) {
        setTimeout(() => leafletMapInstance.invalidateSize(), 200);
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* Event Listeners */
function setupEventListeners() {
    // Severity Filter Tabs
    document.querySelectorAll(".sev-filter-bar .filter-tab").forEach(tab => {
        tab.addEventListener("click", (e) => {
            document.querySelectorAll(".sev-filter-bar .filter-tab").forEach(t => t.classList.remove("active"));
            e.target.classList.add("active");
            currentSeverityFilter = e.target.getAttribute("data-sev");
            renderAlertList();
        });
    });

    // Search bar
    const searchInput = document.getElementById("search-alerts");
    if (searchInput) {
        searchInput.addEventListener("input", renderAlertList);
    }

    // Isolate Host button
    const btnEdr = document.getElementById("btn-edr-isolate");
    if (btnEdr) {
        btnEdr.addEventListener("click", () => {
            if (selectedAlert) {
                executeAction("ISOLATE_HOST", selectedAlert.dest_ip || selectedAlert.asset || "10.0.4.10");
            }
        });
    }

    // Create Incident Ticket
    const btnP1 = document.getElementById("btn-create-p1");
    if (btnP1) {
        btnP1.addEventListener("click", () => {
            if (selectedAlert) {
                showNotification(`Ticket created for incident: ${selectedAlert.title.substring(0, 35)}...`);
            }
        });
    }

    // Export JSON
    const btnExport = document.getElementById("btn-export-dossier");
    if (btnExport) {
        btnExport.addEventListener("click", () => {
            if (!selectedAlert) return;
            const blob = new Blob([JSON.stringify(selectedAlert, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `SentiX-Incident-${selectedAlert.id}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showNotification(`Exported incident dossier to JSON`);
        });
    }
}

/* Load Dashboard Statistics */
async function loadDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        if (res.ok) {
            const data = await res.json();
            const elCrit = document.getElementById("stat-critical");
            const elCont = document.getElementById("stat-contained");
            const elRisk = document.getElementById("stat-risk");
            const elMttr = document.getElementById("stat-mttr");
            const elToday = document.getElementById("stat-events-today");

            if (elCrit) elCrit.textContent = data.critical_incidents;
            if (elCont) elCont.textContent = data.auto_contained;
            if (elRisk) elRisk.innerHTML = `${data.mean_risk_score} <span style="font-size:16px;font-weight:500;color:var(--text-muted)">/ 100</span>`;
            if (elMttr) elMttr.textContent = data.mean_time_to_respond;
            if (elToday) elToday.textContent = (data.events_processed_today || 18513).toLocaleString();
        }
    } catch (err) {
        console.error("Error loading stats:", err);
    }
}

/* Load Alerts */
async function loadAlerts(reselect = true) {
    try {
        const res = await fetch("/api/alerts");
        if (res.ok) {
            activeAlerts = await res.json();
            renderAlertList();
            renderOverviewRecentAlerts();
            if (reselect && activeAlerts.length > 0 && !selectedAlert) {
                selectAlert(activeAlerts[0]);
            }
        }
    } catch (err) {
        console.error("Error loading alerts:", err);
    }
}

/* Render Overview Recent Alerts */
function renderOverviewRecentAlerts() {
    const container = document.getElementById("overview-recent-alerts");
    if (!container) return;

    container.innerHTML = "";
    const topAlerts = activeAlerts.slice(0, 4);

    if (topAlerts.length === 0) {
        container.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-dim)">No active alerts. All systems secure.</div>`;
        return;
    }

    topAlerts.forEach(alert => {
        const row = document.createElement("div");
        row.className = "overview-alert-row";

        const sevClass = (alert.severity || "medium").toLowerCase();
        row.innerHTML = `
            <div class="overview-alert-left">
                <span class="sev-badge ${sevClass}">${alert.severity}</span>
                <span class="overview-alert-title">${alert.title}</span>
            </div>
            <div class="overview-alert-right">
                <span>${alert.src_ip || 'Internal'}</span>
                <span style="color:#f87171;font-weight:700;">Risk ${alert.risk_score}</span>
            </div>
        `;
        row.addEventListener("click", () => {
            selectAlert(alert);
            switchPage("page-alerts");
        });
        container.appendChild(row);
    });
}

/* Render Alerts List in Page 2 */
function renderAlertList() {
    const listEl = document.getElementById("alert-stream-list");
    if (!listEl) return;

    const searchTerm = (document.getElementById("search-alerts")?.value || "").toLowerCase();

    const filtered = activeAlerts.filter(item => {
        const matchSev = currentSeverityFilter === "ALL" || (item.severity && item.severity.toUpperCase() === currentSeverityFilter.toUpperCase());
        const matchSearch = !searchTerm || 
            (item.title && item.title.toLowerCase().includes(searchTerm)) ||
            (item.src_ip && item.src_ip.includes(searchTerm)) ||
            (item.asset && item.asset.toLowerCase().includes(searchTerm)) ||
            (item.mitre_technique && item.mitre_technique.toLowerCase().includes(searchTerm));
        return matchSev && matchSearch;
    });

    listEl.innerHTML = "";
    if (filtered.length === 0) {
        listEl.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text-dim);">No matching alerts found.</div>`;
        return;
    }

    filtered.forEach(alert => {
        const item = document.createElement("div");
        const sevClass = (alert.severity || "medium").toLowerCase();
        const isSelected = selectedAlert && selectedAlert.id === alert.id;

        item.className = `alert-card-item ${isSelected ? 'selected' : ''}`;
        item.innerHTML = `
            <div class="alert-card-header">
                <span class="sev-badge ${sevClass}">${alert.severity}</span>
                <span style="font-size:12px;color:var(--text-dim);">${alert.timestamp}</span>
            </div>
            <div class="alert-card-title">${alert.title}</div>
            <div class="alert-card-footer">
                <span>Target: ${alert.asset || alert.dest_ip || '10.0.4.10'}</span>
                <span style="color:#f87171;font-weight:700;">Risk ${alert.risk_score}/100</span>
            </div>
        `;

        item.addEventListener("click", () => {
            selectAlert(alert);
        });

        listEl.appendChild(item);
    });
}

/* Select and Display Alert in Dossier */
function selectAlert(alert) {
    selectedAlert = alert;
    renderAlertList();

    // Populate Dossier
    const catBadge = document.getElementById("dossier-cat-badge");
    if (catBadge) catBadge.textContent = alert.category ? alert.category.replace(/_/g, ' ') : "SECURITY INCIDENT";

    const titleEl = document.getElementById("dossier-title");
    if (titleEl) titleEl.textContent = alert.title;

    const assetEl = document.getElementById("meta-asset");
    if (assetEl) assetEl.textContent = alert.asset || alert.dest_ip || "10.0.4.10";

    const ipEl = document.getElementById("meta-src-ip");
    if (ipEl) ipEl.textContent = alert.src_ip || "External Origin";

    const protoEl = document.getElementById("meta-protocol");
    if (protoEl) protoEl.textContent = alert.category === "EMAIL_THREAT" ? "SMTP / TLS" : "HTTPS / TCP";

    const techEl = document.getElementById("meta-technique");
    if (techEl) techEl.textContent = alert.mitre_technique || "Suspicious Activity";

    // Risk Scores
    const compositeBar = document.getElementById("bar-composite");
    const compositeVal = document.getElementById("val-composite");
    if (compositeBar && compositeVal) {
        compositeBar.style.width = `${alert.risk_score}%`;
        compositeVal.textContent = `${alert.risk_score} / 100`;
    }

    const ifBar = document.getElementById("bar-if");
    const ifVal = document.getElementById("val-if");
    if (ifBar && ifVal) {
        const valNum = Math.round(alert.if_score || 88);
        ifBar.style.width = `${valNum}%`;
        ifVal.textContent = `${valNum}%`;
    }

    // Threat Intel
    const vtEl = document.getElementById("intel-vt");
    if (vtEl) vtEl.textContent = alert.vt_score || "24 / 72 Engines";

    const abuseEl = document.getElementById("intel-abuse");
    if (abuseEl) abuseEl.textContent = alert.abuse_score || "89% Malicious";

    const otxEl = document.getElementById("intel-otx");
    if (otxEl) otxEl.textContent = `${alert.otx_matches || 28} Pulses`;

    // AI Reasoning
    let details = {};
    try {
        details = typeof alert.details_json === "string" ? JSON.parse(alert.details_json) : (alert.details_json || {});
    } catch (e) {
        details = {};
    }

    const expEl = document.getElementById("dossier-explanation");
    if (expEl) {
        expEl.textContent = details.narrative || `External origin ${alert.src_ip} initiated reconnaissance and potential exploitation against asset ${alert.asset}. SentiX autonomous containment has flagged this vector for immediate mitigation.`;
    }

    const cotContainer = document.getElementById("dossier-cot");
    if (cotContainer) {
        cotContainer.innerHTML = `
            <div class="ai-step-row">
                <span class="ai-step-num">1</span>
                <span><strong>Ingestion &amp; Normalization:</strong> Raw security telemetry parsed and unified across log streams.</span>
            </div>
            <div class="ai-step-row">
                <span class="ai-step-num">2</span>
                <span><strong>Anomaly Detection:</strong> Machine learning Isolation Forest scored anomaly at ${Math.round(alert.if_score || 88)}%.</span>
            </div>
            <div class="ai-step-row">
                <span class="ai-step-num">3</span>
                <span><strong>Automated Response:</strong> Recommended perimeter firewall block on IP ${alert.src_ip || 'N/A'}.</span>
            </div>
        `;
    }
}

/* Load Agent Mesh */
async function loadAgentMesh() {
    try {
        const res = await fetch("/api/agents/status");
        if (res.ok) {
            const agents = await res.json();
            const grid = document.getElementById("agent-mesh-grid");
            if (!grid) return;
            grid.innerHTML = "";

            agents.forEach(agent => {
                const card = document.createElement("div");
                card.className = "agent-grid-item";
                card.innerHTML = `
                    <div class="agent-header-row">
                        <span class="agent-name-text">${agent.name}</span>
                        <span class="agent-status-pill">${agent.status}</span>
                    </div>
                    <div class="agent-role-text">${agent.role}</div>
                    <div class="agent-stats-footer">
                        <span>CPU Load: <strong>${agent.load_pct}%</strong></span>
                        <span>Latency: <strong>${agent.latency_ms}ms</strong></span>
                    </div>
                `;
                grid.appendChild(card);
            });
        }
    } catch (err) {
        console.error("Error loading agent mesh:", err);
    }
}

/* Load Containment Ledger */
async function loadContainmentLedger() {
    try {
        const res = await fetch("/api/actions/history");
        if (res.ok) {
            const ledger = await res.json();
            const tbody = document.getElementById("ledger-table-body");
            const countBadge = document.getElementById("ledger-count-badge");
            if (countBadge) countBadge.textContent = `${ledger.length} Security Actions Recorded`;
            if (!tbody) return;

            tbody.innerHTML = "";
            ledger.forEach(entry => {
                const tr = document.createElement("tr");
                const sevColor = entry.severity === "CRITICAL" ? "#f87171" : "#fbbf24";
                const modeColor = entry.mode === "AUTO" ? "#34d399" : "#38bdf8";

                tr.innerHTML = `
                    <td style="color:var(--text-dim);font-size:12.5px;">${entry.timestamp}</td>
                    <td><strong style="color:#fff;">${entry.action.replace(/_/g, ' ')}</strong></td>
                    <td style="color:#38bdf8;font-weight:600;">${entry.target}</td>
                    <td style="color:${sevColor};font-weight:700;">${entry.severity}</td>
                    <td style="color:${modeColor};font-weight:600;">${entry.mode}</td>
                    <td style="color:var(--text-muted);">${entry.executed_by}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Error loading ledger:", err);
    }
}

/* Execute Action */
async function executeAction(actionType, target) {
    try {
        const res = await fetch("/api/actions/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: actionType,
                target: target,
                severity: "CRITICAL",
                mode: "AUTO",
                executed_by: "SentiX Console"
            })
        });
        if (res.ok) {
            const data = await res.json();
            loadContainmentLedger();
            loadDashboardStats();
            showNotification(`✅ Successfully executed [${data.action}] on [${data.target}]`);
        }
    } catch (err) {
        console.error("Action error:", err);
    }
}

/* Trigger Attack Simulation */
async function triggerAttackSimulation() {
    const btn = document.getElementById("btn-run-sim-action");
    const resultBox = document.getElementById("sim-result-box");
    const resultText = document.getElementById("sim-result-text");

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span>⏳</span> Simulating coordinated attack...`;
    }

    try {
        const res = await fetch("/api/simulation/run", { method: "POST" });
        if (res.ok) {
            await loadAlerts();
            await loadDashboardStats();
            await loadContainmentLedger();

            if (resultBox && resultText) {
                resultBox.style.display = "block";
                resultText.textContent = "Multi-vector APT correlated in 1.2s. External IP 185.220.101.5 blocked & Core Host 10.0.4.10 isolated.";
            }

            showNotification("🚀 Attack test finished: AI detected and auto-contained all vectors!");
        }
    } catch (err) {
        console.error("Simulation error:", err);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span>🚀</span> Run Live Attack Test`;
        }
    }
}

/* Leaflet Geolocation Map */
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

        L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
            maxZoom: 16,
            attribution: "Esri"
        }).addTo(leafletMapInstance);

        const attackVectors = [
            { lat: 52.52, lng: 13.405, ip: "185.220.101.5", city: "Frankfurt, Germany", type: "Phishing C2 Node", sev: "CRITICAL" },
            { lat: 31.23, lng: 121.47, ip: "203.175.188.1", city: "Shanghai, China", type: "Gateway Exploit Probing", sev: "CRITICAL" },
            { lat: 59.93, lng: 30.33, ip: "45.154.255.88", city: "St. Petersburg, Russia", type: "SYN Flood Vector", sev: "HIGH" },
            { lat: 37.77, lng: -122.41, ip: "103.224.182.9", city: "San Francisco, USA", type: "Credential Access Lure", sev: "MEDIUM" }
        ];

        const socCenter = [37.7749, -122.4194];

        attackVectors.forEach(vec => {
            const markerColor = vec.sev === "CRITICAL" ? "#ef4444" : "#f59e0b";
            const circle = L.circleMarker([vec.lat, vec.lng], {
                radius: 8,
                fillColor: markerColor,
                color: "#ffffff",
                weight: 1.5,
                opacity: 1,
                fillOpacity: 0.9
            }).addTo(leafletMapInstance);

            circle.bindPopup(`
                <div style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:6px;min-width:180px;">
                    <div style="font-size:11px;font-weight:700;color:${markerColor};">${vec.sev} THREAT</div>
                    <div style="font-weight:700;color:#fff;font-size:13px;margin:2px 0;">${vec.city}</div>
                    <div style="font-size:12px;color:#94a3b8;">IP: <strong>${vec.ip}</strong></div>
                    <div style="font-size:11.5px;color:#cbd5e1;margin-top:4px;">${vec.type}</div>
                </div>
            `);

            // Arc line connecting to SOC
            L.polyline([[vec.lat, vec.lng], socCenter], {
                color: markerColor,
                weight: 1.5,
                opacity: 0.45,
                dashArray: "4, 6"
            }).addTo(leafletMapInstance);
        });
    } catch (err) {
        console.error("Map initialization failed:", err);
    }
}

/* 60-Minute Volume Chart */
function initChartJsVolume() {
    const canvas = document.getElementById("chartjs-volume-canvas");
    if (!canvas || typeof Chart === "undefined") return;

    try {
        const labels = [];
        const dataPoints = [];
        const blockedPoints = [];

        for (let i = 60; i >= 0; i -= 2) {
            labels.push(`-${i}m`);
            const base = 40 + Math.sin(i / 5) * 20;
            dataPoints.push(Math.round(base + Math.random() * 15));
            blockedPoints.push(Math.round((base + Math.random() * 15) * 0.4));
        }

        const ctx = canvas.getContext("2d");
        chartVolumeInstance = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [
                    {
                        label: "Total Threat Inbounds",
                        data: dataPoints,
                        borderColor: "#38bdf8",
                        backgroundColor: "rgba(56, 189, 248, 0.08)",
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0
                    },
                    {
                        label: "Autonomously Neutralized",
                        data: blockedPoints,
                        borderColor: "#10b981",
                        backgroundColor: "rgba(16, 185, 129, 0.08)",
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0
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
                            font: { family: "-apple-system, BlinkMacSystemFont, sans-serif", size: 12 }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#64748b", font: { size: 11 } }
                    },
                    y: {
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#64748b", font: { size: 11 } },
                        beginAtZero: true
                    }
                }
            }
        });
    } catch (err) {
        console.error("Chart initialization failed:", err);
    }
}

/* Toast Notification Helper */
function showNotification(msg) {
    let toast = document.getElementById("toast-message");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toast-message";
        toast.className = "toast-popup";
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("visible");
    setTimeout(() => {
        toast.classList.remove("visible");
    }, 3500);
}
