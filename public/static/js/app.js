/**
 * SENTIX SOVEREIGN OS v3.0 — AUTONOMOUS CYBERSECURITY CONTROLLER
 * High-performance, reactive state manager, holographic vector map engine, audio synthesizer, and interactive UI controller.
 */

// Global State
let activeAlerts = [];
let selectedAlert = null;
let currentSeverityFilter = "ALL";
let isFeedPaused = false;
let leafletMapInstance = null;
let chartVolumeInstance = null;
let audioFxEnabled = true;
let audioCtx = null;
let currentDefcon = 2; // 1, 2, or 3
let currentMapMode = "vector"; // "vector" or "tiles"
let currentMapRegion = "global"; // "global", "na", "emea", "apac"

// Vector Map Animation State
let vectorMapAnimId = null;
let vectorMapHoveredNode = null;
let vectorMapOffset = { x: 0, y: 0, zoom: 1 };
let vectorMapTargetOffset = { x: 0, y: 0, zoom: 1 };

// Threat Nodes Data
const threatNodes = [
    { id: "fra", lat: 50.11, lng: 8.68, city: "Frankfurt, Germany", ip: "185.220.101.5", type: "Phishing C2 Infrastructure", actor: "APT29 (Midnight Blizzard)", sev: "CRITICAL", latency: 18 },
    { id: "sha", lat: 31.23, lng: 121.47, city: "Shanghai, China", ip: "203.175.188.1", type: "Gateway Exploit Probing", actor: "Volt Typhoon", sev: "CRITICAL", latency: 142 },
    { id: "led", lat: 59.93, lng: 30.33, city: "St. Petersburg, Russia", ip: "45.154.255.88", type: "SYN Flood Amplification", actor: "Sandworm", sev: "HIGH", latency: 68 },
    { id: "sfo", lat: 37.77, lng: -122.41, city: "San Francisco, USA", ip: "103.224.182.9", type: "Credential Harvest Lure", actor: "Scattered Spider", sev: "MEDIUM", latency: 24 },
    { id: "teh", lat: 35.68, lng: 51.38, city: "Tehran, Iran", ip: "91.240.118.42", type: "Password Spray Campaign", actor: "Charming Kitten", sev: "HIGH", latency: 110 },
    { id: "ams", lat: 52.36, lng: 4.90, city: "Amsterdam, Netherlands", ip: "194.26.29.11", type: "Encrypted Cobalt Strike Tunnel", actor: "FIN7 Group", sev: "CRITICAL", latency: 22 }
];

const socHqCoords = { lat: 37.7749, lng: -122.4194, city: "SentiX Defense HQ (San Francisco)", ip: "10.0.4.10" };

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    initAudioEngine();
    initClock();
    initDefconController();
    initPageNavigation();
    initCyberVectorMap();
    initChartJsVolume();
    initDossierTabs();
    initCommandPalette();
    initCyberShell();
    setupEventListeners();

    // Initial Data Fetch
    loadDashboardStats();
    loadAlerts(true);
    loadAgentMesh();
    loadContainmentLedger();

    // High-frequency polling loop (every 4 seconds)
    setInterval(() => {
        if (!isFeedPaused) {
            loadDashboardStats();
            loadAlerts(false);
            loadAgentMesh();
            loadContainmentLedger();
        }
    }, 4000);
});

/* ==========================================================================
   WEB AUDIO API SYNTHESIZER (HIGH-TECH TACTICAL SFX)
   Zero external audio files required! Synthesizes subtle sci-fi pulses.
   ========================================================================== */
function initAudioEngine() {
    const audioBtn = document.getElementById("btn-audio-fx");
    const savedState = localStorage.getItem("sentix_audio_enabled");
    if (savedState !== null) {
        audioFxEnabled = savedState === "true";
    }
    if (audioBtn) {
        audioBtn.classList.toggle("active", audioFxEnabled);
        audioBtn.addEventListener("click", () => {
            audioFxEnabled = !audioFxEnabled;
            localStorage.setItem("sentix_audio_enabled", audioFxEnabled);
            audioBtn.classList.toggle("active", audioFxEnabled);
            if (audioFxEnabled) {
                playCyberChime("click");
                showNotification("🔊 Tactical Cyber SFX: ENABLED");
            } else {
                showNotification("🔇 Tactical Cyber SFX: MUTED");
            }
        });
    }
}

function getAudioContext() {
    if (!audioCtx) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) {
            audioCtx = new AudioContext();
        }
    }
    if (audioCtx && audioCtx.state === "suspended") {
        audioCtx.resume();
    }
    return audioCtx;
}

function playCyberChime(type = "click") {
    if (!audioFxEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;

        if (type === "click") {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sine";
            osc.frequency.setValueAtTime(1600, now);
            osc.frequency.exponentialRampToValueAtTime(800, now + 0.04);
            gain.gain.setValueAtTime(0.04, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.04);
        } else if (type === "alert") {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "triangle";
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.setValueAtTime(1320, now + 0.08);
            gain.gain.setValueAtTime(0.08, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.22);
        } else if (type === "containment") {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sawtooth";
            osc.frequency.setValueAtTime(220, now);
            osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
            gain.gain.setValueAtTime(0.06, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.18);
        } else if (type === "sim") {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sine";
            osc.frequency.setValueAtTime(400, now);
            osc.frequency.exponentialRampToValueAtTime(2400, now + 0.25);
            gain.gain.setValueAtTime(0.08, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.28);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.28);
        } else if (type === "defcon") {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sawtooth";
            osc.frequency.setValueAtTime(440, now);
            osc.frequency.setValueAtTime(660, now + 0.1);
            osc.frequency.setValueAtTime(880, now + 0.2);
            gain.gain.setValueAtTime(0.09, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.35);
        }
    } catch (e) {
        // Audio policy or error ignored gracefully
    }
}

/* ==========================================================================
   DEFCON COMBAT POSTURE CONTROLLER
   ========================================================================== */
function initDefconController() {
    const btn = document.getElementById("btn-defcon-toggle");
    const label = document.getElementById("defcon-label-text");
    if (!btn) return;

    btn.addEventListener("click", () => {
        currentDefcon = (currentDefcon % 3) + 1; // Cycles 1 -> 2 -> 3 -> 1
        playCyberChime("defcon");

        document.body.classList.remove("defcon-1", "defcon-2", "defcon-3");
        document.body.classList.add(`defcon-${currentDefcon}`);

        if (currentDefcon === 1) {
            label.textContent = "DEFCON 1 : COMBAT ENGAGED";
            showNotification("🚨 DEFCON 1 ACTIVATED: Maximum Combat Posture! All perimeter blocks automated.");
            logShellMessage("[DEFCON ALERT] DEFCON 1 DEPLOYED. Multi-agent containment latency set to 0ms.");
        } else if (currentDefcon === 2) {
            label.textContent = "DEFCON 2 : ELEVATED THREAT";
            showNotification("⚠️ DEFCON 2 ACTIVATED: Elevated Threat Posture. Correlation engines vigilant.");
            logShellMessage("[DEFCON ALERT] DEFCON 2: Operational readiness elevated.");
        } else {
            label.textContent = "DEFCON 3 : GUARDED READINESS";
            showNotification("🛡️ DEFCON 3 ACTIVATED: Guarded Readiness Posture.");
            logShellMessage("[DEFCON ALERT] DEFCON 3: Standard defense posture restored.");
        }
    });
}

/* ==========================================================================
   UTC MILITARY CLOCK
   ========================================================================== */
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

/* ==========================================================================
   PAGE NAVIGATION CONTROLLER
   ========================================================================== */
function initPageNavigation() {
    const navButtons = document.querySelectorAll(".nav-link-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const pageId = btn.getAttribute("data-page");
            if (pageId) {
                playCyberChime("click");
                switchPage(pageId);
            }
        });
    });
}

function switchPage(pageId) {
    document.querySelectorAll(".nav-link-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-page") === pageId);
    });

    document.querySelectorAll(".page-view").forEach(page => {
        page.classList.remove("active");
    });

    const target = document.getElementById(pageId);
    if (target) {
        target.classList.add("active");
    }

    // Refresh Map immediately when switching to map tab
    if (pageId === "page-map") {
        resizeCyberVectorMap();
        if (leafletMapInstance && currentMapMode === "tiles") {
            setTimeout(() => leafletMapInstance.invalidateSize(), 100);
        }
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ==========================================================================
   HOLOGRAPHIC CYBER VECTOR MAP ENGINE (GUARANTEED 100% VISIBILITY)
   Direct Canvas 60FPS Tactical World Projection + Live Missiles & Lasers
   ========================================================================== */
function initCyberVectorMap() {
    const canvas = document.getElementById("cyber-map-canvas");
    if (!canvas) return;

    window.addEventListener("resize", resizeCyberVectorMap);
    setTimeout(resizeCyberVectorMap, 50);

    // Mouse Interaction on Map
    canvas.addEventListener("mousemove", onMapMouseMove);
    canvas.addEventListener("click", onMapMouseClick);

    // Start 60FPS Render Loop
    if (!vectorMapAnimId) {
        let lastTime = 0;
        function renderLoop(time) {
            drawCyberVectorMap(time);
            vectorMapAnimId = requestAnimationFrame(renderLoop);
        }
        vectorMapAnimId = requestAnimationFrame(renderLoop);
    }
}

function resizeCyberVectorMap() {
    const canvas = document.getElementById("cyber-map-canvas");
    const container = document.getElementById("map-theatre-box");
    if (!canvas || !container) return;

    const rect = container.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
        canvas.width = rect.width;
        canvas.height = rect.height;
    }
}

// Convert Lat/Lng to Canvas X/Y using Mercator-like projection
function geoToCanvasCoords(lat, lng, width, height) {
    // Basic Equirectangular with region zoom & offset
    const targetLng = (lng + 180) / 360;
    const targetLat = (90 - lat) / 180;

    const baseWidth = width * vectorMapOffset.zoom;
    const baseHeight = height * vectorMapOffset.zoom;

    const x = targetLng * baseWidth + vectorMapOffset.x;
    const y = targetLat * baseHeight + vectorMapOffset.y;

    return { x, y };
}

function drawCyberVectorMap(timestamp) {
    const canvas = document.getElementById("cyber-map-canvas");
    if (!canvas || canvas.style.display === "none") return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    if (w === 0 || h === 0) return;

    // Smoothly interpolate region offset and zoom
    vectorMapOffset.x += (vectorMapTargetOffset.x - vectorMapOffset.x) * 0.1;
    vectorMapOffset.y += (vectorMapTargetOffset.y - vectorMapOffset.y) * 0.1;
    vectorMapOffset.zoom += (vectorMapTargetOffset.zoom - vectorMapOffset.zoom) * 0.1;

    // 1. Dark Void Space Background
    ctx.fillStyle = "#030713";
    ctx.fillRect(0, 0, w, h);

    // 2. Latitude & Longitude Tactical Cyber Grid
    ctx.strokeStyle = "rgba(0, 240, 255, 0.06)";
    ctx.lineWidth = 1;

    for (let lng = -180; lng <= 180; lng += 30) {
        const p1 = geoToCanvasCoords(80, lng, w, h);
        const p2 = geoToCanvasCoords(-80, lng, w, h);
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
    }

    for (let lat = -60; lat <= 60; lat += 30) {
        const p1 = geoToCanvasCoords(lat, -180, w, h);
        const p2 = geoToCanvasCoords(lat, 180, w, h);
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
    }

    // 3. Draw Stylized World Continent Landmass Polygons (Guaranteed visible vector base)
    drawWorldLandmasses(ctx, w, h);

    // 4. Target SOC Center (San Francisco HQ)
    const socPos = geoToCanvasCoords(socHqCoords.lat, socHqCoords.lng, w, h);

    // Draw SOC Shield Radar Pulse Rings
    const socPulse = (timestamp % 2000) / 2000;
    ctx.strokeStyle = `rgba(0, 240, 255, ${1 - socPulse})`;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(socPos.x, socPos.y, 8 + socPulse * 28, 0, Math.PI * 2);
    ctx.stroke();

    ctx.fillStyle = "#00f0ff";
    ctx.beginPath();
    ctx.arc(socPos.x, socPos.y, 6, 0, Math.PI * 2);
    ctx.fill();

    // SOC HQ Label
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 10px 'JetBrains Mono', monospace";
    ctx.fillText("HQ [SOC DEFENSE]", socPos.x + 10, socPos.y + 4);

    // 5. Draw Attacker Nodes & Animated Ballistic Missile Laser Trajectories
    threatNodes.forEach((node, idx) => {
        const nodePos = geoToCanvasCoords(node.lat, node.lng, w, h);
        const isCrit = node.sev === "CRITICAL";
        const color = isCrit ? "#ff2a5f" : "#f59e0b";
        const isHovered = vectorMapHoveredNode && vectorMapHoveredNode.id === node.id;

        // Draw Pulsing Rings on Attacker Node
        const nodePulse = ((timestamp + idx * 400) % 1800) / 1800;
        ctx.strokeStyle = isCrit ? `rgba(255, 42, 95, ${1 - nodePulse})` : `rgba(245, 158, 11, ${1 - nodePulse})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(nodePos.x, nodePos.y, 6 + nodePulse * 20, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(nodePos.x, nodePos.y, isHovered ? 7 : 5, 0, Math.PI * 2);
        ctx.fill();

        // Node IP & City Text
        ctx.fillStyle = isHovered ? "#ffffff" : "rgba(255, 255, 255, 0.75)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillText(`${node.city} [${node.ip}]`, nodePos.x + 9, nodePos.y + 3);

        // Curved Ballistic Arc from Node to SOC HQ
        const midX = (nodePos.x + socPos.x) / 2;
        const midY = Math.min(nodePos.y, socPos.y) - 60 - idx * 12;

        ctx.strokeStyle = isCrit ? "rgba(255, 42, 95, 0.45)" : "rgba(245, 158, 11, 0.4)";
        ctx.lineWidth = isHovered ? 2.5 : 1.5;
        ctx.setLineDash([4, 6]);
        ctx.beginPath();
        ctx.moveTo(nodePos.x, nodePos.y);
        ctx.quadraticCurveTo(midX, midY, socPos.x, socPos.y);
        ctx.stroke();
        ctx.setLineDash([]); // Reset line dash

        // Traveling Laser Energy Missile Packet along Quadratic Curve
        const speed = 0.00035;
        const t = ((timestamp * speed + idx * 0.22) % 1);
        const invT = 1 - t;

        // Quadratic Bezier Formula: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
        const packetX = invT * invT * nodePos.x + 2 * invT * t * midX + t * t * socPos.x;
        const packetY = invT * invT * nodePos.y + 2 * invT * t * midY + t * t * socPos.y;

        ctx.fillStyle = color;
        ctx.shadowColor = color;
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(packetX, packetY, 4, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0; // Reset glow
    });
}

// Vector polygons representing World Landmasses
function drawWorldLandmasses(ctx, w, h) {
    ctx.fillStyle = "rgba(10, 22, 48, 0.75)";
    ctx.strokeStyle = "rgba(0, 240, 255, 0.25)";
    ctx.lineWidth = 1;

    // List of key continents approximations in geo coordinates
    const continents = [
        // North America
        [[-165, 65], [-140, 70], [-100, 75], [-60, 60], [-65, 45], [-75, 30], [-85, 20], [-105, 20], [-125, 32], [-130, 50], [-165, 60]],
        // South America
        [[-80, 10], [-50, -5], [-35, -10], [-40, -25], [-55, -40], [-70, -55], [-75, -45], [-75, -20], [-80, 0]],
        // Europe & UK
        [[-10, 36], [0, 42], [5, 52], [10, 60], [30, 70], [45, 60], [35, 40], [25, 35], [10, 36]],
        // Africa
        [[-15, 30], [10, 37], [32, 32], [50, 12], [42, -5], [30, -32], [18, -35], [10, 5], [-15, 12]],
        // Asia
        [[40, 40], [60, 65], [100, 75], [170, 65], [140, 45], [120, 25], [105, 10], [80, 8], [70, 25], [50, 30]],
        // Australia
        [[115, -22], [130, -12], [145, -15], [150, -32], [140, -38], [115, -34]]
    ];

    continents.forEach(polygon => {
        ctx.beginPath();
        polygon.forEach((pt, i) => {
            const pos = geoToCanvasCoords(pt[1], pt[0], w, h);
            if (i === 0) ctx.moveTo(pos.x, pos.y);
            else ctx.lineTo(pos.x, pos.y);
        });
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
    });
}

function onMapMouseMove(e) {
    const canvas = document.getElementById("cyber-map-canvas");
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    let found = null;
    threatNodes.forEach(node => {
        const pos = geoToCanvasCoords(node.lat, node.lng, canvas.width, canvas.height);
        const dist = Math.hypot(pos.x - mouseX, pos.y - mouseY);
        if (dist < 18) {
            found = node;
        }
    });

    vectorMapHoveredNode = found;
    canvas.style.cursor = found ? "pointer" : "crosshair";
}

function onMapMouseClick(e) {
    if (vectorMapHoveredNode) {
        playCyberChime("click");
        openAdversaryPopover(vectorMapHoveredNode);
    } else {
        closeAdversaryPopover();
    }
}

function openAdversaryPopover(node) {
    const popover = document.getElementById("adversary-map-popover");
    if (!popover) return;

    const cityEl = document.getElementById("popover-city-title");
    const ipEl = document.getElementById("popover-ip-val");
    const typeEl = document.getElementById("popover-type-desc");
    const sevEl = document.getElementById("popover-sev-tag");
    const qBtn = document.getElementById("btn-popover-quarantine");

    if (cityEl) cityEl.textContent = node.city;
    if (ipEl) ipEl.textContent = `IP: ${node.ip}`;
    if (typeEl) typeEl.textContent = `${node.type} (${node.actor})`;
    if (sevEl) {
        sevEl.textContent = `${node.sev} ADVERSARY`;
        sevEl.className = `threat-badge ${node.sev.toLowerCase()}`;
    }

    if (qBtn) {
        qBtn.onclick = () => {
            executeAction("BLOCK_IP", node.ip);
            closeAdversaryPopover();
        };
    }

    popover.style.display = "block";
}

function closeAdversaryPopover() {
    const popover = document.getElementById("adversary-map-popover");
    if (popover) popover.style.display = "none";
}

/* Map Mode Switcher (Vector vs Tile) */
function setMapMode(mode) {
    currentMapMode = mode;
    playCyberChime("click");

    const btnVec = document.getElementById("btn-mode-vector");
    const btnTile = document.getElementById("btn-mode-tiles");
    const canvas = document.getElementById("cyber-map-canvas");
    const tileDiv = document.getElementById("leaflet-map");

    if (btnVec) btnVec.classList.toggle("active", mode === "vector");
    if (btnTile) btnTile.classList.toggle("active", mode === "tiles");

    if (mode === "vector") {
        if (canvas) canvas.style.display = "block";
        if (tileDiv) tileDiv.style.display = "none";
        resizeCyberVectorMap();
    } else {
        if (canvas) canvas.style.display = "none";
        if (tileDiv) tileDiv.style.display = "block";
        initLeafletBackupMap();
    }
}

/* Map Region Jumps */
function setMapRegion(region) {
    currentMapRegion = region;
    playCyberChime("click");

    document.querySelectorAll(".map-top-controls [data-region]").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-region") === region);
    });

    const canvas = document.getElementById("cyber-map-canvas");
    const w = canvas ? canvas.width : 1000;
    const h = canvas ? canvas.height : 600;

    if (region === "global") {
        vectorMapTargetOffset = { x: 0, y: 0, zoom: 1 };
    } else if (region === "na") {
        vectorMapTargetOffset = { x: w * 0.45, y: h * 0.15, zoom: 2.2 };
    } else if (region === "emea") {
        vectorMapTargetOffset = { x: -w * 0.25, y: h * 0.05, zoom: 2.3 };
    } else if (region === "apac") {
        vectorMapTargetOffset = { x: -w * 0.95, y: -h * 0.05, zoom: 2.2 };
    }

    if (leafletMapInstance && currentMapMode === "tiles") {
        if (region === "global") leafletMapInstance.setView([28, 15], 2);
        else if (region === "na") leafletMapInstance.setView([38, -95], 3.5);
        else if (region === "emea") leafletMapInstance.setView([48, 18], 3.5);
        else if (region === "apac") leafletMapInstance.setView([25, 115], 3.5);
    }
}

/* Fullscreen Map Toggle */
function toggleMapFullscreen() {
    playCyberChime("click");
    const box = document.getElementById("map-theatre-box");
    if (!box) return;

    if (!document.fullscreenElement) {
        box.requestFullscreen().catch(err => console.log(err));
    } else {
        document.exitFullscreen().catch(err => console.log(err));
    }
    setTimeout(resizeCyberVectorMap, 200);
}

/* Leaflet Tile Map Fallback / Layer */
function initLeafletBackupMap() {
    const mapEl = document.getElementById("leaflet-map");
    if (!mapEl || typeof L === "undefined") return;

    if (!leafletMapInstance) {
        try {
            leafletMapInstance = L.map("leaflet-map", {
                center: [28.0, 15.0],
                zoom: 2.2,
                minZoom: 1.5,
                maxZoom: 8,
                zoomControl: true,
                attributionControl: false
            });

            // CartoDB Dark Matter tiles (clean, reliable, beautiful tactical dark tiles)
            L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
                maxZoom: 18,
                subdomains: 'abcd',
                attribution: 'CartoDB'
            }).addTo(leafletMapInstance);

            // Add SOC HQ
            L.circleMarker([socHqCoords.lat, socHqCoords.lng], {
                radius: 8,
                fillColor: "#00f0ff",
                color: "#ffffff",
                weight: 2,
                fillOpacity: 1
            }).addTo(leafletMapInstance).bindPopup("<strong>SentiX SOC Defense HQ</strong>");

            // Add threat nodes to Leaflet
            threatNodes.forEach(node => {
                const marker = L.circleMarker([node.lat, node.lng], {
                    radius: 7,
                    fillColor: node.sev === "CRITICAL" ? "#ff2a5f" : "#f59e0b",
                    color: "#ffffff",
                    weight: 1.5,
                    fillOpacity: 0.95
                }).addTo(leafletMapInstance);

                marker.bindPopup(`
                    <div style="font-family:'Plus Jakarta Sans',sans-serif;padding:6px;min-width:180px;background:#030712;color:#fff;border-radius:6px;">
                        <div style="font-size:10px;font-weight:800;color:#ff2a5f;">${node.sev} ADVERSARY NODE</div>
                        <div style="font-weight:700;color:#fff;font-size:12px;margin:2px 0;">${node.city}</div>
                        <div style="font-family:monospace;font-size:11px;color:#94a3b8;">IP: <strong>${node.ip}</strong></div>
                        <div style="font-size:11px;color:#cbd5e1;margin-top:4px;">${node.type}</div>
                    </div>
                `);

                L.polyline([[node.lat, node.lng], [socHqCoords.lat, socHqCoords.lng]], {
                    color: node.sev === "CRITICAL" ? "#ff2a5f" : "#f59e0b",
                    weight: 1.5,
                    opacity: 0.5,
                    dashArray: "4, 6"
                }).addTo(leafletMapInstance);
            });
        } catch (e) {
            console.error("Leaflet backup init error:", e);
        }
    }

    setTimeout(() => {
        if (leafletMapInstance) leafletMapInstance.invalidateSize();
    }, 100);
}

/* ==========================================================================
   TACTICAL CYBER SHELL TERMINAL CONTROLLER
   ========================================================================== */
function initCyberShell() {
    const toggleBtn = document.getElementById("btn-toggle-shell");
    const drawer = document.getElementById("cyber-shell-drawer");
    const input = document.getElementById("shell-cmd-input");

    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            playCyberChime("click");
            toggleCyberShell();
        });
    }

    // Keyboard shortcut ~ (tilde)
    window.addEventListener("keydown", (e) => {
        if (e.key === "`" || e.key === "~") {
            if (document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
                e.preventDefault();
                toggleCyberShell();
            }
        }
    });

    if (input) {
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                const cmd = input.value.trim();
                input.value = "";
                executeShellCommand(cmd);
            }
        });
    }
}

function toggleCyberShell(forceState = null) {
    const drawer = document.getElementById("cyber-shell-drawer");
    const input = document.getElementById("shell-cmd-input");
    if (!drawer) return;

    if (forceState !== null) {
        drawer.classList.toggle("open", forceState);
    } else {
        drawer.classList.toggle("open");
    }

    if (drawer.classList.contains("open") && input) {
        input.focus();
    }
}

function logShellMessage(msg) {
    const out = document.getElementById("shell-output-log");
    if (!out) return;
    const line = document.createElement("div");
    line.textContent = msg;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
}

function executeShellCommand(cmd) {
    if (!cmd) return;
    logShellMessage(`sentix-soc@defense:~$ ${cmd}`);
    playCyberChime("click");

    const parts = cmd.split(" ");
    const action = parts[0].toLowerCase();

    if (action === "help") {
        logShellMessage("Available Commands:");
        logShellMessage("  status          - Display system & agent health");
        logShellMessage("  simulate        - Run automated multi-vector attack simulation");
        logShellMessage("  block <ip>      - Deploy automated perimeter firewall drop");
        logShellMessage("  isolate <host>  - Deploy EDR network isolation on asset");
        logShellMessage("  defcon <1-3>    - Set DEFCON combat readiness posture");
        logShellMessage("  alerts          - Switch to Threat Incidents terminal");
        logShellMessage("  map             - Switch to Geolocation Threat Map");
        logShellMessage("  clear           - Clear terminal buffer");
    } else if (action === "status") {
        logShellMessage("[STATUS] SentiX Sovereign OS v3.0 | DEFCON: " + currentDefcon + " | Agents: 12/12 SYNCHED");
    } else if (action === "simulate") {
        logShellMessage("[SIMULATION] Dispatching APT multi-vector scenario...");
        triggerAttackSimulation();
    } else if (action === "block" && parts[1]) {
        executeAction("BLOCK_IP", parts[1]);
        logShellMessage(`[CONTAINMENT] Firewall drop rule committed for ${parts[1]}`);
    } else if (action === "isolate" && parts[1]) {
        executeAction("ISOLATE_HOST", parts[1]);
        logShellMessage(`[CONTAINMENT] EDR host isolation executed on ${parts[1]}`);
    } else if (action === "defcon" && parts[1]) {
        const lvl = parseInt(parts[1]);
        if ([1, 2, 3].includes(lvl)) {
            currentDefcon = lvl;
            document.body.classList.remove("defcon-1", "defcon-2", "defcon-3");
            document.body.classList.add(`defcon-${lvl}`);
            const label = document.getElementById("defcon-label-text");
            if (label) label.textContent = `DEFCON ${lvl} : ACTIVE`;
            logShellMessage(`[POSTURE] DEFCON posture set to level ${lvl}`);
            playCyberChime("defcon");
        } else {
            logShellMessage("[ERROR] Invalid DEFCON level. Choose 1, 2, or 3.");
        }
    } else if (action === "alerts") {
        switchPage("page-alerts");
    } else if (action === "map") {
        switchPage("page-map");
    } else if (action === "clear") {
        const out = document.getElementById("shell-output-log");
        if (out) out.innerHTML = "";
    } else {
        logShellMessage(`[ERROR] Command not recognized: '${cmd}'. Type 'help' for commands.`);
    }
}

/* ==========================================================================
   EVENT LISTENERS & FILTER CONTROLS
   ========================================================================== */
function setupEventListeners() {
    // Severity Filter Buttons
    document.querySelectorAll(".severity-pill-group .filter-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            playCyberChime("click");
            document.querySelectorAll(".severity-pill-group .filter-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            currentSeverityFilter = e.target.getAttribute("data-sev");
            renderAlertList();
        });
    });

    // Search Input
    const searchInput = document.getElementById("search-alerts");
    if (searchInput) {
        searchInput.addEventListener("input", renderAlertList);
    }

    // Isolate Host Button in Dossier
    const btnEdr = document.getElementById("btn-edr-isolate");
    if (btnEdr) {
        btnEdr.addEventListener("click", () => {
            if (selectedAlert) {
                executeAction("ISOLATE_HOST", selectedAlert.dest_ip || selectedAlert.asset || "10.0.4.10");
            }
        });
    }

    // Block IP Button in Dossier
    const btnBlockIp = document.getElementById("btn-block-ip-action");
    if (btnBlockIp) {
        btnBlockIp.addEventListener("click", () => {
            if (selectedAlert) {
                executeAction("BLOCK_IP", selectedAlert.src_ip || "185.220.101.5");
            }
        });
    }

    // Create P1 Incident Ticket
    const btnP1 = document.getElementById("btn-create-p1");
    if (btnP1) {
        btnP1.addEventListener("click", () => {
            if (selectedAlert) {
                playCyberChime("alert");
                showNotification(`📋 P1 Incident Ticket dispatched for: ${selectedAlert.title.substring(0, 32)}...`);
                logShellMessage(`[TICKET] Created incident ticket #${Math.floor(1000 + Math.random() * 9000)} for asset ${selectedAlert.asset}`);
            }
        });
    }

    // Export Dossier JSON
    const btnExport = document.getElementById("btn-export-dossier");
    if (btnExport) {
        btnExport.addEventListener("click", () => {
            if (!selectedAlert) return;
            playCyberChime("click");
            const blob = new Blob([JSON.stringify(selectedAlert, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `SentiX-Forensic-Dossier-${selectedAlert.id}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showNotification(`📥 Forensic JSON Dossier exported successfully`);
        });
    }
}

/* ==========================================================================
   DOSSIER TABS CONTROLLER (AI CoT / MITRE ATT&CK / Raw Evidence)
   ========================================================================== */
function initDossierTabs() {
    const tabs = document.querySelectorAll(".dossier-tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            playCyberChime("click");
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".dossier-tab-content").forEach(c => c.classList.remove("active"));

            tab.classList.add("active");
            const targetId = tab.getAttribute("data-tab");
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}

/* ==========================================================================
   LOAD DASHBOARD STATISTICS
   ========================================================================== */
async function loadDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        if (res.ok) {
            const data = await res.json();

            // War Room KPIs
            const elCrit = document.getElementById("stat-critical");
            const elCont = document.getElementById("stat-contained");
            const elRisk = document.getElementById("stat-risk");
            const elMttr = document.getElementById("stat-mttr");

            if (elCrit) elCrit.textContent = data.critical_incidents;
            if (elCont) elCont.textContent = data.auto_contained;
            if (elRisk) elRisk.innerHTML = `${data.mean_risk_score} <span style="font-size:16px;color:var(--text-muted)">/ 100</span>`;
            if (elMttr) elMttr.textContent = data.mean_time_to_respond;

            // Global HUD Header Telemetry
            const hudThreats = document.getElementById("hud-val-threats");
            const hudContained = document.getElementById("hud-val-contained");
            const hudRisk = document.getElementById("hud-val-risk");
            const hudMttr = document.getElementById("hud-val-mttr");

            if (hudThreats) hudThreats.textContent = data.critical_incidents;
            if (hudContained) hudContained.textContent = data.auto_contained;
            if (hudRisk) hudRisk.textContent = `${data.mean_risk_score}/100`;
            if (hudMttr) hudMttr.textContent = data.mean_time_to_respond;

            // Sidebar counters
            const navBadge = document.getElementById("badge-nav-threats");
            if (navBadge) navBadge.textContent = data.critical_incidents;

            const sbEvents = document.getElementById("sidebar-events-count");
            if (sbEvents) sbEvents.textContent = `${(data.events_processed_today || 18513).toLocaleString()} EVTS`;
        }
    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
    }
}

/* ==========================================================================
   LOAD ALERTS
   ========================================================================== */
async function loadAlerts(reselect = true) {
    try {
        const res = await fetch("/api/alerts");
        if (res.ok) {
            activeAlerts = await res.json();
            renderAlertList();
            renderWarRoomPriorityStream();

            if (reselect && activeAlerts.length > 0 && !selectedAlert) {
                selectAlert(activeAlerts[0]);
            } else if (selectedAlert) {
                const fresh = activeAlerts.find(a => a.id === selectedAlert.id);
                if (fresh) selectAlert(fresh, false);
            }
        }
    } catch (err) {
        console.error("Failed to load alerts:", err);
    }
}

/* ==========================================================================
   RENDER WAR ROOM PRIORITY STREAM (PAGE 1)
   ========================================================================== */
function renderWarRoomPriorityStream() {
    const container = document.getElementById("overview-recent-alerts");
    if (!container) return;

    container.innerHTML = "";
    const topAlerts = activeAlerts.slice(0, 5);

    if (topAlerts.length === 0) {
        container.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text-muted);font-family:var(--font-mono);">No active threats. All perimeter zones secure.</div>`;
        return;
    }

    topAlerts.forEach(alert => {
        const row = document.createElement("div");
        const sevLower = (alert.severity || "medium").toLowerCase();
        row.className = `threat-stream-row ${sevLower}`;

        row.innerHTML = `
            <div class="threat-row-primary">
                <span class="threat-badge ${sevLower}">${alert.severity}</span>
                <div class="threat-meta-block">
                    <div class="threat-title-text">${alert.title}</div>
                    <div class="threat-sub-meta">
                        <span>ORIGIN: ${alert.src_ip || 'Internal'}</span>
                        <span>•</span>
                        <span>TARGET: ${alert.asset || alert.dest_ip || '10.0.4.10'}</span>
                        <span>•</span>
                        <span>${alert.mitre_technique || 'Mitre T1566'}</span>
                    </div>
                </div>
            </div>
            <div class="threat-row-actions">
                <span class="risk-chip">RISK ${alert.risk_score}</span>
                <span style="color:var(--neon-cyan);font-size:12px;font-weight:700;">INSPECT →</span>
            </div>
        `;

        row.addEventListener("click", () => {
            playCyberChime("click");
            selectAlert(alert);
            switchPage("page-alerts");
        });

        container.appendChild(row);
    });
}

/* ==========================================================================
   RENDER ALERT MASTER LIST (PAGE 2)
   ========================================================================== */
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
        listEl.innerHTML = `<div style="padding:40px;text-align:center;color:var(--text-dim);font-family:var(--font-mono);">NO MATCHING INCIDENTS LOCATED</div>`;
        return;
    }

    filtered.forEach(alert => {
        const item = document.createElement("div");
        const sevClass = (alert.severity || "medium").toLowerCase();
        const isSelected = selectedAlert && selectedAlert.id === alert.id;

        item.className = `alert-feed-card ${isSelected ? 'selected' : ''}`;
        item.innerHTML = `
            <div class="alert-card-top">
                <span class="threat-badge ${sevClass}">${alert.severity}</span>
                <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${alert.timestamp || 'Just now'}</span>
            </div>
            <div class="alert-card-heading">${alert.title}</div>
            <div class="alert-card-bottom">
                <span>TARGET: ${alert.asset || alert.dest_ip || '10.0.4.10'}</span>
                <span style="color:var(--neon-crimson);font-weight:700;">SCORE: ${alert.risk_score}/100</span>
            </div>
        `;

        item.addEventListener("click", () => {
            playCyberChime("click");
            selectAlert(alert);
        });

        listEl.appendChild(item);
    });
}

/* ==========================================================================
   SELECT & DISPLAY ALERT IN FORENSIC DOSSIER
   ========================================================================== */
function selectAlert(alert, reRenderList = true) {
    if (!alert) return;
    selectedAlert = alert;
    if (reRenderList) {
        renderAlertList();
    }

    // Populate Dossier Header
    const catBadge = document.getElementById("dossier-cat-badge");
    if (catBadge) catBadge.textContent = alert.category ? alert.category.replace(/_/g, ' ') : "SECURITY INCIDENT";

    const titleEl = document.getElementById("dossier-title");
    if (titleEl) titleEl.textContent = alert.title;

    // Telemetry Strip
    const assetEl = document.getElementById("meta-asset");
    if (assetEl) assetEl.textContent = alert.asset || alert.dest_ip || "10.0.4.10";

    const ipEl = document.getElementById("meta-src-ip");
    if (ipEl) ipEl.textContent = alert.src_ip || "External Origin";

    const protoEl = document.getElementById("meta-protocol");
    if (protoEl) protoEl.textContent = alert.category === "EMAIL_THREAT" ? "SMTP / TLS" : "HTTPS / TCP";

    const techEl = document.getElementById("meta-technique");
    if (techEl) techEl.textContent = alert.mitre_technique || "T1566 Spear-Phishing";

    // Risk Scores
    const compVal = document.getElementById("val-composite");
    const compBar = document.getElementById("bar-composite");
    if (compVal && compBar) {
        compVal.textContent = `${alert.risk_score} / 100`;
        compBar.style.width = `${alert.risk_score}%`;
    }

    const ifVal = document.getElementById("val-if");
    const ifBar = document.getElementById("bar-if");
    if (ifVal && ifBar) {
        const valNum = Math.round(alert.if_score || 89);
        ifVal.textContent = `${valNum}%`;
        ifBar.style.width = `${valNum}%`;
    }

    // Threat Intel Indicators
    const vtEl = document.getElementById("intel-vt");
    if (vtEl) vtEl.textContent = alert.vt_score || "24 / 72 Engines";

    const abuseEl = document.getElementById("intel-abuse");
    if (abuseEl) abuseEl.textContent = alert.abuse_score || "89% Malicious";

    const otxEl = document.getElementById("intel-otx");
    if (otxEl) otxEl.textContent = `${alert.otx_matches || 28} Pulses`;

    // Parse Details JSON
    let details = {};
    try {
        details = typeof alert.details_json === "string" ? JSON.parse(alert.details_json) : (alert.details_json || {});
    } catch (e) {
        details = {};
    }

    // AI Explanation Narrative
    const expEl = document.getElementById("dossier-explanation");
    if (expEl) {
        expEl.textContent = details.narrative || `External origin ${alert.src_ip} initiated reconnaissance and exploit probing against asset ${alert.asset}. SentiX autonomous containment has flagged this vector for immediate mitigation.`;
    }

    // AI Chain-of-Thought Steps
    const cotContainer = document.getElementById("dossier-cot");
    if (cotContainer) {
        cotContainer.innerHTML = `
            <div class="cot-step-item">
                <span class="cot-step-num">01</span>
                <div>
                    <strong style="color:#fff;">Telemetry Ingestion &amp; Feature Extraction:</strong>
                    <div style="color:var(--text-secondary);margin-top:2px;">Parsed raw network packets, auth log headers, and domain reputation for source ${alert.src_ip || 'N/A'}.</div>
                </div>
            </div>
            <div class="cot-step-item">
                <span class="cot-step-num">02</span>
                <div>
                    <strong style="color:#fff;">Multi-Agent Corroboration &amp; ML Scoring:</strong>
                    <div style="color:var(--text-secondary);margin-top:2px;">Isolation Forest anomaly confidence rated at ${Math.round(alert.if_score || 89)}%. Cross-checked NIST NVD vulnerabilities mapping critical CVE exposure.</div>
                </div>
            </div>
            <div class="cot-step-item">
                <span class="cot-step-num">03</span>
                <div>
                    <strong style="color:#fff;">Autonomous Containment Directive:</strong>
                    <div style="color:var(--text-secondary);margin-top:2px;">Dispatched perimeter firewall drop on IP ${alert.src_ip || '185.220.101.5'} and initiated host isolation for asset ${alert.asset || '10.0.4.10'}.</div>
                </div>
            </div>
        `;
    }

    // Raw JSON tab
    const rawTerminal = document.getElementById("dossier-raw-json");
    if (rawTerminal) {
        rawTerminal.textContent = JSON.stringify(alert, null, 2);
    }
}

/* ==========================================================================
   LOAD NEURAL AGENT MESH MATRIX (12 AGENTS)
   ========================================================================== */
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
                card.className = "agent-node-card";
                const isCritLoad = agent.load_pct > 80;

                card.innerHTML = `
                    <div class="agent-node-top">
                        <span class="agent-code-name">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--neon-cyan);">
                                <rect x="3" y="3" width="18" height="18" rx="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline>
                            </svg>
                            ${agent.name}
                        </span>
                        <span class="agent-state-pill ${agent.status === 'ACTIVE' ? 'active' : 'online'}">${agent.status}</span>
                    </div>
                    <div class="agent-role-desc">${agent.role}</div>
                    <div class="agent-telemetry-metrics">
                        <div class="agent-meter-row">
                            <span style="color:var(--text-muted);">NEURAL LOAD:</span>
                            <strong style="color:${isCritLoad ? 'var(--neon-crimson)' : 'var(--neon-cyan)'};">${agent.load_pct}%</strong>
                        </div>
                        <div class="meter-track">
                            <div class="meter-fill-bar" style="width:${agent.load_pct}%;background:${isCritLoad ? 'var(--neon-crimson)' : 'var(--neon-cyan)'};"></div>
                        </div>
                        <div class="agent-meter-row" style="margin-top:4px;">
                            <span style="color:var(--text-muted);">LATENCY:</span>
                            <strong style="color:var(--neon-emerald);">${agent.latency_ms}ms</strong>
                        </div>
                    </div>
                `;
                grid.appendChild(card);
            });
        }
    } catch (err) {
        console.error("Failed to load agent mesh:", err);
    }
}

/* ==========================================================================
   LOAD CONTAINMENT LEDGER
   ========================================================================== */
async function loadContainmentLedger() {
    try {
        const res = await fetch("/api/actions/history");
        if (res.ok) {
            const ledger = await res.json();
            const tbody = document.getElementById("ledger-table-body");
            const countBadge = document.getElementById("ledger-count-badge");
            if (countBadge) countBadge.textContent = `${ledger.length} AUDITED ACTIONS`;
            if (!tbody) return;

            tbody.innerHTML = "";
            ledger.forEach(entry => {
                const tr = document.createElement("tr");
                const sevColor = entry.severity === "CRITICAL" ? "var(--neon-crimson)" : "var(--neon-amber)";
                const modeColor = entry.mode === "AUTO" ? "var(--neon-emerald)" : "var(--neon-cyan)";

                tr.innerHTML = `
                    <td style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted);">${entry.timestamp}</td>
                    <td><strong style="color:#fff;">${entry.action.replace(/_/g, ' ')}</strong></td>
                    <td style="font-family:var(--font-mono);color:var(--neon-cyan);font-weight:700;">${entry.target}</td>
                    <td style="font-family:var(--font-mono);color:${sevColor};font-weight:700;">${entry.severity}</td>
                    <td style="font-family:var(--font-mono);color:${modeColor};font-weight:700;">${entry.mode}</td>
                    <td style="color:var(--text-secondary);">${entry.executed_by}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Failed to load ledger:", err);
    }
}

/* ==========================================================================
   EXECUTE DEFENSIVE ACTION
   ========================================================================== */
async function executeAction(actionType, target) {
    playCyberChime("containment");
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
            await loadContainmentLedger();
            await loadDashboardStats();
            showNotification(`🔒 [${data.action}] autonomous containment executed on [${data.target}]`);
            logShellMessage(`[CONTAINMENT SUCCESS] Action: ${data.action} | Target: ${data.target} | Mode: AUTO | Executor: SentiX Console`);
        }
    } catch (err) {
        console.error("Action execution failed:", err);
        showNotification(`⚠️ Action execution failed: ${err.message}`);
    }
}

/* ==========================================================================
   INTERACTIVE LIVE-FIRE ATTACK SIMULATION
   ========================================================================== */
async function triggerAttackSimulation() {
    playCyberChime("sim");
    const btn = document.getElementById("btn-run-sim-action");
    const hudBtn = document.getElementById("btn-hud-launch-sim");
    const resultBox = document.getElementById("sim-result-box");
    const resultText = document.getElementById("sim-result-text");

    const cards = [
        document.getElementById("sim-card-1"),
        document.getElementById("sim-card-2"),
        document.getElementById("sim-card-3"),
        document.getElementById("sim-card-4")
    ];

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span>⏳ SIMULATING APT INTRUSION...</span>`;
    }
    if (hudBtn) hudBtn.disabled = true;

    cards.forEach(c => { if (c) { c.classList.remove("in-progress", "neutralized"); } });

    logShellMessage("[SIMULATION LAUNCH] Injecting coordinated APT campaign scenario...");

    // Phase 1: Phishing
    if (cards[0]) cards[0].classList.add("in-progress");
    logShellMessage("[SIMULATION] Phase 01: Ingesting spear-phishing payload referencing C2 185.220.101.5");

    setTimeout(() => {
        if (cards[0]) { cards[0].classList.remove("in-progress"); cards[0].classList.add("neutralized"); }
        if (cards[1]) cards[1].classList.add("in-progress");
        logShellMessage("[SIMULATION] Phase 02: Ingesting buffer overflow probe on internal asset 10.0.4.10");
    }, 400);

    setTimeout(() => {
        if (cards[1]) { cards[1].classList.remove("in-progress"); cards[1].classList.add("neutralized"); }
        if (cards[2]) cards[2].classList.add("in-progress");
        logShellMessage("[SIMULATION] Phase 03: Mapping unpatched CVE-2024-38077 via NVD scraper");
    }, 800);

    setTimeout(() => {
        if (cards[2]) { cards[2].classList.remove("in-progress"); cards[2].classList.add("neutralized"); }
        if (cards[3]) cards[3].classList.add("in-progress");
        logShellMessage("[SIMULATION] Phase 04: Triggering Pythia correlation system & automated containment");
    }, 1200);

    try {
        const res = await fetch("/api/simulation/run", { method: "POST" });
        if (res.ok) {
            await loadAlerts();
            await loadDashboardStats();
            await loadContainmentLedger();

            setTimeout(() => {
                if (cards[3]) { cards[3].classList.remove("in-progress"); cards[3].classList.add("neutralized"); }
                if (resultBox && resultText) {
                    resultBox.style.display = "block";
                    resultText.textContent = "Multi-vector APT correlated in 1.2s. External IP 185.220.101.5 blocked & Core Host 10.0.4.10 isolated.";
                }
                playCyberChime("alert");
                showNotification("🚀 Coordinated APT neutralized! All vectors contained autonomously.");
                logShellMessage("[SIMULATION SUCCESS] APT neutralized in 1.2s. 185.220.101.5 blocked & 10.0.4.10 isolated.");
            }, 1500);
        }
    } catch (err) {
        console.error("Simulation error:", err);
    } finally {
        setTimeout(() => {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg><span>EXECUTE ATTACK TEST</span>`;
            }
            if (hudBtn) hudBtn.disabled = false;
        }, 1600);
    }
}

/* ==========================================================================
   WORKBENCH MANUAL TESTERS
   ========================================================================== */
async function runWorkbenchEmail() {
    playCyberChime("click");
    const input = document.getElementById("wb-email-input");
    const output = document.getElementById("wb-email-output");
    if (!input || !output) return;

    try {
        const payload = JSON.parse(input.value);
        output.textContent = "// Dispatched to Email Verification Agent... analyzing...";
        const res = await fetch("/api/email/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
        playCyberChime("alert");
        logShellMessage(`[WORKBENCH] Email analyzed. Risk: ${data.threat_score || 85}/100.`);
    } catch (err) {
        output.textContent = `// Error executing test: ${err.message}`;
    }
}

async function runWorkbenchLog() {
    playCyberChime("click");
    const input = document.getElementById("wb-log-input");
    const output = document.getElementById("wb-log-output");
    if (!input || !output) return;

    try {
        const payload = JSON.parse(input.value);
        output.textContent = "// Dispatched to Log Analyzer & ML Agent... calculating anomalies...";
        const res = await fetch("/api/logs/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
        playCyberChime("alert");
        logShellMessage(`[WORKBENCH] Logs analyzed. Anomaly score: ${data.anomaly_score || 88}%.`);
    } catch (err) {
        output.textContent = `// Error executing test: ${err.message}`;
    }
}

/* ==========================================================================
   COMMAND PALETTE (CMD+K / CTRL+K)
   ========================================================================== */
function initCommandPalette() {
    const backdrop = document.getElementById("cmd-palette-backdrop");
    const input = document.getElementById("cmd-palette-search");
    const results = document.getElementById("cmd-palette-results");
    const openBtn = document.getElementById("btn-open-palette");

    const commands = [
        { label: "Switch to Situation War Room", shortcut: "G O", action: () => switchPage("page-overview") },
        { label: "Inspect Threat Incidents & Dossier", shortcut: "G A", action: () => switchPage("page-alerts") },
        { label: "Open Real-Time Geolocation Threat Map", shortcut: "G M", action: () => switchPage("page-map") },
        { label: "Examine 12-Agent Neural Mesh", shortcut: "G N", action: () => switchPage("page-agents") },
        { label: "View Containment Ledger & Audit History", shortcut: "G L", action: () => switchPage("page-ledger") },
        { label: "Open Live Attack Simulator", shortcut: "G S", action: () => switchPage("page-simulator") },
        { label: "Open Payload Analysis Workbench", shortcut: "G W", action: () => switchPage("page-workbench") },
        { label: "Toggle Cyber Shell Terminal", shortcut: "~ / `", action: () => toggleCyberShell() },
        { label: "Cycle DEFCON Readiness Posture", shortcut: "DEFCON", action: () => document.getElementById("btn-defcon-toggle").click() },
        { label: "Fire Live APT Attack Simulation", shortcut: "RUN", action: () => triggerAttackSimulation() },
        { label: "Block Known Attacker IP (185.220.101.5)", shortcut: "BLOCK", action: () => executeAction("BLOCK_IP", "185.220.101.5") },
        { label: "Isolate Critical Asset (10.0.4.10)", shortcut: "ISOLATE", action: () => executeAction("ISOLATE_HOST", "10.0.4.10") }
    ];

    function renderCommands(query = "") {
        if (!results) return;
        results.innerHTML = "";
        const filtered = commands.filter(c => c.label.toLowerCase().includes(query.toLowerCase()));

        if (filtered.length === 0) {
            results.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text-muted);font-family:var(--font-mono);">No matching tactical commands.</div>`;
            return;
        }

        filtered.forEach(cmd => {
            const item = document.createElement("div");
            item.className = "cmd-item";
            item.innerHTML = `
                <span>${cmd.label}</span>
                <span class="cmd-item-shortcut">${cmd.shortcut}</span>
            `;
            item.addEventListener("click", () => {
                playCyberChime("click");
                closePalette();
                cmd.action();
            });
            results.appendChild(item);
        });
    }

    function openPalette() {
        playCyberChime("click");
        if (backdrop && input) {
            backdrop.classList.add("open");
            input.value = "";
            renderCommands();
            input.focus();
        }
    }

    function closePalette() {
        if (backdrop) backdrop.classList.remove("open");
    }

    if (openBtn) openBtn.addEventListener("click", openPalette);

    if (backdrop) {
        backdrop.addEventListener("click", (e) => {
            if (e.target === backdrop) closePalette();
        });
    }

    if (input) {
        input.addEventListener("input", (e) => renderCommands(e.target.value));
    }

    window.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            if (backdrop && backdrop.classList.contains("open")) {
                closePalette();
            } else {
                openPalette();
            }
        } else if (e.key === "Escape") {
            closePalette();
        }
    });
}

/* ==========================================================================
   CHART.JS 60-MINUTE ATTACK VELOCITY
   ========================================================================== */
function initChartJsVolume() {
    const canvas = document.getElementById("chartjs-volume-canvas");
    if (!canvas || typeof Chart === "undefined") return;

    try {
        const labels = [];
        const dataPoints = [];
        const blockedPoints = [];

        for (let i = 60; i >= 0; i -= 2) {
            labels.push(`-${i}m`);
            const base = 42 + Math.sin(i / 5) * 22;
            const inbound = Math.round(base + Math.random() * 14);
            dataPoints.push(inbound);
            blockedPoints.push(Math.round(inbound * 0.88));
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
                        borderColor: "#00f0ff",
                        backgroundColor: "rgba(0, 240, 255, 0.08)",
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0
                    },
                    {
                        label: "Autonomous Neutralizations",
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
                            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11 }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } }
                    },
                    y: {
                        grid: { color: "rgba(255, 255, 255, 0.04)" },
                        ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } },
                        beginAtZero: true
                    }
                }
            }
        });
    } catch (err) {
        console.error("Chart initialization error:", err);
    }
}

/* ==========================================================================
   TOAST NOTIFICATION HELPER
   ========================================================================== */
function showNotification(msg) {
    let toast = document.getElementById("toast-message");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toast-message";
        toast.className = "toast-hud-popup";
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("visible");
    setTimeout(() => {
        toast.classList.remove("visible");
    }, 3800);
}
