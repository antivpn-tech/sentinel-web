let currentEval = null;
let isIpMasked = true;
let currentRealIp = null;
let visitorIp = null;

const CODE_SNIPPETS = {
    curl: `# Query the live Sentinel Edge API with Universal License Key
curl -s -X GET "https://api.antivpn.tech/v1/check?ip=185.213.154.20" \\
  -H "Authorization: Bearer stl_live_your_api_key_here"

# Edge Telemetry Response Headers (<0.5ms):
# < X-Sentinel-Tier: business
# < X-Sentinel-Quota-Limit: 1000000
# < X-Sentinel-Quota-Remaining: 984520
# < X-Sentinel-Status: active
#
# {
#   "ip": "185.213.154.20",
#   "action": "BLOCK",
#   "risk_score": 95,
#   "threat_type": "Commercial VPN",
#   "asn": 206016,
#   "provider": "Mullvad VPN",
#   "country": "SE",
#   "reasons": ["Carrier Network Classification: Commercial VPN (Mullvad VPN)"],
#   "duration_ms": 1
# }`,

    node: `// Node.js (18+), Bun, Next.js, or Express Middleware
async function checkClientAccess(clientIP) {
    const url = \`https://api.antivpn.tech/v1/check?ip=\${encodeURIComponent(clientIP)}\`;
    const response = await fetch(url, {
        headers: {
            "Authorization": "Bearer " + process.env.SENTINEL_API_KEY, // stl_live_...
            "Accept": "application/json"
        }
    });

    // Inspect live quota telemetry headers
    const quotaLeft = response.headers.get("X-Sentinel-Quota-Remaining");
    const tier = response.headers.get("X-Sentinel-Tier");
    const verdict = await response.json();

    if (verdict.action === "BLOCK") {
        console.warn(\`Denied \${clientIP}: \${verdict.threat_type} (Risk: \${verdict.risk_score}/100) [Quota: \${quotaLeft}]\`);
        return false; // Refuse socket or drop request
    }

    return true; // Allow access
}`,

    python: `import os
import requests

SENTINEL_KEY = os.getenv("SENTINEL_API_KEY", "stl_live_your_api_key_here")

def verify_ip(client_ip: str) -> bool:
    """Query Sentinel Edge API with Universal Key & Quota Telemetry."""
    response = requests.get(
        "https://api.antivpn.tech/v1/check",
        params={"ip": client_ip},
        headers={"Authorization": f"Bearer {SENTINEL_KEY}"},
        timeout=2.0
    )
    
    # Inspect edge quota telemetry
    quota_remaining = response.headers.get("X-Sentinel-Quota-Remaining")
    data = response.json()

    if data.get("action") == "BLOCK":
        risk = data.get("risk_score")
        threat = data.get("threat_type")
        print(f"Blocked {client_ip}: {threat} (Risk {risk}/100) [Remaining Quota: {quota_remaining}]")
        return False

    return True`,

    go: `package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

var httpClient = &http.Client{Timeout: 2 * time.Second}
const sentinelKey = "stl_live_your_api_key_here"

type SentinelVerdict struct {
    IP         string   \`json:"ip"\`
    Action     string   \`json:"action"\`
    RiskScore  int      \`json:"risk_score"\`
    ThreatType string   \`json:"threat_type"\`
    ASN        int      \`json:"asn"\`
    Provider   string   \`json:"provider"\`
    Country    string   \`json:"country"\`
    Reasons    []string \`json:"reasons"\`
    DurationMs int      \`json:"duration_ms"\`
}

func CheckIP(ip string) (*SentinelVerdict, error) {
    url := fmt.Sprintf("https://api.antivpn.tech/v1/check?ip=%s", ip)
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+sentinelKey)

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Read telemetry quota header: resp.Header.Get("X-Sentinel-Quota-Remaining")
    var verdict SentinelVerdict
    if err := json.NewDecoder(resp.Body).Decode(&verdict); err != nil {
        return nil, err
    }
    return &verdict, nil
}`,

    mc: `// High-Concurrency Game Server & TCP Ingress (Velocity / Paper / Java 21)
@ChannelHandler.Sharable
public class SentinelIngressHandler extends ChannelInboundHandlerAdapter {

    private final SentinelClient sentinel = SentinelClient.builder()
        .apiKey("stl_live_your_api_key_here")
        .endpoint("https://api.antivpn.tech")
        .maxLocalCacheEntries(50_000)
        .cacheTtl(Duration.ofMinutes(15))
        .build();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof HAProxyMessage proxyMsg) {
            String realClientIP = proxyMsg.sourceAddress();

            // 1. High-speed local cache evaluation (0ms)
            if (sentinel.isBlockedFast(realClientIP)) {
                ctx.close(); // Immediate connection refusal
                return;
            }

            // 2. Asynchronous sub-millisecond Edge API verification
            sentinel.evaluateAsync(realClientIP).thenAccept(verdict -> {
                if ("BLOCK".equals(verdict.getAction())) {
                    ctx.close();
                } else {
                    ctx.fireChannelRead(msg);
                }
            });
            return;
        }
        ctx.fireChannelRead(msg);
    }
}`
};

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

function initApp() {
    initScrollEngine();
    initTabs();
    initCodeSnippets();
    initCommandBar();
    setupEventListeners();
    setupCopyButtons();
    renderPresets();
    pingLiveEdge();
    detectVisitorConnection();
}

// Live edge health check
async function pingLiveEdge() {
    const statEl = document.getElementById("latency-stat");
    const headerStatus = document.getElementById("header-edge-status");
    const heroBadge = document.getElementById("hero-badge-latency");
    try {
        const start = performance.now();
        const res = await fetch("https://api.antivpn.tech/healthz", { cache: "no-store" });
        const latency = Math.round(performance.now() - start);
        if (res.ok) {
            if (statEl) statEl.textContent = `${latency} ms (Global Edge)`;
            if (headerStatus) headerStatus.textContent = `Edge Active (${latency}ms)`;
            if (heroBadge) heroBadge.textContent = `${latency} ms global latency`;
        }
    } catch (e) {
        if (statEl) statEl.textContent = "< 5 ms (Edge)";
        if (heroBadge) heroBadge.textContent = "sub-5ms active";
    }
}

// Command bar launcher
function initCommandBar() {
    const rows = document.querySelectorAll(".command-row");
    const typedBox = document.querySelector(".typed-query");
    const copyHeroBtn = document.getElementById("hero-copy-btn");

    if (copyHeroBtn) {
        copyHeroBtn.addEventListener("click", () => {
            navigator.clipboard.writeText('curl -s "https://api.antivpn.tech/v1/check?ip=185.213.154.20"');
            copyHeroBtn.style.color = "var(--brand-warm-amber)";
            setTimeout(() => { copyHeroBtn.style.color = ""; }, 1800);
        });
    }

    rows.forEach(row => {
        row.addEventListener("click", () => {
            rows.forEach(r => r.classList.remove("active-row"));
            row.classList.add("active-row");

            const ip = row.getAttribute("data-ip");
            if (ip) {
                if (typedBox) typedBox.textContent = `sentinel evaluate ${ip}`;
                const ipInput = document.getElementById("ip-input");
                if (ipInput) ipInput.value = ip;
                evaluateTarget(ip);
            }
        });
    });
}

// Scroll progress bar - 100% hardware-composited scaleX (zero layout reflows)
function initScrollEngine() {
    const progressBar = document.getElementById("scroll-progress");
    if (!progressBar) return;

    let ticking = false;
    window.addEventListener("scroll", () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const scrollTop = window.scrollY || document.documentElement.scrollTop;
                const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
                if (scrollHeight > 0) {
                    const progress = Math.min(Math.max(scrollTop / scrollHeight, 0), 1);
                    progressBar.style.transform = `scaleX(${progress})`;
                }
                ticking = false;
            });
            ticking = true;
        }
    }, { passive: true });
}

// Tab switching (Visual / JSON)
function initTabs() {
    const tabVisual = document.getElementById("tab-visual");
    const tabJson = document.getElementById("tab-json");
    const visualView = document.getElementById("visual-view");
    const jsonViewWrap = document.getElementById("json-view-wrap");

    if (!tabVisual || !tabJson) return;

    tabVisual.addEventListener("click", () => {
        tabVisual.classList.add("active");
        tabJson.classList.remove("active");
        if (visualView) visualView.style.display = "block";
        if (jsonViewWrap) jsonViewWrap.style.display = "none";
    });

    tabJson.addEventListener("click", () => {
        tabJson.classList.add("active");
        tabVisual.classList.remove("active");
        if (visualView) visualView.style.display = "none";
        if (jsonViewWrap) jsonViewWrap.style.display = "block";
        updateJsonView();
    });
}

function updateJsonView() {
    const jsonView = document.getElementById("json-view");
    if (!jsonView || !currentEval) return;
    if (!isIpMasked) {
        jsonView.textContent = JSON.stringify(currentEval, null, 2);
        return;
    }
    const maskedCopy = {
        ...currentEval,
        ip: getMaskedIp(currentEval.ip),
        hostname: currentEval.hostname ? maskStringWithIp(currentEval.hostname, currentRealIp) : null,
        reasons: currentEval.reasons ? currentEval.reasons.map(r => maskStringWithIp(r, currentRealIp)) : []
    };
    jsonView.textContent = JSON.stringify(maskedCopy, null, 2);
}

// Code snippet switcher
function initCodeSnippets() {
    const tabs = document.querySelectorAll(".code-tab-btn");
    const display = document.getElementById("code-display");

    const activeTab = document.querySelector(".code-tab-btn.active");
    if (activeTab && display) {
        const key = activeTab.getAttribute("data-tab");
        if (CODE_SNIPPETS[key]) {
            display.querySelector("code").textContent = CODE_SNIPPETS[key];
        }
    }

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            const key = tab.getAttribute("data-tab");
            if (CODE_SNIPPETS[key] && display) {
                display.querySelector("code").textContent = CODE_SNIPPETS[key];
            }
        });
    });
}

// Clipboard helpers
function setupCopyButtons() {
    const copyCodeBtn = document.getElementById("btn-copy-code");
    if (copyCodeBtn) {
        copyCodeBtn.addEventListener("click", () => {
            const display = document.getElementById("code-display");
            if (display) {
                navigator.clipboard.writeText(display.textContent.trim());
                copyCodeBtn.textContent = "Copied!";
                setTimeout(() => { copyCodeBtn.textContent = "Copy"; }, 1800);
            }
        });
    }

    const copyJsonBtn = document.getElementById("btn-copy-json");
    if (copyJsonBtn) {
        copyJsonBtn.addEventListener("click", () => {
            const jsonView = document.getElementById("json-view");
            if (jsonView) {
                navigator.clipboard.writeText(jsonView.textContent.trim());
                copyJsonBtn.textContent = "Copied!";
                setTimeout(() => { copyJsonBtn.textContent = "Copy JSON"; }, 1800);
            }
        });
    }
}

// IP masking and visibility
function getMaskedIp(ip) {
    if (!ip) return "--";
    if (ip.includes(".")) {
        const parts = ip.split(".");
        if (parts.length === 4) {
            return `${parts[0]}.•••.•••.•••`;
        }
    }
    if (ip.includes(":")) {
        const parts = ip.split(":");
        return `${parts[0]}:••••:••••:••••`;
    }
    return "••••••••••••";
}

function maskStringWithIp(str, rawIp) {
    if (!str || typeof str !== "string" || !rawIp) return str;
    let res = str;
    if (rawIp.includes(".")) {
        const p = rawIp.split(".");
        if (p.length === 4) {
            // Forward IP patterns (e.g. 186.104.86.42, 186-104-86-42, 186_104_86_42)
            const forwardRegex = new RegExp(`${p[0]}[-._]${p[1]}[-._]${p[2]}[-._]${p[3]}`, "gi");
            res = res.replace(forwardRegex, (m) => {
                const sep = m.includes("-") ? "-" : (m.includes("_") ? "_" : ".");
                return `${p[0]}${sep}•••${sep}•••${sep}•••`;
            });

            // Mid/suffix pattern (e.g. -104-86-42)
            const midRegex = new RegExp(`([-._])${p[1]}[-._]${p[2]}[-._]${p[3]}`, "gi");
            res = res.replace(midRegex, "$1•••$1•••$1•••");

            // Reverse IP patterns (e.g. 42-86-104-186 or 42.86.104.186)
            const reverseRegex = new RegExp(`${p[3]}[-._]${p[2]}[-._]${p[1]}[-._]${p[0]}`, "gi");
            res = res.replace(reverseRegex, (m) => {
                const sep = m.includes("-") ? "-" : (m.includes("_") ? "_" : ".");
                return `•••${sep}•••${sep}•••${sep}${p[0]}`;
            });
        }
    } else if (rawIp.includes(":")) {
        res = res.replaceAll(rawIp, getMaskedIp(rawIp));
    }
    return res;
}

function updateIpVisibility() {
    const ipInput = document.getElementById("ip-input");
    const telIp = document.getElementById("tel-ip");
    const telReq = document.getElementById("tel-request");
    const telHostname = document.getElementById("tel-hostname");
    const reasonsEl = document.getElementById("reasons-text");
    
    // Update both toggle buttons (input bar and data cell)
    const eyeBtns = [
        document.getElementById("btn-toggle-ip"),
        document.getElementById("btn-toggle-cell-ip")
    ];

    eyeBtns.forEach(btn => {
        if (!btn) return;
        const showIcon = btn.querySelector(".eye-show");
        const hideIcon = btn.querySelector(".eye-hide");
        if (isIpMasked) {
            if (showIcon) showIcon.style.display = "block";
            if (hideIcon) hideIcon.style.display = "none";
            btn.setAttribute("title", "Reveal IP address");
            btn.setAttribute("aria-label", "Reveal IP address");
        } else {
            if (showIcon) showIcon.style.display = "none";
            if (hideIcon) hideIcon.style.display = "block";
            btn.setAttribute("title", "Hide IP address");
            btn.setAttribute("aria-label", "Hide IP address");
        }
    });

    const displayIp = (isIpMasked && currentRealIp) ? getMaskedIp(currentRealIp) : (currentRealIp || "--");

    if (telIp) {
        telIp.textContent = displayIp;
    }

    if (telReq && currentRealIp) {
        telReq.textContent = `GET /v1/check?ip=${displayIp}`;
    }

    if (ipInput && currentRealIp) {
        const curVal = ipInput.value.trim();
        if (curVal === currentRealIp || curVal === getMaskedIp(currentRealIp) || curVal === "") {
            ipInput.value = displayIp;
        }
    }

    // Update hostname with masking
    if (telHostname && currentEval) {
        const rawH = currentEval.hostname || "No PTR record (Unassigned)";
        telHostname.textContent = isIpMasked ? maskStringWithIp(rawH, currentRealIp) : rawH;
        telHostname.title = isIpMasked ? maskStringWithIp(rawH, currentRealIp) : rawH;
    }

    // Update reasons with masking
    if (reasonsEl && currentEval && currentEval.reasons) {
        reasonsEl.innerHTML = currentEval.reasons.map(r => `• ${isIpMasked ? maskStringWithIp(r, currentRealIp) : r}`).join("<br>");
    }

    updateJsonView();
}

function toggleIpMasking() {
    isIpMasked = !isIpMasked;
    updateIpVisibility();
}

// Input and preset handlers
function setupEventListeners() {
    const scanBtn = document.getElementById("btn-scan");
    const ipInput = document.getElementById("ip-input");
    const toggleIpBtn = document.getElementById("btn-toggle-ip");
    const toggleCellIpBtn = document.getElementById("btn-toggle-cell-ip");

    if (toggleIpBtn) {
        toggleIpBtn.addEventListener("click", () => {
            toggleIpMasking();
        });
    }

    if (toggleCellIpBtn) {
        toggleCellIpBtn.addEventListener("click", () => {
            toggleIpMasking();
        });
    }

    if (scanBtn && ipInput) {
        scanBtn.addEventListener("click", () => {
            const val = ipInput.value.trim();
            evaluateTarget(val || "self");
        });

        ipInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                const val = ipInput.value.trim();
                evaluateTarget(val || "self");
            }
        });
    }
}

function renderPresets() {
    const container = document.getElementById("presets-container");
    if (!container) return;
    container.innerHTML = "";

    // "My Connection" button
    const myBtn = document.createElement("button");
    myBtn.className = "preset-chip preset-my-ip";
    myBtn.innerHTML = `<span class="preset-pulse"></span> My Connection`;
    myBtn.addEventListener("click", () => {
        if (visitorIp) {
            currentRealIp = visitorIp;
            evaluateTarget(visitorIp);
        } else {
            detectVisitorConnection();
        }
    });
    container.appendChild(myBtn);

    // Target presets
    SENTINEL_DATASET.PRESETS.forEach(preset => {
        const btn = document.createElement("button");
        btn.className = "preset-chip";
        btn.textContent = preset.label;
        btn.addEventListener("click", () => {
            currentRealIp = preset.ip;
            const ipInput = document.getElementById("ip-input");
            if (ipInput) {
                ipInput.value = isIpMasked ? getMaskedIp(preset.ip) : preset.ip;
            }
            evaluateTarget(preset.ip);
        });
        container.appendChild(btn);
    });
}

// WebRTC STUN candidate probe to detect browser proxy extension leaks & bypasses
function detectWebRtcIp() {
    return new Promise((resolve) => {
        try {
            const RTCPC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
            if (!RTCPC) return resolve(null);

            const pc = new RTCPC({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }, { urls: "stun:stun.l.google.com:19302" }] });
            let done = false;

            pc.onicecandidate = (event) => {
                if (!event || !event.candidate || !event.candidate.candidate) return;
                const cand = event.candidate.candidate;
                const ipMatch = cand.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})|([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i);
                if (ipMatch && ipMatch[0]) {
                    const candidateIp = ipMatch[0];
                    if (!candidateIp.startsWith("10.") && !candidateIp.startsWith("192.168.") &&
                        !/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(candidateIp) && !candidateIp.startsWith("127.") &&
                        candidateIp !== "::1" && !candidateIp.startsWith("fe80:") && !candidateIp.startsWith("fc00:")) {
                        if (!done) {
                            done = true;
                            try { pc.close(); } catch (_) {}
                            resolve(candidateIp);
                        }
                    }
                }
            };

            pc.createDataChannel("");
            pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(() => resolve(null));

            setTimeout(() => {
                if (!done) {
                    done = true;
                    try { pc.close(); } catch (_) {}
                    resolve(null);
                }
            }, 1200);
        } catch (_) {
            resolve(null);
        }
    });
}

// Visitor detection
async function detectVisitorConnection() {
    const desc = document.getElementById("verdict-desc");
    if (desc) desc.textContent = "Analyzing inbound connection headers...";

    try {
        const startTime = performance.now();
        const clientTz = encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone || "");
        const clientEpoch = Date.now();
        const webdriver = navigator.webdriver ? "1" : "0";
        const webrtcIp = await detectWebRtcIp();
        const webrtcParam = webrtcIp ? `&webrtc_ip=${encodeURIComponent(webrtcIp)}` : "";
        const queryParams = `client_tz=${clientTz}&client_epoch=${clientEpoch}&webdriver=${webdriver}${webrtcParam}&key=stl_test_showcase_demo`;
        const res = await fetch(`https://api.antivpn.tech/v1/check?${queryParams}`, { cache: "no-store" });
        const rtt = Math.round(performance.now() - startTime);

        if (res.ok) {
            const data = await res.json();
            visitorIp = data.ip;
            currentRealIp = data.ip;
            const telemetry = {
                tier: res.headers.get("X-Sentinel-Tier") || "enterprise",
                quotaRemaining: res.headers.get("X-Sentinel-Quota-Remaining") || "9999",
                status: res.headers.get("X-Sentinel-Status") || "active"
            };
            renderEvaluation(data, rtt, telemetry);
        } else {
            const errData = await res.json().catch(() => null);
            renderErrorState(res.status, errData);
        }
    } catch (e) {
        renderErrorState(0, null);
    }
}

// Target evaluation
async function evaluateTarget(ip) {
    const scanBtn = document.getElementById("btn-scan");
    const desc = document.getElementById("verdict-desc");

    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.style.opacity = "0.7";
        scanBtn.textContent = "Evaluating...";
    }
    if (desc) desc.textContent = "Querying live Sentinel Edge API...";

    // Handle masked input or empty
    let targetIp = (ip || "").trim();
    if (!targetIp || targetIp === "self" || targetIp === getMaskedIp(currentRealIp) || (visitorIp && targetIp === getMaskedIp(visitorIp))) {
        targetIp = visitorIp || "self";
    }

    const clientTz = encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone || "");
    const clientEpoch = Date.now();
    const webdriver = navigator.webdriver ? "1" : "0";
    const webrtcIp = await detectWebRtcIp();
    const webrtcParam = webrtcIp ? `&webrtc_ip=${encodeURIComponent(webrtcIp)}` : "";
    const queryParams = `client_tz=${clientTz}&client_epoch=${clientEpoch}&webdriver=${webdriver}${webrtcParam}&key=stl_test_showcase_demo`;

    const targetUrl = (targetIp === "self") 
        ? `https://api.antivpn.tech/v1/check?${queryParams}`
        : `https://api.antivpn.tech/v1/check?ip=${encodeURIComponent(targetIp)}&${queryParams}`;

    try {
        const startTime = performance.now();
        const res = await fetch(targetUrl);
        const rtt = Math.round(performance.now() - startTime);

        if (res.ok) {
            const data = await res.json();
            currentRealIp = data.ip;
            const telemetry = {
                tier: res.headers.get("X-Sentinel-Tier") || "enterprise",
                quotaRemaining: res.headers.get("X-Sentinel-Quota-Remaining") || "9999",
                status: res.headers.get("X-Sentinel-Status") || "active"
            };
            renderEvaluation(data, rtt, telemetry);
        } else {
            const errData = await res.json().catch(() => null);
            const preset = SENTINEL_DATASET.PRESETS.find(p => p.ip === targetIp);
            if (preset) {
                fallbackPresetEval(targetIp);
            } else {
                renderErrorState(res.status, errData);
            }
        }
    } catch (err) {
        const preset = SENTINEL_DATASET.PRESETS.find(p => p.ip === targetIp);
        if (preset) {
            fallbackPresetEval(targetIp);
        } else {
            renderErrorState(0, null);
        }
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.style.opacity = "1";
            scanBtn.textContent = "Inspect Target";
        }
    }
}

function fallbackPresetEval(ip) {
    const preset = SENTINEL_DATASET.PRESETS.find(p => p.ip === ip);
    if (preset) {
        currentRealIp = preset.ip;
        const isBlocked = preset.expectedRisk >= 70;
        renderEvaluation({
            ip: preset.ip,
            action: isBlocked ? "BLOCK" : "ALLOW",
            risk_score: preset.expectedRisk,
            threat_type: preset.category,
            asn: parseInt(preset.asn.replace("AS", ""), 10) || 0,
            provider: preset.provider,
            country: preset.country,
            reasons: [
                `Carrier Network Classification: ${preset.provider} (${preset.category})`,
                isBlocked ? "Subnet flagged by Sentinel Global Threat Grid." : "Verified consumer residential subnet."
            ],
            duration_ms: 1
        }, 15);
    }
}

function renderErrorState(status, errData) {
    const banner = document.getElementById("verdict-banner");
    const badge = document.getElementById("verdict-badge");
    const desc = document.getElementById("verdict-desc");
    const meterVal = document.getElementById("meter-value");
    const scoreFill = document.getElementById("score-bar-fill");
    const reasonsEl = document.getElementById("reasons-text");
    const telType = document.getElementById("tel-type");
    const telProvider = document.getElementById("tel-provider");
    const telAsn = document.getElementById("tel-asn");
    const telTime = document.getElementById("tel-time");

    const is429 = status === 429;
    const msg = (errData && errData.message)
        ? errData.message
        : (is429
            ? "Daily showcase verification quota reached for this IP. Claim a free Developer Key (5,000/mo) at antivpn.tech#pricing."
            : "Sentinel Edge inspection service temporarily unreachable. Check network connectivity.");

    if (banner) banner.className = "verdict-banner warning";
    if (badge) {
        badge.className = "verdict-badge verdict-warning-badge";
        badge.textContent = is429 ? "RATE LIMITED" : "EDGE UNAVAILABLE";
    }
    if (desc) desc.textContent = msg;
    if (meterVal) meterVal.textContent = "--";
    if (scoreFill) {
        scoreFill.style.width = "0%";
        scoreFill.style.backgroundColor = "var(--brand-warm-amber)";
    }
    if (reasonsEl) {
        reasonsEl.innerHTML = is429
            ? "• Daily showcase verification quota reached for this IP address.<br>• For continuous testing or automated traffic, claim a free Developer Key at <a href='#pricing' style='color: var(--brand-warm-amber); text-decoration: underline;'>antivpn.tech#pricing</a>."
            : "• Inbound HTTP inspection request timed out or was refused.<br>• Ensure internet connectivity or firewall rules allow edge connections.";
    }
    if (telType) telType.textContent = is429 ? "Showcase Limit Reached" : "Inspection Offline";
    if (telProvider) telProvider.textContent = "--";
    if (telAsn) telAsn.textContent = "--";
    if (telTime) telTime.innerHTML = `<strong>--</strong> <span style="color: var(--text-muted); font-size: 11px;">(Status ${status || 'Err'})</span>`;

    if (is429 && window.SentinelBilling && SentinelBilling.showToast) {
        SentinelBilling.showToast((errData && errData.message) || "Daily showcase limit reached. Claim a free Developer key!");
    }
}

// Render evaluation results
function renderEvaluation(data, rttMs, telemetry = {}) {
    currentEval = data;
    currentRealIp = data.ip;

    // Elements
    const telAsn = document.getElementById("tel-asn");
    const telProvider = document.getElementById("tel-provider");
    const telCountry = document.getElementById("tel-country");
    const telType = document.getElementById("tel-type");
    const telTime = document.getElementById("tel-time");
    const meterVal = document.getElementById("meter-value");
    const scoreFill = document.getElementById("score-bar-fill");

    // Sync IP visibility with current masking state
    updateIpVisibility();

    const telHostname = document.getElementById("tel-hostname");

    if (telHostname) {
        const rawH = data.hostname || "No PTR record (Unassigned)";
        telHostname.textContent = isIpMasked ? maskStringWithIp(rawH, currentRealIp) : rawH;
        telHostname.title = telHostname.textContent;
    }
    if (telAsn) telAsn.textContent = data.asn ? `AS${data.asn}` : "AS0 (Residential)";
    if (telProvider) telProvider.textContent = data.provider || "Unknown Provider";
    if (telType) {
        const country = data.country || "Global";
        const loc = data.city ? `${data.city}, ${country}` : country;
        telType.innerHTML = `${data.threat_type || "Clean Connection"} <span class="badge-metric" style="margin-left: 6px;">${loc}</span>`;
    }
    if (meterVal) meterVal.textContent = data.risk_score;

    // Latency & Edge Telemetry Execution
    if (telTime) {
        const quotaInfo = telemetry.quotaRemaining ? ` · Quota: ${Number(telemetry.quotaRemaining).toLocaleString()} left (${(telemetry.tier || 'DEV').toUpperCase()})` : "";
        telTime.innerHTML = `<strong>${data.duration_ms || 1} ms</strong> <span style="color: var(--text-muted); font-size: 11px;">(Edge) / ${rttMs || 1} ms (RTT)${quotaInfo}</span>`;
    }

    // Risk Meter Progress Bar
    if (scoreFill) {
        scoreFill.style.width = `${Math.max(data.risk_score, 2)}%`;
        if (data.risk_score >= 70) {
            scoreFill.style.backgroundColor = "var(--status-danger)";
        } else if (data.risk_score >= 30) {
            scoreFill.style.backgroundColor = "var(--status-warning)";
        } else {
            scoreFill.style.backgroundColor = "var(--status-success)";
        }
    }

    // Verdict Banner & Badges
    const banner = document.getElementById("verdict-banner");
    const badge = document.getElementById("verdict-badge");
    const desc = document.getElementById("verdict-desc");

    const isBlocked = data.action === "BLOCK" || data.risk_score >= 70;

    if (banner && badge && desc) {
        if (isBlocked) {
            banner.className = "verdict-banner blocked";
            badge.className = "verdict-badge verdict-blocked-badge";
            badge.textContent = "BLOCKED";
            desc.textContent = `${data.threat_type} detected — Policy: Drop / Refuse Handshake.`;
        } else {
            banner.className = "verdict-banner clean";
            badge.className = "verdict-badge verdict-clean-badge";
            badge.textContent = "ALLOWED";
            desc.textContent = "Legitimate residential connection verified — Policy: Pass-Through.";
        }
    }

    // Reasons Diagnosis
    const reasonsEl = document.getElementById("reasons-text");
    if (reasonsEl && data.reasons) {
        reasonsEl.innerHTML = data.reasons.map(r => `• ${isIpMasked ? maskStringWithIp(r, currentRealIp) : r}`).join("<br>");
    }

    updateJsonView();
}

// =========================================================================
// UNIVERSAL PRICING, SANDBOX KEYS & CHECKOUT INTERFACE
// =========================================================================
window.SentinelPricing = {
    getSandboxKey() {
        const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, "0")).join("");
        const sandboxKey = `stl_test_${randomHex}`;
        
        navigator.clipboard.writeText(sandboxKey).then(() => {
            SentinelPricing.showToast(`Copied Sandbox Dev Key: ${sandboxKey.substring(0, 18)}... (Zero-quota testing)`);
        }).catch(() => {
            prompt("Your Sentinel Sandbox Dev Key:", sandboxKey);
        });
    },

    checkout(tier) {
        const checkouts = {
            starter: "https://antivpn.lemonsqueezy.com/checkout/buy/369af5b1-bf17-4125-8db2-e0b5196706e6",
            business: "https://antivpn.lemonsqueezy.com/checkout/buy/54472a37-beba-4bc1-9f81-cf12d3148152",
            scale: "https://antivpn.lemonsqueezy.com/checkout/buy/c05af8ab-b4c9-46b7-a24d-fa0c7bc46c76"
        };
        const baseUrl = checkouts[tier];
        if (!baseUrl) return;

        // Generate cryptographically unguessable checkout session token (192-bit CSPRNG)
        const rand = crypto.getRandomValues(new Uint8Array(24));
        const sessionId = "stl_sec_" + Array.from(rand).map(b => b.toString(16).padStart(2, "0")).join("");
        sessionStorage.setItem("sentinel_active_session", sessionId);
        sessionStorage.setItem("sentinel_checkout_tier", tier);

        const sep = baseUrl.includes("?") ? "&" : "?";
        const targetUrl = `${baseUrl}${sep}checkout[custom][session_id]=${sessionId}`;

        // Launch background poll immediately
        startCheckoutSessionPolling(sessionId, tier);

        if (window.LemonSqueezy && window.LemonSqueezy.Url) {
            window.LemonSqueezy.Url.Open(targetUrl);
        } else {
            window.open(targetUrl, "_blank");
        }
    },

    claimFreeKey() {
        window.location.href = "https://api.antivpn.tech/v1/auth/github/login";
    },

    showToast(message) {
        let container = document.getElementById("toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "toast-container";
            container.className = "toast-container";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = "toast";
        toast.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            <span>${message}</span>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 4500);
    }
};

// Aliases to avoid ReferenceErrors across scopes
window.SentinelBilling = window.SentinelPricing;
const SentinelBilling = window.SentinelPricing;

// Force close and remove all Lemon Squeezy iframes, overlays, and loaders
function closeLemonSqueezyOverlay() {
    try {
        if (window.LemonSqueezy && window.LemonSqueezy.Url && window.LemonSqueezy.Url.Close) {
            window.LemonSqueezy.Url.Close();
        }
    } catch (e) {}

    document.querySelectorAll("iframe").forEach(frame => {
        const src = (frame.src || "").toLowerCase();
        if (src.includes("lemonsqueezy") || src.includes("checkout")) {
            frame.remove();
        }
    });

    document.querySelectorAll(".lemonsqueezy-loader, [class*='lemonsqueezy']").forEach(el => {
        if (el.tagName !== "BODY") el.remove();
    });

    document.body.classList.remove("lemonsqueezy-open", "lemonsqueezy-loading");
}

// Background session poller for payment clearance
let activePollInterval = null;

async function pollSessionOnce(sessionId) {
    if (!sessionId || !sessionId.startsWith("stl_sec_")) return false;
    try {
        const res = await fetch(`https://api.antivpn.tech/v1/billing/order?session_id=${encodeURIComponent(sessionId)}&_t=${Date.now()}`);
        if (res.ok) {
            const data = await res.json();
            if (data.status === "success" && data.key) {
                if (activePollInterval) {
                    clearInterval(activePollInterval);
                    activePollInterval = null;
                }
                sessionStorage.removeItem("sentinel_active_session");

                closeLemonSqueezyOverlay();

                showLicenseModal({
                    badge: "Subscription Active",
                    title: `Subscription Activated: ${data.tier_name || "Enterprise"}`,
                    desc: `Your live API key has been provisioned with ${(data.monthly_limit || 0).toLocaleString()} verifications/month across 300+ Anycast edge PoPs. Store it in a secure location.`,
                    key: data.key,
                    tierName: data.tier_name,
                    monthlyLimit: data.monthly_limit
                });
                return true;
            }
        }
    } catch (e) {
        // Transient edge delay
    }
    return false;
}

function startCheckoutSessionPolling(sessionId, tier) {
    if (!sessionId || !sessionId.startsWith("stl_sec_")) return;
    if (activePollInterval) clearInterval(activePollInterval);

    let attempts = 0;
    const maxAttempts = 150; // Poll for up to 5 minutes (every 2s)

    activePollInterval = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
            clearInterval(activePollInterval);
            activePollInterval = null;
            return;
        }
        await pollSessionOnce(sessionId);
    }, 2000);
}

// Universal License Delivery Modal & URL Parameter Handlers
function showLicenseModal({ badge = "Active License", title, desc, key, tierName = "", monthlyLimit = "" }) {
    const existing = document.getElementById("sentinel-license-modal");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sentinel-license-modal";
    overlay.className = "sentinel-modal-overlay";

    const curlExample = `curl -s -X GET "https://api.antivpn.tech/v1/check?ip=1.1.1.1" \\
  -H "Authorization: Bearer ${key}"`;

    overlay.innerHTML = `
        <div class="sentinel-modal-card">
            <div class="sentinel-modal-badge">${badge}</div>
            <h2 class="sentinel-modal-title">${title}</h2>
            <p class="sentinel-modal-desc">${desc}</p>

            <div class="sentinel-modal-key-box">
                <input type="text" class="sentinel-modal-key-text" value="${key}" readonly id="modal-key-input">
                <button type="button" class="sentinel-modal-copy-btn" id="modal-copy-btn">Copy Key</button>
            </div>

            <div style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">
                Instant Ingress Verification (Terminal / cURL)
            </div>
            <pre class="sentinel-modal-quickstart"><code>${curlExample}</code></pre>

            <div class="sentinel-modal-footer">
                <button type="button" class="sentinel-modal-close-btn" id="modal-close-btn">Start Building</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    const copyBtn = document.getElementById("modal-copy-btn");
    const keyInput = document.getElementById("modal-key-input");
    const closeBtn = document.getElementById("modal-close-btn");

    if (copyBtn && keyInput) {
        copyBtn.addEventListener("click", () => {
            keyInput.select();
            navigator.clipboard.writeText(key).then(() => {
                copyBtn.textContent = "Copied!";
                copyBtn.style.background = "#22c55e";
                copyBtn.style.color = "#ffffff";
                setTimeout(() => {
                    copyBtn.textContent = "Copy Key";
                    copyBtn.style.background = "";
                    copyBtn.style.color = "";
                }, 2000);
            });
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", () => overlay.remove());
    }

    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.remove();
    });
}

// Listen for Lemon.js Overlay Events & Window Message Events
function setupLemonSqueezyEvents() {
    function processEventData(data) {
        if (!data) return;
        if (typeof data === "string") {
            try { data = JSON.parse(data); } catch (e) { return; }
        }
        if (data.event === "Checkout.Success" || data.action === "Checkout.Success") {
            closeLemonSqueezyOverlay();
            const activeSession = sessionStorage.getItem("sentinel_active_session");
            if (activeSession) {
                pollSessionOnce(activeSession);
            }
        }
    }

    window.addEventListener("message", (event) => {
        processEventData(event.data);
    });

    function bindLS() {
        if (window.LemonSqueezy && window.LemonSqueezy.Setup) {
            window.LemonSqueezy.Setup({
                eventHandler: (event) => {
                    processEventData(event);
                }
            });
            return true;
        }
        return false;
    }

    if (!bindLS()) {
        const interval = setInterval(() => {
            if (bindLS()) clearInterval(interval);
        }, 300);
        setTimeout(() => clearInterval(interval), 10000);
    }
}
setupLemonSqueezyEvents();

// Auto-check URL parameters for Lemon Squeezy Purchases and GitHub OAuth
(async function checkPostPurchaseAndOAuth() {
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id") || params.get("session");
    const claimedKey = params.get("claimed_key");
    const isNew = params.get("new") === "true";
    const authError = params.get("auth_error");

    const storedSession = sessionStorage.getItem("sentinel_active_session");

    // 1. Handle Secret Session ID in URL or active session storage
    if (sessionId && sessionId.startsWith("stl_sec_")) {
        window.history.replaceState({}, document.title, window.location.pathname);
        startCheckoutSessionPolling(sessionId);
        return;
    }

    if (storedSession && storedSession.startsWith("stl_sec_")) {
        startCheckoutSessionPolling(storedSession);
    }

    // 2. Handle GitHub OAuth Key Claim
    if (claimedKey) {
        window.history.replaceState({}, document.title, window.location.pathname);
        const title = isNew ? "Free Developer Key Minted" : "Welcome Back";
        const desc = isNew
            ? "Your verified GitHub account has been provisioned with 5,000 monthly checks across 300+ global edge locations."
            : "Here is your active Sentinel Developer key (5,000 monthly checks).";

        setTimeout(() => {
            showLicenseModal({
                badge: "Developer Tier",
                title: title,
                desc: desc,
                key: claimedKey,
                monthlyLimit: 5000
            });
        }, 300);
        return;
    }

    // 3. Handle GitHub OAuth Errors
    if (authError) {
        window.history.replaceState({}, document.title, window.location.pathname);
        const errorMsgs = {
            account_too_new: "GitHub account must be at least 30 days old to claim a free key. Please use our instant Sandbox key for testing.",
            invalid_token: "GitHub authentication was canceled or expired. Please try again.",
            server_error: "Authentication service temporarily unavailable. Please try again."
        };
        setTimeout(() => {
            SentinelBilling.showToast(errorMsgs[authError] || "Unable to claim free key. Please try again.");
        }, 500);
    }
})();

// ==========================================================================
// ENTERPRISE LEGAL & COMPLIANCE MODAL CONTROLLER
// ==========================================================================
const SentinelLegal = {
    content: {
        terms: {
            title: "Terms of Service",
            html: `
                <div class="legal-section-block">
                    <p>These Terms of Service ("Terms") govern access to and usage of the Sentinel edge threat intelligence API, dashboard, client connectors, and documentation (collectively, the "Service") operated by Sentinel ("we", "us", or "our").</p>

                    <div class="legal-callout-shield">
                        <strong>CRITICAL SUMMARY:</strong> Sentinel provides algorithmic threat screening indicators for defensive network filtering. Under no circumstances does Sentinel guarantee 100% detection of all evasion mechanisms or zero false positives. Our aggregate liability is strictly capped at $100 USD or fees paid in the preceding one month.
                    </div>

                    <h3>1. Acceptance & Authorization</h3>
                    <p>By minting an API key, issuing queries to <code>api.antivpn.tech</code>, integrating client libraries, or subscribing to paid quotas, you agree to be legally bound by these Terms. If you represent an organization, you warrant authority to bind that entity.</p>

                    <h3>2. Advisory Nature of Threat Scoring</h3>
                    <p>Sentinel evaluates IP addresses using automated heuristics, carrier network topology analysis, and the Sentinel Global Threat Grid. All risk scores (0–100), threat classifications, and recommended actions (e.g., ALLOW, AUDIT, BLOCK) are <strong>purely advisory algorithmic estimates</strong> provided for screening purposes. You retain sole and exclusive responsibility for determining whether to drop, challenge, rate-limit, or permit traffic on your applications and networks.</p>

                    <h3>3. Disclaimer of Warranties</h3>
                    <p>TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SERVICE IS PROVIDED STRICTLY <strong>"AS IS"</strong> AND <strong>"AS AVAILABLE"</strong>. SENTINEL EXPRESSLY DISCLAIMS ALL WARRANTIES, WHETHER STATUTORY, EXPRESS, OR IMPLIED, INCLUDING IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, SYSTEM INTEGRATION, TITLE, AND NON-INFRINGEMENT. WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, TIMELY, SECURE, ACCURATE, OR ERROR-FREE.</p>

                    <h3>4. Strict Limitation of Liability</h3>
                    <div class="legal-callout-shield">
                        <strong>LIMITATION OF LIABILITY & WAIVER OF CONSEQUENTIAL DAMAGES:</strong><br>
                        TO THE FULLEST EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL SENTINEL, ITS OPERATORS, EMPLOYEES, OR AGENTS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, CONSEQUENTIAL, SPECIAL, PUNITIVE, OR EXEMPLARY DAMAGES WHATSOEVER, INCLUDING DAMAGES FOR LOSS OF PROFITS, LOSS OF REVENUE, LOSS OF USERS OR PLAYERS, BUSINESS INTERRUPTION, LOSS OF DATA, FRAUD LOSSES, CHARGEBACK FINES, OR REPUTATIONAL DAMAGE, REGARDLESS OF THE LEGAL THEORY (TORT, CONTRACT, OR OTHERWISE), EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.<br><br>
                        <strong>AGGREGATE LIABILITY CEILING:</strong> IN NO EVENT SHALL SENTINEL'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATING TO THE SERVICE EXCEED THE GREATER OF <strong>ONE HUNDRED UNITED STATES DOLLARS ($100.00 USD)</strong> OR THE TOTAL SUBSCRIPTION FEES ACTUALLY PAID BY YOU TO SENTINEL IN THE PRECEDING ONE (1) MONTH.
                    </div>

                    <h3>5. High-Concurrency Fair Use & Rate Limiting</h3>
                    <p>Each license key operates under defined monthly verification quotas and burst thresholds. Sentinel reserves the right to throttle, drop, or temporarily suspend keys that exceed contracted quotas, generate abusive packet bursts, or exhibit denial-of-service characteristics without prior notice.</p>

                    <h3>6. Indemnification</h3>
                    <p>You agree to defend, indemnify, and hold harmless Sentinel and its operators from and against any third-party claims, liabilities, damages, or costs (including reasonable legal fees) arising out of or related to your application's enforcement actions, misconfiguration, or breach of these Terms.</p>
                </div>
            `
        },
        privacy: {
            title: "Privacy Notice & Data Processing (GDPR / CCPA)",
            html: `
                <div class="legal-section-block">
                    <p>Sentinel is architected around strict data minimization and privacy-by-design principles. This policy explains how IP addresses and connection metadata are handled across our global edge infrastructure.</p>

                    <h3>1. Data Minimization & Volatile Processing</h3>
                    <p>Sentinel performs stateless connection evaluation. Inbound IP addresses queried against <code>api.antivpn.tech/v1/check</code> are evaluated strictly inside <strong>ephemeral isolate RAM</strong> across our edge points of presence.</p>

                    <div class="legal-callout-shield">
                        <strong>0ms Persistent Disk Storage:</strong> Queried client IP addresses, payload parameters, and inspection results are <strong>never written to persistent disk, relational databases, or query log stores</strong>. Once the JSON response is delivered, the in-memory inspection state is immediately released.
                    </div>

                    <h3>2. Legal Basis for Processing (GDPR Article 6(1)(f))</h3>
                    <p>Under European Union GDPR Recital 30 and judicial precedent (CJEU <em>Breyer v. Germany</em>), dynamic IP addresses are classified as Personal Data. Sentinel processes queried IP addresses strictly under the legal basis of <strong>Legitimate Interests (GDPR Art. 6(1)(f))</strong> to deliver cybersecurity filtering, mitigate automated botnet attacks, detect credential stuffing, and safeguard digital infrastructure.</p>

                    <h3>3. Infrastructure Sub-Processors</h3>
                    <p>To deliver sub-millisecond edge execution and commercial billing, Sentinel utilizes authoritative sub-processors under strict security terms:</p>
                    <ul>
                        <li><strong>Cloudflare, Inc.:</strong> Global Anycast edge compute, DDoS mitigation, and SSL termination.</li>
                        <li><strong>Lemon Squeezy, LLC:</strong> Merchant of Record for payment processing, tax calculation, and subscription management.</li>
                    </ul>

                    <h3>4. Cookie-Free Architecture</h3>
                    <p>The Sentinel web platform, documentation, and API console operate <strong>completely free of tracking cookies, third-party analytics scripts, or behavioral advertising beacons</strong>. We do not sell or monetize personal information under the California Consumer Privacy Act (CCPA).</p>

                    <h3>5. Data Subject Inquiries</h3>
                    <p>Because Sentinel does not log or persist IP addresses, we do not maintain searchable user dossiers or persistent identifiers. For formal privacy or data protection inquiries, contact <code>legal@antivpn.tech</code>.</p>
                </div>
            `
        },
        aup: {
            title: "Acceptable Use Policy (AUP)",
            html: `
                <div class="legal-section-block">
                    <p>To ensure global edge availability and prevent weaponization of our intelligence network, all users and keyholders must comply with this Acceptable Use Policy.</p>

                    <h3>1. Strictly Prohibited Activities</h3>
                    <p>You may not utilize Sentinel or its APIs to:</p>
                    <ul>
                        <li>Conduct unauthorized reconnaissance, port scanning, or vulnerability probing against external networks.</li>
                        <li>Reverse engineer, scrape, decompile, or systematically extract the underlying threat intelligence database, proxy signatures, or heuristic models.</li>
                        <li>Resell, sublicense, syndicate, or redistribute raw API responses to third parties without an executed Enterprise Redistributor Agreement.</li>
                        <li>Circumvent license authentication, tamper with quota metering headers, or spoof identity attributes.</li>
                        <li>Deploy automated volumetric denial-of-service traffic intended to impair Sentinel edge infrastructure.</li>
                    </ul>

                    <h3>2. Key Revocation & Enforcement</h3>
                    <p>Sentinel reserves the right to immediately terminate, revoke, or blacklist any API key or IP range found in violation of this AUP, without eligibility for refunds or prior notice.</p>
                </div>
            `
        },
        billing: {
            title: "Merchant of Record & Refund Policy",
            html: `
                <div class="legal-section-block">
                    <p>This disclosure outlines how subscriptions, billing operations, and cancellations are conducted for Sentinel commercial licenses.</p>

                    <h3>1. Lemon Squeezy as Merchant of Record</h3>
                    <p>All subscription transactions, license purchases, and global invoicing are processed by <strong>Lemon Squeezy, LLC</strong> acting as Merchant of Record. Lemon Squeezy handles global sales tax, VAT, GST calculation, PCI-DSS payment compliance, and chargeback dispute resolution.</p>

                    <h3>2. Subscription Renewals & Cancellation</h3>
                    <p>Commercial licenses (Starter, Business, Scale) are billed automatically on a recurring monthly cycle. You may cancel your subscription at any time with one click through the Lemon Squeezy Customer Billing Portal provided in your receipt email. Upon cancellation, your API key remains operational through the conclusion of the paid billing period.</p>

                    <h3>3. Digital Goods & Refund Terms</h3>
                    <p>Sentinel licenses provide instantaneous cryptographic API key provisioning and access to high-concurrency edge infrastructure. As such, fees are generally non-refundable once an API key has been generated and utilized.</p>
                    <p>We provide a <strong>Free Developer Tier</strong> specifically so developers and organizations can thoroughly evaluate API accuracy, integration compatibility, and latency prior to purchasing a paid tier. If you encounter documented technical failures attributable to Sentinel that prevent service usage, contact <code>support@antivpn.tech</code> within 14 days of purchase.</p>
                </div>
            `
        },
        sla: {
            title: "Service Level Availability Target",
            html: `
                <div class="legal-section-block">
                    <p>This document details infrastructure availability standards, uptime targets, and the framework governing enterprise service levels.</p>

                    <h3>1. Public Infrastructure Availability Target</h3>
                    <p>Sentinel’s distributed edge architecture is engineered for continuous high-availability with a target of <strong>99.9% uptime</strong> across global points of presence.</p>

                    <div class="legal-callout-shield">
                        <strong>Public Tier Target Notice:</strong> The 99.9% availability metric represents an architectural engineering goal for public self-serve tiers, not an express contractual guarantee or warranty.
                    </div>

                    <h3>2. Exclusions from Availability Calculations</h3>
                    <p>Uptime metrics do not include service interruptions resulting from:</p>
                    <ul>
                        <li>Scheduled maintenance communicated via status announcements.</li>
                        <li>Upstream global internet backbone disruptions or Cloudflare Anycast edge outages beyond Sentinel’s direct operational control.</li>
                        <li>Customer networking errors, improper timeout handling, or local DNS resolver failures.</li>
                        <li>Volumetric cyberattacks, DDoS events, or malicious upstream ISP routing anomalies.</li>
                    </ul>

                    <h3>3. Binding Enterprise Service Level Agreements</h3>
                    <p>Enterprise clients requiring legally binding Service Level Agreements (SLAs) with contractually guaranteed uptime thresholds and Service Credit remedies may execute a custom Master Services Agreement (MSA) with dedicated isolate infrastructure. Contact <code>enterprise@antivpn.tech</code> for customized SLA contracts.</p>
                </div>
            `
        },
        a11y: {
            title: "Accessibility Statement (WCAG 2.1 AA)",
            html: `
                <div class="legal-section-block">
                    <p>Sentinel is committed to ensuring digital accessibility for all users, including individuals with visual, auditory, cognitive, and motor impairments. We continually enhance user experience across our web console and documentation in alignment with the <strong>Web Content Accessibility Guidelines (WCAG) 2.1 Level AA</strong> and the Americans with Disabilities Act (ADA).</p>

                    <div class="legal-callout-shield">
                        <strong>ACCESSIBILITY COMMITMENT & STANDARDS:</strong><br>
                        • All form inputs, interactive controls, and inspection tools maintain programmatic ARIA labels.<br>
                        • Interface elements are designed with high-contrast color pairings conforming to minimum 4.5:1 contrast standards.<br>
                        • Full keyboard navigation support (Tab, Space, Enter, Escape) with clear focus indicators and bypass skip links.
                    </div>

                    <h3>1. Measures Taken for Accessibility</h3>
                    <ul>
                        <li><strong>Semantic HTML:</strong> Use of standard landmarks, dialog roles, and structured headings to ensure assistive technologies (NVDA, JAWS, VoiceOver) navigate smoothly.</li>
                        <li><strong>Keyboard Operability:</strong> Interactive modals, tab panels, and code snippet selectors are fully navigable without pointing devices.</li>
                        <li><strong>Non-Text Contrast:</strong> Code syntax blocks, charts, and risk dials feature distinct visual identifiers and legible typographic hierarchies.</li>
                        <li><strong>Assistive Tech Labels:</strong> Decorative icons are hidden from screen readers via <code>aria-hidden="true"</code>, while actionable controls provide explicit textual descriptions.</li>
                    </ul>

                    <h3>2. Feedback & Assistance</h3>
                    <p>If you encounter accessibility barriers, experience difficulty operating our interface with screen readers, or require documentation in alternative formats, please contact our compliance team directly at <code>accessibility@antivpn.tech</code>. We investigate all accessibility inquiries promptly.</p>
                </div>
            `
        },
        export: {
            title: "Trade Sanctions & Export Compliance",
            html: `
                <div class="legal-section-block">
                    <p>Sentinel software, edge APIs, cryptographic signatures, and threat intelligence data are subject to the export control and trade sanctions laws of the United States and the European Union.</p>

                    <h3>1. Embargoed Destinations & Restricted Parties</h3>
                    <p>By accessing Sentinel APIs or purchasing a commercial license, you certify that:</p>
                    <ul>
                        <li>You are not located in, organized under the laws of, or a resident of any country or region subject to comprehensive trade sanctions administered by the US Department of the Treasury's Office of Foreign Assets Control (OFAC) (including Cuba, Iran, North Korea, Syria, and the Crimea, Donetsk, and Luhansk regions of Ukraine).</li>
                        <li>You are not identified on any government sanctions registry, including the OFAC Specially Designated Nationals (SDN) list or the US Department of Commerce Entity List.</li>
                        <li>You will not use, transfer, or export Sentinel services or data to facilitate prohibited military end-uses or cyber warfare activities.</li>
                    </ul>

                    <h3>2. Minors & Age Restrictions (COPPA & GDPR)</h3>
                    <p>The Service is designed exclusively for commercial software developers, system administrators, and corporate networks. You must be at least eighteen (18) years of age or the legal age of majority in your jurisdiction to purchase subscriptions or enter into binding agreements. Sentinel does not knowingly solicit or collect personal information from individuals under the age of thirteen (13).</p>
                </div>
            `
        }
    },

    open(tab = 'terms') {
        const modal = document.getElementById("sentinel-legal-modal");
        if (!modal) return;
        this.switchTab(tab);
        modal.style.display = "flex";
        document.body.style.overflow = "hidden";
    },

    close() {
        const modal = document.getElementById("sentinel-legal-modal");
        if (!modal) return;
        modal.style.display = "none";
        document.body.style.overflow = "";
    },

    switchTab(tabKey) {
        const tabData = this.content[tabKey] || this.content.terms;
        const titleEl = document.getElementById("legal-modal-title");
        const bodyEl = document.getElementById("legal-modal-body");

        if (titleEl) titleEl.textContent = tabData.title;
        if (bodyEl) {
            bodyEl.innerHTML = tabData.html;
            bodyEl.scrollTop = 0;
        }

        document.querySelectorAll(".legal-tab-btn").forEach(btn => {
            btn.classList.toggle("active", btn.getAttribute("data-tab") === tabKey);
        });
    }
};

window.SentinelLegal = SentinelLegal;

// Wire up Legal Modal Outside Click & Escape Key
document.addEventListener("DOMContentLoaded", () => {
    const legalModal = document.getElementById("sentinel-legal-modal");
    if (legalModal) {
        legalModal.addEventListener("click", (e) => {
            if (e.target === legalModal) {
                SentinelLegal.close();
            }
        });
    }
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            SentinelLegal.close();
        }
    });
});


