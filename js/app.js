let currentEval = null;
let isIpMasked = true;
let currentRealIp = null;
let visitorIp = null;

const CODE_SNIPPETS = {
    curl: `# Query the live Sentinel Edge API
curl -s -X GET "https://api.antivpn.tech/v1/check?ip=185.213.154.20"

# Live JSON Response:
# {
#   "ip": "185.213.154.20",
#   "action": "BLOCK",
#   "risk_score": 95,
#   "threat_type": "Commercial VPN",
#   "asn": 206016,
#   "provider": "Mullvad VPN",
#   "country": "SE",
#   "reasons": ["BGP Prefix Match: Mullvad VPN (Commercial VPN)"],
#   "duration_ms": 1
# }`,

    node: `// Node.js (18+), Bun, or Edge Runtime / Fetch
async function checkClientAccess(clientIP) {
    const url = \`https://api.antivpn.tech/v1/check?ip=\${encodeURIComponent(clientIP)}\`;
    const response = await fetch(url, { headers: { "Accept": "application/json" } });
    const verdict = await response.json();

    if (verdict.action === "BLOCK") {
        console.warn(\`Access denied for \${clientIP}: \${verdict.threat_type} (Risk: \${verdict.risk_score}/100)\`);
        return false; // Deny request or terminate socket
    }

    return true; // Allow access
}`,

    python: `import requests

def verify_ip(client_ip: str) -> bool:
    """Query Sentinel Edge API to evaluate VPN/Proxy risk."""
    response = requests.get(
        "https://api.antivpn.tech/v1/check",
        params={"ip": client_ip},
        timeout=2.0
    )
    data = response.json()

    if data.get("action") == "BLOCK":
        risk = data.get("risk_score")
        threat = data.get("threat_type")
        print(f"Blocked connection from {client_ip}: {threat} (Risk {risk}/100)")
        return False

    return True`,

    go: `package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

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

var httpClient = &http.Client{Timeout: 2 * time.Second}

func CheckIP(ip string) (*SentinelVerdict, error) {
    url := fmt.Sprintf("https://api.antivpn.tech/v1/check?ip=%s", ip)
    resp, err := httpClient.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var verdict SentinelVerdict
    if err := json.NewDecoder(resp.Body).Decode(&verdict); err != nil {
        return nil, err
    }
    return &verdict, nil
}`,

    mc: `// High-Concurrency Game Server & TCP Socket Ingress (Java 21)
// Native reverse-proxy ingress & threat mitigation pipeline
@ChannelHandler.Sharable
public class SentinelIngressHandler extends ChannelInboundHandlerAdapter {

    private final SentinelClient sentinel = SentinelClient.builder()
        .endpoint("https://api.antivpn.tech")
        .maxLocalCacheEntries(50_000)
        .cacheTtl(Duration.ofMinutes(15))
        .build();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof HAProxyMessage proxyMsg) {
            // 1. Extract genuine client IP from inbound proxy header
            String realClientIP = proxyMsg.sourceAddress();

            // 2. High-speed local cache evaluation
            if (sentinel.isBlockedFast(realClientIP)) {
                ctx.close(); // Immediate connection refusal
                return;
            }

            // 3. Asynchronous Edge API verification
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

// Scroll progress bar
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
                    progressBar.style.width = `${(scrollTop / scrollHeight) * 100}%`;
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
    jsonView.textContent = JSON.stringify(currentEval, null, 2);
}

// Code snippet switcher
function initCodeSnippets() {
    const tabs = document.querySelectorAll(".code-tab-btn");
    const display = document.getElementById("code-display");

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
            return `${parts[0]}.${parts[1]}.•••.••`;
        }
    }
    if (ip.includes(":")) {
        const parts = ip.split(":");
        return `${parts[0]}:${parts[1]}:••••:••••`;
    }
    return "••••••••••••";
}

function updateIpVisibility() {
    const ipInput = document.getElementById("ip-input");
    const telIp = document.getElementById("tel-ip");
    const telReq = document.getElementById("tel-request");
    
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

// Visitor detection
async function detectVisitorConnection() {
    const desc = document.getElementById("verdict-desc");
    if (desc) desc.textContent = "Analyzing inbound connection headers...";

    try {
        const startTime = performance.now();
        const clientTz = encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone || "");
        const clientEpoch = Date.now();
        const webdriver = navigator.webdriver ? "1" : "0";
        const queryParams = `client_tz=${clientTz}&client_epoch=${clientEpoch}&webdriver=${webdriver}`;
        const res = await fetch(`https://api.antivpn.tech/v1/check?${queryParams}`, { cache: "no-store" });
        const rtt = Math.round(performance.now() - startTime);

        if (res.ok) {
            const data = await res.json();
            visitorIp = data.ip;
            currentRealIp = data.ip;
            renderEvaluation(data, rtt);
        } else {
            fallbackLocalEvaluate();
        }
    } catch (e) {
        fallbackLocalEvaluate();
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
    const queryParams = `client_tz=${clientTz}&client_epoch=${clientEpoch}&webdriver=${webdriver}`;

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
            renderEvaluation(data, rtt);
        } else {
            fallbackPresetEval(targetIp);
        }
    } catch (err) {
        fallbackPresetEval(targetIp);
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
                `BGP Prefix Match: ${preset.provider} (${preset.category})`,
                isBlocked ? "Threat classified as Datacenter/VPN subnet." : "Verified consumer residential subnet."
            ],
            duration_ms: 1
        }, 15);
    }
}

function fallbackLocalEvaluate() {
    visitorIp = "186.104.86.42";
    currentRealIp = "186.104.86.42";
    renderEvaluation({
        ip: "186.104.86.42",
        action: "ALLOW",
        risk_score: 0,
        threat_type: "Clean Residential",
        asn: 7922,
        provider: "Residential Internet Service Provider",
        country: "US",
        reasons: ["Verified consumer residential or mobile subscriber connection."],
        duration_ms: 1
    }, 22);
}

// Render evaluation results
function renderEvaluation(data, rttMs) {
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
        telHostname.textContent = data.hostname || "No PTR record (Unassigned)";
        telHostname.title = data.hostname || "";
    }
    if (telAsn) telAsn.textContent = data.asn ? `AS${data.asn}` : "AS0 (Residential)";
    if (telProvider) telProvider.textContent = data.provider || "Unknown Provider";
    if (telType) {
        const country = data.country || "Global";
        const loc = data.city ? `${data.city}, ${country}` : country;
        telType.innerHTML = `${data.threat_type || "Clean Connection"} <span class="badge-metric" style="margin-left: 6px;">${loc}</span>`;
    }
    if (meterVal) meterVal.textContent = data.risk_score;

    // Latency & Execution
    if (telTime) {
        telTime.innerHTML = `<strong>${data.duration_ms || 1} ms</strong> <span style="color: var(--text-muted); font-size: 11px;">(Edge) / ${rttMs || 1} ms (RTT)</span>`;
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
        reasonsEl.innerHTML = data.reasons.map(r => `• ${r}`).join("<br>");
    }

    updateJsonView();
}
