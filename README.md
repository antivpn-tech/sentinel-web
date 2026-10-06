# Sentinel — Edge Anti-VPN & Threat Intelligence Engine

[![Live Showcase](https://img.shields.io/badge/Live%20Console-antivpn.tech-00f2fe?style=for-the-badge&logo=cloudflare&logoColor=white)](https://antivpn.tech)
[![API Status](https://img.shields.io/badge/API-api.antivpn.tech-10b981?style=for-the-badge)](https://api.antivpn.tech/healthz)
[![Global Latency](https://img.shields.io/badge/Global%20Latency-%3C%205ms-3b82f6?style=for-the-badge)](https://antivpn.tech)
[![Dual Stack](https://img.shields.io/badge/Dual--Stack-IPv4%20%7C%20IPv6-f59e0b?style=for-the-badge)](https://antivpn.tech)
[![License](https://img.shields.io/badge/License-Proprietary-gray?style=for-the-badge)](https://antivpn.tech)

**Sentinel** is an autonomous edge threat mitigation platform engineered to identify and block commercial VPNs, datacenter proxies, residential proxy tunnels, Tor relays, and automated bots in real time.

Evaluate any IP address live at **[antivpn.tech](https://antivpn.tech)**.

---

## How It Works

Sentinel evaluates inbound traffic at the edge before connection authorization, eliminating server load and blocking malicious sessions with sub-millisecond edge compute execution across 300+ global PoPs.

### Connection Filtering Lifecycle

```
[ LEGITIMATE USER ]
  │  (Consumer ISP: Comcast, Verizon, Vodafone, etc.)
  ▼
[ Sentinel Edge Network ]
  │  ► Subscriber Carrier Verification & Edge Ingress Consistency
  │  ► Autonomous Infrastructure Legitimate Routing Match
  ▼
  Verdict: ALLOW (Risk: 0/100) ──► Forwarded to Application / Game Server


[ MALICIOUS ACTOR / BOT / PROXY ]
  │  (Mullvad, NordVPN, Bright Data, Hetzner VPS, Tor, etc.)
  ▼
[ Sentinel Edge Network ]
  │  ► Sentinel Global Threat Grid Correlation
  │  ► Sentinel Carrier & Autonomous System Topology Match
  │  ► Dynamic Tunnel & Gateway Behavioral Anomaly Detection
  ▼
  Verdict: BLOCK (Risk: 85-100) ──► Connection Refused / 403 Handshake Drop
```

---

## Features

* **Universal Multi-Protocol Mitigation**: Blocks commercial VPNs, cloud datacenter VPS nodes, open SOCKS4/SOCKS5 proxies, Tor exit relays, and bulletproof subnets.
* **Residential Proxy & Covert Tunnel Defense**: Identifies stealth residential proxy tunnels, rotating gateway nodes, and hijacked consumer endpoints via proprietary edge telemetry and temporal correlation.
* **Dual-Stack IPv4 & IPv6 Parity**: Seamless inspection of both legacy IPv4 blocks and modern IPv6 privacy relay subnets.
* **Carrier & Topology Intelligence**: Autonomous carrier routing and infrastructure topology validation, separating verified residential broadband from transit cloud infrastructure.
* **Zero Cold Starts**: Distributed serverless edge presence across 330+ locations globally for sub-millisecond execution overhead.

---

## Integration Guide: Protect Your Application

Sentinel integrates into any technology stack with minimal lines of code.

### Authentication & API Keys

All queries to `api.antivpn.tech` should be authenticated using your Universal License Key (`stl_live_...`) passed in the standard HTTP `Authorization` header:

```http
Authorization: Bearer stl_live_your_api_key_here
```

*(Alternatively, for environments where configuring custom request headers is constrained, pass `?key=stl_live_your_api_key_here` as a query parameter).*

#### Live Quota Telemetry Headers
Every authenticated API response returns real-time quota telemetry headers evaluated directly in volatile isolate RAM (<0.5ms):
* `X-Sentinel-Tier`: Active plan tier (`developer`, `starter`, `business`, `scale`).
* `X-Sentinel-Quota-Limit`: Total monthly checks allocated to this key.
* `X-Sentinel-Quota-Remaining`: Remaining checks available in the current billing cycle.
* `X-Sentinel-Status`: License status (`active`).

> [!TIP]
> Always load your API key via environment variables (`SENTINEL_API_KEY`) or secure secret managers. Never commit production keys to public GitHub repositories or client-facing bundles.

---

### 1. Node.js / Express Middleware

Protect website routes, login endpoints, and checkout flows:

```javascript
// middleware/sentinel.js
const SENTINEL_KEY = process.env.SENTINEL_API_KEY || "stl_live_your_api_key_here";

async function sentinelGuard(req, res, next) {
    const clientIP = req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    try {
        const response = await fetch(`https://api.antivpn.tech/v1/check?ip=${encodeURIComponent(clientIP)}`, {
            headers: {
                "Authorization": `Bearer ${SENTINEL_KEY}`,
                "Accept": "application/json"
            }
        });

        const verdict = await response.json();
        // Optional: inspect remaining monthly quota
        const quotaRemaining = response.headers.get("X-Sentinel-Quota-Remaining");

        if (verdict.action === "BLOCK") {
            console.warn(`[Sentinel] Blocked ${clientIP} (${verdict.threat_type}, Risk: ${verdict.risk_score}/100) [Quota Left: ${quotaRemaining}]`);
            return res.status(403).json({
                error: "Access Denied",
                message: "Traffic from VPNs, hosting proxies, and anonymizers is restricted on this network.",
                threat_type: verdict.threat_type
            });
        }

        // Pass clean residential connection
        next();
    } catch (err) {
        // Fail-open strategy to prevent service disruption if network fails
        next();
    }
}

module.exports = sentinelGuard;
```

---

### 2. Python / FastAPI & Flask

Protect backend APIs and stop web scrapers or credential stuffers:

```python
# sentinel_guard.py
import os
import requests
from fastapi import Request, HTTPException

SENTINEL_API = "https://api.antivpn.tech/v1/check"
SENTINEL_KEY = os.getenv("SENTINEL_API_KEY", "stl_live_your_api_key_here")

def verify_connection(client_ip: str) -> bool:
    """Evaluates an IP address against Sentinel Edge intelligence."""
    try:
        res = requests.get(
            SENTINEL_API,
            params={"ip": client_ip},
            headers={"Authorization": f"Bearer {SENTINEL_KEY}"},
            timeout=2.0
        )
        # Inspect edge quota telemetry
        quota_remaining = res.headers.get("X-Sentinel-Quota-Remaining")
        data = res.json()
        return data.get("action") != "BLOCK"
    except requests.RequestException:
        return True  # Fail-open fallback

# FastAPI Dependency
async def require_clean_connection(request: Request):
    client_ip = request.headers.get("CF-Connecting-IP") or request.client.host
    if not verify_connection(client_ip):
        raise HTTPException(
            status_code=403,
            detail="Access restricted: VPN / Proxy detected."
        )
```

---

### 3. Go HTTP Middleware

High-throughput middleware for high-concurrency microservices:

```go
package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type SentinelVerdict struct {
	IP         string `json:"ip"`
	Action     string `json:"action"`
	RiskScore  int    `json:"risk_score"`
	ThreatType string `json:"threat_type"`
}

var (
	client      = &http.Client{Timeout: 2 * time.Second}
	sentinelKey = os.Getenv("SENTINEL_API_KEY") // Or fallback "stl_live_your_api_key_here"
)

func SentinelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("CF-Connecting-IP")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		url := fmt.Sprintf("https://api.antivpn.tech/v1/check?ip=%s", clientIP)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		// Authenticate with Universal License Key
		req.Header.Set("Authorization", "Bearer "+sentinelKey)

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			// Read telemetry quota: resp.Header.Get("X-Sentinel-Quota-Remaining")
			var verdict SentinelVerdict
			if err := json.NewDecoder(resp.Body).Decode(&verdict); err == nil {
				if verdict.Action == "BLOCK" {
					http.Error(w, "Forbidden: VPN / Proxy Restricted", http.StatusForbidden)
					return
				}
			}
			resp.Body.Close()
		}

		next.ServeHTTP(w, r)
	})
}
```

---

### 4. Game Servers & TCP Sockets (Java / Netty)

Filter connections on game server or TCP socket ingress before handshake:

```java
// Netty Channel Inbound Handler
public class SentinelIngressGuard extends ChannelInboundHandlerAdapter {

    private static final String API_KEY = System.getenv().getOrDefault("SENTINEL_API_KEY", "stl_live_your_api_key_here");
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        String clientIP = extractClientIP(ctx, msg);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.antivpn.tech/v1/check?ip=" + clientIP))
            .header("Authorization", "Bearer " + API_KEY)
            .timeout(Duration.ofMillis(1500))
            .GET()
            .build();

        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenAccept(response -> {
                if (response.body().contains("\"action\":\"BLOCK\"")) {
                    ctx.close(); // Immediate connection refusal before authentication
                } else {
                    ctx.fireChannelRead(msg);
                }
            })
            .exceptionally(ex -> {
                ctx.fireChannelRead(msg); // Fail-open fallback
                return null;
            });
    }
}
```

---

### 5. Instant Terminal Check (cURL)

Inspect any target address in seconds with your license key:

```bash
# Query an arbitrary IP target with Universal License Key
curl -s -X GET "https://api.antivpn.tech/v1/check?ip=185.213.154.20" \
  -H "Authorization: Bearer stl_live_your_api_key_here" | jq
```

**JSON Output:**
```json
{
  "ip": "185.213.154.20",
  "action": "BLOCK",
  "risk_score": 95,
  "threat_type": "Commercial VPN",
  "asn": 206016,
  "provider": "Mullvad VPN",
  "hostname": null,
  "country": "SE",
  "reasons": [
    "Carrier Network Classification: Commercial VPN (Mullvad VPN)"
  ],
  "duration_ms": 1
}
```

---

## API Reference

### `GET /v1/check?ip={target_ip}`
Evaluates an explicit IPv4 or IPv6 address.

### `GET /v1/check`
Automatically evaluates the inbound visitor's connection headers.

### `GET /healthz`
Global edge health and liveness probe.

---

## Privacy & Zero-Log Architecture

Sentinel is engineered around strict data minimization and stateless evaluation:

* **Volatile Memory Processing**: Inbound IP queries are evaluated strictly in ephemeral edge isolate memory (V8 isolates).
* **Zero Persistent Storage**: Inspected IPs and query payloads are never written to disk, database, or persistent storage.
* **No Telemetry Harvesting**: Zero user identity tracking, zero traffic logging, and zero third-party data sharing.

---

## Legal & Advisory Notice

Sentinel provides algorithmic threat intelligence and network classifications strictly for defensive screening and informational purposes. All results are automated heuristic assessments; customers retain exclusive discretion and authority over connection filtering and enforcement actions across their systems. 

All third-party trademarks and trade names referenced herein (including Cloudflare, Lemon Squeezy, WTFast, and ExitLag) belong to their respective holders and are used solely for nominative identification and technical compatibility. For complete terms, visit our [Terms of Service](https://antivpn.tech/terms) and [Privacy Notice](https://antivpn.tech/privacy).

---

## Project & Ownership

* **Organization**: [@antivpn-tech](https://github.com/antivpn-tech)
* **Developer & Architect**: [@undrrwrldd](https://github.com/undrrwrldd)
* **Live Showcase**: [https://antivpn.tech](https://antivpn.tech)
* **Edge Endpoint**: [https://api.antivpn.tech](https://api.antivpn.tech)
* **Copyright**: © 2026 Sentinel Security / AntiVPN Tech. All rights reserved.
