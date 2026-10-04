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
  │  (Consumer ISP: Comcast, Movistar, Vodafone, etc.)
  ▼
[ Sentinel Edge Network ]
  │  ► Authoritative carrier & subscriber verification
  │  ► Timezone & hardware coherence checks
  ▼
  Verdict: ALLOW (Risk: 0/100) ──► Forwarded to Application / Game Server


[ MALICIOUS ACTOR / BOT / PROXY ]
  │  (Mullvad, NordVPN, Bright Data, Hetzner VPS, Tor, etc.)
  ▼
[ Sentinel Edge Network ]
  │  ► Autonomous threat network match
  │  ► Infrastructure reverse DNS pattern match
  │  ► Client-to-network timezone skew anomaly
  ▼
  Verdict: BLOCK (Risk: 85-100) ──► Connection Refused / 403 Handshake Drop
```

---

## Features

* **Universal Threat Mitigation**: Stops commercial VPNs, cloud datacenter VPS nodes, open SOCKS5/HTTP proxies, and Tor exit relays.
* **Residential Proxy Defense**: Identifies residential proxy tunnels by analyzing client hardware clock and physical edge gateway timezone coherence.
* **Dual-Stack IPv4 & IPv6 Parity**: Seamless inspection of both legacy IPv4 blocks and modern IPv6 privacy relay subnets.
* **Reverse DNS (rDNS / PTR) Analysis**: Live DNS-over-HTTPS inspection resolving authoritative subscriber hostnames vs. hosting nodes.
* **Zero Cold Starts**: Distributed serverless edge presence across 330+ locations globally for sub-millisecond execution overhead.

---

## Integration Guide: Protect Your Application

Sentinel integrates into any technology stack with minimal lines of code.

### 1. Node.js / Express Middleware

Protect website routes, login endpoints, and checkout flows:

```javascript
// middleware/sentinel.js
async function sentinelGuard(req, res, next) {
    const clientIP = req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    try {
        const response = await fetch(`https://api.antivpn.tech/v1/check?ip=${encodeURIComponent(clientIP)}`);
        const verdict = await response.json();

        if (verdict.action === "BLOCK") {
            console.warn(`[Sentinel] Blocked ${clientIP} (${verdict.threat_type}, Risk: ${verdict.risk_score}/100)`);
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
import requests
from fastapi import Request, HTTPException

SENTINEL_API = "https://api.antivpn.tech/v1/check"

def verify_connection(client_ip: str) -> bool:
    """Evaluates an IP address against Sentinel Edge intelligence."""
    try:
        res = requests.get(SENTINEL_API, params={"ip": client_ip}, timeout=2.0)
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
	"time"
)

type SentinelVerdict struct {
	IP         string `json:"ip"`
	Action     string `json:"action"`
	RiskScore  int    `json:"risk_score"`
	ThreatType string `json:"threat_type"`
}

var client = &http.Client{Timeout: 2 * time.Second}

func SentinelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("CF-Connecting-IP")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		resp, err := client.Get(fmt.Sprintf("https://api.antivpn.tech/v1/check?ip=%s", clientIP))
		if err == nil && resp.StatusCode == http.StatusOK {
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

Filter connections on Minecraft, Steam, or custom game server ingress before handshake:

```java
// Netty Channel Inbound Handler
public class SentinelIngressGuard extends ChannelInboundHandlerAdapter {

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        String clientIP = extractClientIP(ctx, msg);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.antivpn.tech/v1/check?ip=" + clientIP))
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

Inspect any target address in seconds:

```bash
# Query an arbitrary IP target
curl -s "https://api.antivpn.tech/v1/check?ip=185.213.154.20" | jq
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

## Project & Ownership

* **Developer & Architect**: [@undrrwrldd](https://github.com/undrrwrldd)
* **Live Showcase**: [https://antivpn.tech](https://antivpn.tech)
* **Edge Endpoint**: [https://api.antivpn.tech](https://api.antivpn.tech)
* **Copyright**: © 2026. All rights reserved.
