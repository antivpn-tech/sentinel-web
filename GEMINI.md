# Agent & Contributor Guidelines — Sentinel Web Portal

## 🛡️ Public Codebase Confidentiality & Terminology Rules

This repository is **publicly accessible**. To protect the proprietary integrity of the Sentinel Edge Intelligence platform, all contributors and AI agents must adhere to the following rules:

### 1. Zero Disclosure of Detection Mechanics
- **Never reveal internal detection mechanics**: Do not document, describe, or commit internal heuristics, clock/timezone skew calculations, DNS-over-HTTPS (DoH) PTR query logic, WebRTC candidate scanning, or internal scoring formulas.
- **No upstream feed references**: Never name or reference upstream raw threat lists or third-party feed providers.

### 2. Mandatory Proprietary Terminology
Always use Sentinel's proprietary terms across documentation, UI copy, mock telemetry, and code comments:
- **Threat Intelligence Sources**: Refer to threat data exclusively as the **Sentinel Global Threat Grid** or **Sentinel Threat Network**.
- **Carrier & AS Resolution**: Refer to Autonomous System categorization as **Carrier Network Classification** or **Carrier & Topology Intelligence**.
- **Residential Proxy Mitigation**: Refer to tunnel detection as **Dynamic Tunnel & Gateway Behavioral Anomaly Detection** or **Temporal & Edge Ingress Consistency**.
- **Anti-Bot & Velocity Protection**: Refer to connection flood suppression as **Sentinel Gate** or **Join Velocity Shielding**.
- **Edge Data Privacy**: Refer to inspection as **Zero-Log Volatile Memory Architecture** or **Stateless Edge Processing**.

### 3. Credential & Example Hygiene
- Only placeholder license keys (`stl_live_your_api_key_here`) or sandbox demo keys (`stl_test_showcase_demo`) may appear in documentation or code.
- Never commit live production API credentials or sensitive keys.
- Do not use regional ISP references in examples (e.g., Movistar, VTR). Use generic international carriers.
