# API Beacon Radar
### Covert Financial Webhook & Open Banking Steganography Sentinel

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Zero-Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)]()
[![Throughput](https://img.shields.io/badge/Throughput->160k_inspections%2Fsec-orange.svg)]()
[![Latency](https://img.shields.io/badge/Latency-6.21_µs-brightgreen.svg)]()

`api-beacon-radar` is an institutional-grade, zero-external-dependency inline defensive sensor engineered for payment gateways, FinTech SaaS APIs, and Open Banking switches (Stripe, Plaid, FDX 6.0, Adyen). It protects high-volume financial webhook streams from being hijacked as **covert Command and Control (C2) communication channels, periodic beaconing tunnels, and dead-drop data exfiltration registers**.

```
    [ Incoming Financial Webhooks (Stripe / Plaid / FDX 6.0 / Adyen) ]
                                    │
                                    ▼
    ┌──────────────────────────────────────────────────────────────┐
    │                     API Beacon Radar                         │
    ├──────────────────────────────┬───────────────────────────────┤
    │ Vector 1: Statistical Timing │ Vector 2: Information Entropy │
    │ Inter-Arrival Time (IAT)     │ Shannon Entropy H(X)          │
    │ Coefficient of Variation Cv  │ Custom Headers, Nonces & Body │
    │ Periodicity & Jitter Cluster │ High-Entropy Hex/Base64 Blobs │
    └──────────────┬───────────────┴───────────────┬───────────────┘
                   │                               │
                   ▼                               ▼
    ┌──────────────────────────────────────────────────────────────┐
    │       Composite Threat Scorer & Autonomous Gateway Gate      │
    │       Threat = 0.60 * StegoScore + 0.40 * BeaconScore        │
    └──────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
        [ Real-Time Verdict: ALLOW | QUARANTINE | DROP_ALERT ]
        [ Chained SHA-256 Telemetry Stream to a2zsoc.com Vault ]
```

---

## 🏛️ The Financial API Covert Channel Threat

Modern FinTechs exchange hundreds of millions of webhooks and API calls daily. Because this traffic is high-frequency, TLS-encrypted, and essential for revenue operations, it represents the ultimate blind spot for enterprise security teams:
1. **Algorithmic C2 Beaconing**: Compromised payment switches or insider malware communicate with external servers by modulating webhook delivery intervals. Even with synthetic jitter (e.g. 10%–20%), the inter-arrival time displays an abnormally low Coefficient of Variation ($C_v \le 0.25$) compared to Poisson-distributed natural business traffic ($C_v \approx 1.0$).
2. **Dead-Drop Exfiltration**: Attackers embed encrypted stolen cardholder data, customer PII, or internal tokens within custom webhook headers (e.g., `X-Signature-Nonce`), metadata key-value pairs, or payment reference fields.
3. **Idempotency Abuse**: Threat actors repeatedly fire failed webhook retry events with mutating idempotency tokens, turning standard API gateways into asynchronous C2 dead-drop message registers.

---

## 📐 Mathematical Formulation

### 1. Inter-Arrival Time (IAT) Coefficient of Variation ($C_v$)
Given a sequence of $n$ consecutive webhook arrival timestamps $t_1, t_2, \dots, t_n$, the inter-arrival deltas are defined as:

$$\Delta t_i = t_{i} - t_{i-1} \quad \text{for } i \in \{2, \dots, n\}$$

The mean interval $\mu$ and standard deviation $\sigma$ are:

$$\mu = \frac{1}{n-1} \sum_{i=2}^n \Delta t_i, \quad \sigma = \sqrt{\frac{1}{n-1} \sum_{i=2}^n (\Delta t_i - \mu)^2}$$

The Coefficient of Variation ($C_v$) evaluates periodicity:

$$C_v = \frac{\sigma}{\mu}$$

* **Natural Business Traffic**: $C_v \ge 0.50$ (stochastic Poisson process).
* **Algorithmic C2 Beaconing**: $C_v \le 0.25$ (programmatic periodic timer, even with 10%–20% random jitter).

### 2. Shannon Information Entropy ($H$)
To distinguish structured English or JSON metadata from encrypted exfiltration strings:

$$H(X) = -\sum_{i=1}^k P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the probability of character $x_i$ appearing in the target string.
* Strings with $H(X) > 4.70$ and length $\ge 24$ characters are flagged as **encrypted/steganographic payloads**.

---

## ⚡ System Sequence Architecture

```mermaid
sequenceDiagram
    autonumber
    actor Client as External Webhook Source (Stripe/C2)
    participant Gateway as API Gateway / Reverse Proxy
    participant Radar as A2ZSocBeaconBridge
    participant Timing as InterArrivalAnalyzer
    participant Stego as PayloadEntropyScanner
    participant SOC as a2zsoc Evidence Vault

    Client->>Gateway: POST /api/v1/webhooks/payment
    Gateway->>Radar: inspect_and_log(WebhookEnvelope)
    
    par Parallel Vector Inspection
        Radar->>Timing: record_and_analyze(SourceID, Timestamp)
        Timing-->>Radar: BeaconAnalysisResult (Cv, Period T)
    and
        Radar->>Stego: scan_envelope(Envelope)
        Stego-->>Radar: SteganographyAnalysisResult (Entropy, Field)
    end
    
    Radar->>Radar: Compute Composite Threat Score
    
    alt If Both Beaconing & Steganography (Threat >= 0.85)
        Radar->>SOC: Chained SHA-256 Audit Hash (DROP_ALERT)
        Radar-->>Gateway: DROP_ALERT (Terminated inline in < 7 µs)
        Gateway-->>Client: HTTP 403 / Signature Rejected
    else If High Entropy Steganography Detected
        Radar->>SOC: Chained SHA-256 Audit Hash (QUARANTINE_WEBHOOK)
        Radar-->>Gateway: QUARANTINE_WEBHOOK (Held in Sandbox)
    else
        Radar->>SOC: Telemetry Event Logged (ALLOW)
        Radar-->>Gateway: ALLOW (Forwarded to internal worker)
    end
```

---

## ⚡ Performance Benchmark

Benchmarked on Apple Silicon (M-series) using pure Python standard library:

| Metric | Measured Value | Standard Required |
| :--- | :--- | :--- |
| **Inline Inspection Latency** | **6.21 µs / inspection** | $< 1\text{ ms}$ |
| **Inspection Throughput** | **161,099 webhooks / sec** | $> 10,000\text{ webhooks / sec}$ |
| **External Dependencies** | **0 (Zero)** | Standard Library |
| **Audit Hash Overhead** | **$< 2 \text{ µs}$** | N/A |

---

## 🚀 Quickstart & Usage

### 1. Installation
```bash
git clone https://github.com/AAH20/api-beacon-radar.git
cd api-beacon-radar
```

### 2. Run Stream Inspection Demo
```bash
python3 -m projects.api_beacon_radar.cli stream
```
Output:
```text
=====================================================================================
🛰️ API BEACON RADAR - REAL-TIME FINANCIAL WEBHOOK INSPECTION STREAM
=====================================================================================

Event: EVT-01 (STRIPE) from SRC-BENIGN-01
Verdict:              ✅ ALLOW
Composite Threat:     0.0800
Execution Latency:    59.17 µs
Beacon Analysis:      Detected=False (Cv=1.000, T=0.0s)
Stego Analysis:       Detected=False (Max H=3.71)
Audit Hash:           0c5b83a55d6998537d0f9f400cc70598...

Event: EVT-05 (PLAID) from SRC-BOTNET-01
Verdict:              🚨 DROP_ALERT
Composite Threat:     0.9100
Execution Latency:    30.08 µs
Beacon Analysis:      Detected=True (Cv=0.000, T=10.0s)
Stego Analysis:       Detected=True (Max H=5.39)
Offending Field:      header:X-Telemetry-Token
Audit Hash:           46cf73c0fbb54224fd07e86ba7889a7a...
=====================================================================================
```

### 3. Run Latency Benchmark
```bash
python3 -m projects.api_beacon_radar.cli benchmark --iterations 5000
```

---

## 💻 Python Programmatic API

```python
from api_beacon_radar import (
    A2ZSocBeaconBridge,
    WebhookEventEnvelope,
)
import time

# 1. Initialize institutional bridge
bridge = A2ZSocBeaconBridge()

# 2. Ingest incoming webhook
envelope = WebhookEventEnvelope(
    event_id="HOOK-90214",
    provider="STRIPE",
    endpoint_path="/webhooks/v1",
    headers={
        "Content-Type": "application/json",
        "X-Custom-Nonce": "q9Xm4zL8vKw2pRt7yBc1dFg5hJk3nPs6",  # High-entropy header
    },
    payload_body='{"status": "succeeded", "amount": 10000}',
    metadata_fields={"ref": "Order-101"},
    timestamp=time.time(),
    client_source_id="IP-198.51.100.42",
)

# 3. Inspect in real time (< 10 µs)
decision = bridge.inspect_and_log(envelope)

print(f"Verdict:       {decision.verdict}")
print(f"Threat Score:  {decision.composite_threat_score}")
print(f"Latency:       {decision.execution_latency_us:.2f} µs")
print(f"Audit Hash:    {decision.audit_hash}")
```

---

## 🧪 Testing

Execute the test suite with 100% standard library coverage:
```bash
python3 -m unittest discover -s projects/api_beacon_radar/tests
```

---

## 📜 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
