"""
cli.py - Command Line Interface for API Beacon Radar
Covert Financial Webhook & Open Banking Steganography Sentinel.
Zero external dependencies (Python 3.10+ standard library).
"""

import argparse
import json
import sys
import time
from .models import (
    WebhookEventEnvelope,
)
from .payload_entropy_scanner import PayloadEntropyScanner, compute_shannon_entropy
from .inter_arrival_analyzer import InterArrivalAnalyzer
from .covert_channel_sentinel import CovertChannelSentinel
from .a2zsoc_beacon_bridge import A2ZSocBeaconBridge


def run_stream_demo() -> None:
    print("=" * 85)
    print("🛰️ API BEACON RADAR - REAL-TIME FINANCIAL WEBHOOK INSPECTION STREAM")
    print("=" * 85)

    bridge = A2ZSocBeaconBridge()
    now = time.time()

    # Sequence of 5 periodic beacon arrivals from "SRC-BOTNET-01" (every 10 seconds)
    events = [
        # Event 1: Normal webhook
        WebhookEventEnvelope(
            event_id="EVT-01",
            provider="STRIPE",
            endpoint_path="/api/v1/webhooks/stripe",
            headers={"Content-Type": "application/json", "Stripe-Signature": "t=1700000000,v1=abc123def456"},
            payload_body='{"type": "invoice.paid", "amount": 25000, "customer": "cus_99124"}',
            metadata_fields={"order_reference": "Order-2024-MAR-0112"},
            timestamp=now - 40.0,
            client_source_id="SRC-BENIGN-01",
        ),
        # Events 2-5: Automated periodic beaconing from SRC-BOTNET-01 (spaced exactly 10s apart)
        WebhookEventEnvelope(
            event_id="EVT-02", provider="PLAID", endpoint_path="/api/v1/webhooks/plaid",
            headers={"Plaid-Verification": "standard_sig"},
            payload_body='{"webhook_type": "TRANSACTIONS", "webhook_code": "DEFAULT_UPDATE"}',
            metadata_fields={}, timestamp=now - 30.0, client_source_id="SRC-BOTNET-01",
        ),
        WebhookEventEnvelope(
            event_id="EVT-03", provider="PLAID", endpoint_path="/api/v1/webhooks/plaid",
            headers={"Plaid-Verification": "standard_sig"},
            payload_body='{"webhook_type": "TRANSACTIONS", "webhook_code": "DEFAULT_UPDATE"}',
            metadata_fields={}, timestamp=now - 20.0, client_source_id="SRC-BOTNET-01",
        ),
        WebhookEventEnvelope(
            event_id="EVT-04", provider="PLAID", endpoint_path="/api/v1/webhooks/plaid",
            headers={"Plaid-Verification": "standard_sig"},
            payload_body='{"webhook_type": "TRANSACTIONS", "webhook_code": "DEFAULT_UPDATE"}',
            metadata_fields={}, timestamp=now - 10.0, client_source_id="SRC-BOTNET-01",
        ),
        # Event 5: Combines 10s periodic beaconing with a high-entropy exfiltration header!
        WebhookEventEnvelope(
            event_id="EVT-05", provider="PLAID", endpoint_path="/api/v1/webhooks/plaid",
            headers={
                "Plaid-Verification": "standard_sig",
                "X-Telemetry-Token": "yZ9#pL8$mQ2!wK4@vR7&dF1^xN5*jB3~sC6%tH0+uA"  # Very high entropy!
            },
            payload_body='{"webhook_type": "TRANSACTIONS", "webhook_code": "DEFAULT_UPDATE"}',
            metadata_fields={"covert_drop": "k9Xm4zL8vKw2pRt7yBc1dFg5hJk3nPs6"},
            timestamp=now, client_source_id="SRC-BOTNET-01",
        ),
    ]

    for ev in events:
        dec = bridge.inspect_and_log(ev)
        print(f"\nEvent: {ev.event_id} ({ev.provider}) from {ev.client_source_id}")
        verdict_icon = "✅ ALLOW" if dec.verdict == "ALLOW" else ("🚨 " + dec.verdict)
        print(f"Verdict:              {verdict_icon}")
        print(f"Composite Threat:     {dec.composite_threat_score:.4f}")
        print(f"Execution Latency:    {dec.execution_latency_us:.2f} µs")
        print(f"Beacon Analysis:      Detected={dec.beacon_analysis.is_beacon_detected} (Cv={dec.beacon_analysis.coefficient_of_variation:.3f}, T={dec.beacon_analysis.estimated_period_seconds:.1f}s)")
        print(f"Stego Analysis:       Detected={dec.stego_analysis.is_steganography_detected} (Max H={dec.stego_analysis.max_entropy_found:.2f})")
        if dec.stego_analysis.offending_field:
            print(f"Offending Field:      {dec.stego_analysis.offending_field}")
        print(f"Audit Hash:           {dec.audit_hash[:32]}...")

    print("\n" + "=" * 85)


def run_benchmark(iterations: int = 5000) -> None:
    print(f"🚀 Running sub-millisecond API beacon inspection benchmark ({iterations} webhooks)...")
    sentinel = CovertChannelSentinel()
    now = time.time()
    env = WebhookEventEnvelope(
        event_id="BENCH", provider="STRIPE", endpoint_path="/hook",
        headers={"X-Sig": "standard_signature_here"}, payload_body='{"ok": true}',
        metadata_fields={"note": "standard payment note"}, timestamp=now, client_source_id="SRC-BENCH"
    )

    t0 = time.perf_counter()
    for _ in range(iterations):
        sentinel.inspect_webhook(env)
    t1 = time.perf_counter()

    elapsed = t1 - t0
    ops_per_sec = iterations / elapsed
    us_per_op = (elapsed / iterations) * 1_000_000

    print(f"Completed {iterations} inspections in {elapsed:.4f}s")
    print(f"Throughput: {ops_per_sec:,.0f} inspections/second")
    print(f"Latency:    {us_per_op:.2f} µs per inspection (< 0.05 ms)")


def main() -> None:
    parser = argparse.ArgumentParser(description="API Beacon Radar CLI")
    parser.add_argument("command", choices=["stream", "benchmark"], help="Command to run")
    parser.add_argument("--iterations", type=int, default=5000, help="Benchmark iterations")

    args = parser.parse_args()
    if args.command == "stream":
        run_stream_demo()
    elif args.command == "benchmark":
        run_benchmark(args.iterations)


if __name__ == "__main__":
    main()
