"""
test_api_beacon_radar.py - Unit Tests for API Beacon Radar
Zero external dependencies (Python 3.10+ standard library).
"""

import unittest
import time
from projects.api_beacon_radar.models import (
    WebhookEventEnvelope,
)
from projects.api_beacon_radar.payload_entropy_scanner import (
    PayloadEntropyScanner,
    compute_shannon_entropy,
)
from projects.api_beacon_radar.inter_arrival_analyzer import (
    InterArrivalAnalyzer,
)
from projects.api_beacon_radar.covert_channel_sentinel import (
    CovertChannelSentinel,
)
from projects.api_beacon_radar.a2zsoc_beacon_bridge import (
    A2ZSocBeaconBridge,
)


class TestApiBeaconRadar(unittest.TestCase):
    def test_shannon_entropy_scanner(self):
        scanner = PayloadEntropyScanner(entropy_threshold=4.65)
        # Normal webhook
        benign_env = WebhookEventEnvelope(
            event_id="E1", provider="STRIPE", endpoint_path="/hook",
            headers={"Content-Type": "application/json"},
            payload_body='{"invoice": "inv_12345", "status": "paid"}',
            metadata_fields={"note": "Payment for software license"},
        )
        res_benign = scanner.scan_envelope(benign_env)
        self.assertFalse(res_benign.is_steganography_detected)
        self.assertLess(res_benign.max_entropy_found, 4.65)

        # High-entropy encrypted header
        stego_env = WebhookEventEnvelope(
            event_id="E2", provider="STRIPE", endpoint_path="/hook",
            headers={"X-Covert-Payload": "yZ9#pL8$mQ2!wK4@vR7&dF1^xN5*jB3~sC6%tH0+uA"},
            payload_body='{"invoice": "inv_12345"}',
        )
        res_stego = scanner.scan_envelope(stego_env)
        self.assertTrue(res_stego.is_steganography_detected)
        self.assertGreater(res_stego.max_entropy_found, 4.65)

    def test_inter_arrival_beaconing_detection(self):
        analyzer = InterArrivalAnalyzer(min_events_required=4, cv_beacon_threshold=0.25)
        now = 1000.0

        # Feed 5 periodic timestamps exactly 10s apart (+/- 0.2s jitter)
        timestamps = [now, now + 10.1, now + 20.0, now + 30.2, now + 40.1]
        results = [analyzer.record_and_analyze("SRC-BEACON", ts) for ts in timestamps]

        # First 3 events have insufficient history
        self.assertFalse(results[0].is_beacon_detected)
        self.assertFalse(results[1].is_beacon_detected)
        # 4th and 5th should detect low Cv and fire beacon alarm!
        self.assertTrue(results[3].is_beacon_detected)
        self.assertTrue(results[4].is_beacon_detected)
        self.assertLess(results[4].coefficient_of_variation, 0.25)

    def test_sentinel_verdicts_and_drop(self):
        sentinel = CovertChannelSentinel()
        now = 5000.0

        # Normal event -> ALLOW
        env_allow = WebhookEventEnvelope(
            event_id="A1", provider="STRIPE", endpoint_path="/hook",
            payload_body='{"status": "ok"}', timestamp=now, client_source_id="SRC-A"
        )
        dec_allow = sentinel.inspect_webhook(env_allow)
        self.assertEqual(dec_allow.verdict, "ALLOW")

        # High-entropy header -> QUARANTINE_WEBHOOK
        env_quarantine = WebhookEventEnvelope(
            event_id="Q1", provider="STRIPE", endpoint_path="/hook",
            headers={"X-Drop": "a8K!vM9#zL2$wP4%qR7^tY0&bC3*xD5(jH1)"},
            payload_body='{"status": "ok"}', timestamp=now, client_source_id="SRC-Q"
        )
        dec_quarantine = sentinel.inspect_webhook(env_quarantine)
        self.assertEqual(dec_quarantine.verdict, "QUARANTINE_WEBHOOK")

    def test_a2zsoc_bridge_logging(self):
        bridge = A2ZSocBeaconBridge()
        env = WebhookEventEnvelope("EV-1", "STRIPE", "/hook", payload_body="{}", timestamp=time.time())
        dec = bridge.inspect_and_log(env)
        self.assertEqual(len(dec.audit_hash), 64)

        telemetry = bridge.get_telemetry_events()
        self.assertEqual(len(telemetry), 1)
        self.assertEqual(telemetry[0]["event_type"], "API_RADAR_INSPECTION_DECISION")


if __name__ == "__main__":
    unittest.main()
