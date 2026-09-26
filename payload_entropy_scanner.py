"""
payload_entropy_scanner.py - Payload Shannon Entropy & Steganography Scanner
Analyzes financial webhook headers and metadata fields for high-entropy encrypted blobs
and covert dead-drop exfiltration payloads.
Zero external dependencies (Python 3.10+ standard library).
"""

import base64
import binascii
import math
import re
from typing import Dict, Optional, Tuple
from .models import WebhookEventEnvelope, SteganographyAnalysisResult


def compute_shannon_entropy(data: str) -> float:
    """Computes Shannon information entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class PayloadEntropyScanner:
    """Evaluates financial API payloads for covert steganography and encrypted blobs."""

    def __init__(
        self,
        entropy_threshold: float = 4.70,
        min_blob_length: int = 24,
    ):
        self.entropy_threshold = entropy_threshold
        self.min_blob_length = min_blob_length

    def scan_envelope(self, envelope: WebhookEventEnvelope) -> SteganographyAnalysisResult:
        """
        Scans headers, body, and metadata for hidden high-entropy payloads.
        """
        max_entropy = 0.0
        offending_field = None
        extracted_sample = None

        # 1. Inspect custom headers
        for k, v in envelope.headers.items():
            if len(v) >= self.min_blob_length:
                ent = compute_shannon_entropy(v)
                if ent > max_entropy:
                    max_entropy = ent
                    if ent > self.entropy_threshold:
                        offending_field = f"header:{k}"
                        extracted_sample = v[:32] + "..." if len(v) > 32 else v

        # 2. Inspect metadata fields
        for k, v in envelope.metadata_fields.items():
            if len(v) >= self.min_blob_length:
                ent = compute_shannon_entropy(v)
                if ent > max_entropy:
                    max_entropy = ent
                    if ent > self.entropy_threshold:
                        offending_field = f"metadata:{k}"
                        extracted_sample = v[:32] + "..." if len(v) > 32 else v

        # 3. Check for raw hex or base64 dead-drop strings in payload body
        if not offending_field and len(envelope.payload_body) > self.min_blob_length:
            b64_matches = re.findall(r'[A-Za-z0-9+/]{32,}={0,2}', envelope.payload_body)
            for m in b64_matches:
                ent = compute_shannon_entropy(m)
                if ent > max_entropy:
                    max_entropy = ent
                if ent > self.entropy_threshold:
                    offending_field = "body:embedded_base64"
                    extracted_sample = m[:32] + "..."
                    break

        is_stego = (offending_field is not None and max_entropy > self.entropy_threshold)

        if is_stego:
            rationale = (
                f"HIGH-ENTROPY ANOMALY DETECTED in '{offending_field}' (H={max_entropy:.2f} > {self.entropy_threshold}). "
                f"Byte distribution indicates encrypted binary, compressed payload, or C2 dead-drop token."
            )
        else:
            rationale = f"All inspected webhook fields exhibit expected natural or JSON entropy profiles (Max H={max_entropy:.2f})."

        return SteganographyAnalysisResult(
            is_steganography_detected=is_stego,
            max_entropy_found=max_entropy,
            offending_field=offending_field,
            extracted_blob_sample=extracted_sample,
            rationale=rationale,
        )
