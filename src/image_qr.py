"""Detect QR codes inside inline/attached images (image-only phishing)."""

from __future__ import annotations

import io
import re
from typing import Any

from src.models import Finding

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as decode_qr

    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


def scan_images_for_qr(images: list[dict[str, Any]]) -> tuple[list[str], list[Finding]]:
    """
    Decode QR payloads from image bytes.
    Returns list of decoded strings (often URLs).
    """
    findings: list[Finding] = []
    decoded: list[str] = []

    if not images:
        return decoded, findings

    if not QR_AVAILABLE:
        findings.append(
            Finding(
                category="qr",
                severity="low",
                message="QR scanning unavailable (install Pillow + pyzbar; on macOS: brew install zbar)",
                evidence={},
            )
        )
        return decoded, findings

    for img in images:
        data = img.get("data", b"")
        name = img.get("filename", "image")
        if not data:
            continue
        try:
            image = Image.open(io.BytesIO(data))
            for symbol in decode_qr(image):
                payload = symbol.data.decode("utf-8", errors="replace").strip()
                if payload and payload not in decoded:
                    decoded.append(payload)
                    findings.append(
                        Finding(
                            category="qr",
                            severity="high",
                            message=f"QR code found in {name}",
                            evidence={"filename": name, "payload": payload},
                        )
                    )
        except Exception as exc:
            findings.append(
                Finding(
                    category="qr",
                    severity="low",
                    message=f"Could not scan {name} for QR: {exc}",
                    evidence={"filename": name},
                )
            )

    for payload in decoded:
        if _looks_like_url(payload):
            if re.search(r"bit\.ly|tinyurl|t\.co|goo\.gl", payload, re.I):
                findings.append(
                    Finding(
                        category="qr",
                        severity="critical",
                        message="QR contains shortened URL — high phishing risk",
                        evidence={"url": payload},
                    )
                )

    return decoded, findings


def _looks_like_url(text: str) -> bool:
    return text.startswith(("http://", "https://")) or "://" in text
