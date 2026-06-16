"""Handle encrypted email edge cases."""

from __future__ import annotations

from email.message import EmailMessage

from src.models import Finding
from src.parser import is_encrypted


def check_encryption(msg: EmailMessage) -> list[Finding]:
    encrypted, enc_type = is_encrypted(msg)
    if not encrypted:
        return []

    return [
        Finding(
            category="encryption",
            severity="high",
            message=(
                f"Email body is encrypted ({enc_type}). Automated content/URL/QR analysis "
                "is limited — route to manual review or decrypt in a safe sandbox."
            ),
            evidence={"encryption_type": enc_type},
        ),
        Finding(
            category="encryption",
            severity="info",
            message=(
                "You can still inspect outer headers (From, Authentication-Results, "
                "Received chain) and envelope metadata."
            ),
            evidence={},
        ),
    ]
