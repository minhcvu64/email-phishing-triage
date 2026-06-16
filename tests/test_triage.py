import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models import Verdict
from src.triage import triage_eml


SAMPLES = ROOT / "samples"


def test_legit_sample_has_lower_risk_than_phishing():
    legit = triage_eml(SAMPLES / "legit_order.eml")
    phish = triage_eml(SAMPLES / "phishing_urgency.eml")
    assert phish.risk_score > legit.risk_score
    assert phish.verdict in (Verdict.PHISHING, Verdict.SUSPICIOUS)


def test_phishing_detects_auth_failures():
    report = triage_eml(SAMPLES / "phishing_urgency.eml")
    messages = " ".join(f.message for f in report.findings)
    assert "DKIM failed" in messages or "SPF failed" in messages or "DMARC failed" in messages


def test_extracts_urls_from_phishing():
    report = triage_eml(SAMPLES / "phishing_urgency.eml")
    assert any("192.168" in u for u in report.urls_found)


def test_image_only_flags_content_pattern():
    report = triage_eml(SAMPLES / "image_only_phishing.eml")
    messages = " ".join(f.message for f in report.findings)
    assert "image" in messages.lower() or report.risk_score >= 15
