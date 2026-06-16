"""Aggregate findings into risk score and verdict."""

from __future__ import annotations

from src.attachments import SEVERITY_WEIGHT
from src.models import Finding, TriageReport, Verdict


def compute_verdict(
    findings: list[Finding],
    encrypted: bool,
    risk_score: int,
) -> Verdict:
    if encrypted:
        return Verdict.MANUAL_REVIEW

    severities = {f.severity for f in findings}
    if "critical" in severities or risk_score >= 70:
        return Verdict.PHISHING
    if risk_score >= 40 or "high" in severities:
        return Verdict.SUSPICIOUS
    if risk_score <= 15 and not any(s in severities for s in ("medium", "high", "critical")):
        return Verdict.LEGIT
    return Verdict.SUSPICIOUS


def score_findings(findings: list[Finding]) -> int:
    total = 0
    for f in findings:
        total += SEVERITY_WEIGHT.get(f.severity, 0)
    return min(total, 100)


def build_report(
    subject: str,
    sender: str,
    findings: list[Finding],
    auth_summary: dict,
    urls: list[str],
    qr_urls: list[str],
    encrypted: bool,
) -> TriageReport:
    risk = score_findings(findings)
    verdict = compute_verdict(findings, encrypted, risk)
    return TriageReport(
        subject=subject,
        sender=sender,
        verdict=verdict,
        risk_score=risk,
        findings=findings,
        auth_summary=auth_summary,
        urls_found=urls,
        qr_urls=qr_urls,
    )
