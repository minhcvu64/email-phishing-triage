from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    LEGIT = "legit"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MANUAL_REVIEW = "manual_review"


@dataclass
class Finding:
    category: str
    severity: str  # info | low | medium | high | critical
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriageReport:
    subject: str
    sender: str
    verdict: Verdict
    risk_score: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    auth_summary: dict[str, Any] = field(default_factory=dict)
    urls_found: list[str] = field(default_factory=list)
    qr_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "message": f.message,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "auth_summary": self.auth_summary,
            "urls_found": self.urls_found,
            "qr_urls": self.qr_urls,
        }
