"""Hash attachments and optionally query VirusTotal."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from src.models import Finding

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".dll", ".hta", ".iso", ".lnk", ".docm", ".xlsm",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze_attachments_meta(attachments: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for att in attachments:
        name = att.get("filename", "")
        ext = os.path.splitext(name)[1].lower()
        size = att.get("size", 0)
        digest = sha256(att.get("data", b""))

        if ext in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category="attachment",
                    severity="high",
                    message=f"Dangerous attachment type: {name}",
                    evidence={"filename": name, "sha256": digest},
                )
            )
        elif ext in (".zip", ".rar", ".7z"):
            findings.append(
                Finding(
                    category="attachment",
                    severity="medium",
                    message=f"Archive attachment may hide malware: {name}",
                    evidence={"filename": name, "sha256": digest},
                )
            )
        else:
            findings.append(
                Finding(
                    category="attachment",
                    severity="info",
                    message=f"Attachment: {name} ({size} bytes)",
                    evidence={"filename": name, "sha256": digest, "size": size},
                )
            )
    return findings


def virustotal_lookup(file_hash: str, api_key: str) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    if not api_key:
        return {}, [
            Finding(
                category="virustotal",
                severity="info",
                message="VirusTotal skipped (no VIRUSTOTAL_API_KEY)",
                evidence={},
            )
        ]

    try:
        import vt
    except ImportError:
        return {}, [
            Finding(
                category="virustotal",
                severity="low",
                message="vt-py not installed",
                evidence={},
            )
        ]

    try:
        client = vt.Client(api_key)
        file_obj = client.get_object(f"/files/{file_hash}")
        stats = file_obj.last_analysis_stats or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        client.close()

        info = {"malicious": malicious, "suspicious": suspicious, "stats": dict(stats)}
        if malicious > 0:
            findings.append(
                Finding(
                    category="virustotal",
                    severity="critical",
                    message=f"VirusTotal: {malicious} engines flagged file as malicious",
                    evidence=info,
                )
            )
        elif suspicious > 0:
            findings.append(
                Finding(
                    category="virustotal",
                    severity="high",
                    message=f"VirusTotal: {suspicious} engines flagged file as suspicious",
                    evidence=info,
                )
            )
        else:
            findings.append(
                Finding(
                    category="virustotal",
                    severity="info",
                    message="VirusTotal: no malicious detections for hash",
                    evidence=info,
                )
            )
        return info, findings
    except Exception as exc:
        err = str(exc).lower()
        if "not found" in err or "404" in err:
            return {}, [
                Finding(
                    category="virustotal",
                    severity="info",
                    message="File hash not in VirusTotal database (unknown file)",
                    evidence={"sha256": file_hash},
                )
            ]
        return {}, [
            Finding(
                category="virustotal",
                severity="low",
                message=f"VirusTotal API error: {exc}",
                evidence={"sha256": file_hash},
            )
        ]
