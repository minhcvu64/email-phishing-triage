"""Main triage pipeline — wire all checks together."""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv

from src.attachments import analyze_attachments_meta, sha256, virustotal_lookup
from src.auth_check import check_auth_headers, check_dmarc_policy
from src.encrypted import check_encryption
from src.image_qr import scan_images_for_qr
from src.indicators import analyze_content_patterns, analyze_urls, extract_urls
from src.models import TriageReport
from src.parser import (
    extract_text_bodies,
    get_header,
    is_encrypted,
    iter_attachments,
    iter_inline_images,
    load_eml,
)
from src.scorer import build_report


def triage_eml(path: str | Path) -> TriageReport:
    load_dotenv()
    trusted = [
        d.strip().lower()
        for d in os.getenv("TRUSTED_DOMAINS", "").split(",")
        if d.strip()
    ]
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    msg = load_eml(path)
    subject = get_header(msg, "Subject", "(no subject)")
    sender = get_header(msg, "From", "(unknown)")

    findings: list = []
    enc_flag, _ = is_encrypted(msg)
    findings.extend(check_encryption(msg))

    auth_summary, auth_findings = check_auth_headers(msg)
    findings.extend(auth_findings)

    from_domain = auth_summary.get("from_domain", "")
    if from_domain:
        _, dmarc_findings = check_dmarc_policy(from_domain)
        findings.extend(dmarc_findings)

    if not enc_flag:
        plain, html = extract_text_bodies(msg)
        urls = extract_urls(plain, html)
        findings.extend(analyze_urls(urls, trusted))
        findings.extend(analyze_content_patterns(plain, html))

        attachments = iter_attachments(msg)
        findings.extend(analyze_attachments_meta(attachments))

        for att in attachments:
            digest = sha256(att.get("data", b""))
            if att.get("size", 0) > 0:
                _, vt_findings = virustotal_lookup(digest, vt_key)
                findings.extend(vt_findings)

        images = iter_inline_images(msg)
        # Also treat image attachments as QR scan targets
        for att in attachments:
            if (att.get("content_type") or "").startswith("image/"):
                images.append(att)

        qr_payloads, qr_findings = scan_images_for_qr(images)
        findings.extend(qr_findings)
        if qr_payloads:
            qr_urls = [p for p in qr_payloads if p.startswith("http")]
            findings.extend(analyze_urls(qr_urls, trusted))
    else:
        urls = []
        qr_payloads = []

    return build_report(
        subject=subject,
        sender=sender,
        findings=findings,
        auth_summary=auth_summary,
        urls=urls if not enc_flag else [],
        qr_urls=qr_payloads if not enc_flag else [],
        encrypted=enc_flag,
    )


def main() -> None:
    import argparse

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    parser = argparse.ArgumentParser(
        description="Triage an email (.eml) for phishing indicators",
    )
    parser.add_argument("eml_path", help="Path to .eml file")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    args = parser.parse_args()

    report = triage_eml(args.eml_path)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return

    console = Console()
    color = {
        "legit": "green",
        "suspicious": "yellow",
        "phishing": "red",
        "manual_review": "magenta",
    }.get(report.verdict.value, "white")

    console.print(
        Panel(
            f"[bold]{report.subject}[/bold]\nFrom: {report.sender}\n"
            f"Risk score: {report.risk_score}/100\n"
            f"Verdict: [{color}]{report.verdict.value.upper()}[/{color}]",
            title="Email Triage Report",
        )
    )

    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Message")
    for f in report.findings:
        table.add_row(f.severity, f.category, f.message)
    console.print(table)

    if report.urls_found:
        console.print("\n[bold]URLs:[/bold]", ", ".join(report.urls_found))
    if report.qr_urls:
        console.print("\n[bold]QR payloads:[/bold]", ", ".join(report.qr_urls))


if __name__ == "__main__":
    main()
