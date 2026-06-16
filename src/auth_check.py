"""SPF / DKIM / DMARC signals from headers and DNS."""

from __future__ import annotations

import re
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlparse

import dns.resolver

from src.models import Finding
from src.parser import get_all_header_lines, get_header


def _parse_authentication_results(lines: list[str]) -> dict[str, str]:
    """
    Parse Authentication-Results headers (simplified).
    Example: dkim=pass; spf=pass; dmarc=pass
    """
    results: dict[str, str] = {}
    pattern = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*(\w+)", re.IGNORECASE)
    for line in lines:
        for match in pattern.finditer(line):
            results[match.group(1).lower()] = match.group(2).lower()
    return results


def _domain_from_address(addr: str) -> str:
    match = re.search(r"@[\w.\-]+", addr)
    if not match:
        return ""
    return match.group(0).lstrip("@").lower()


def check_auth_headers(msg: EmailMessage) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    auth_lines = get_all_header_lines(msg, "Authentication-Results")
    received_spf = get_all_header_lines(msg, "Received-SPF")
    parsed = _parse_authentication_results(auth_lines)

    from_header = get_header(msg, "From")
    return_path = get_header(msg, "Return-Path")
    from_domain = _domain_from_address(from_header)

    summary: dict[str, Any] = {
        "from_domain": from_domain,
        "authentication_results": parsed,
        "received_spf_lines": received_spf,
    }

    for mechanism in ("spf", "dkim", "dmarc"):
        status = parsed.get(mechanism)
        if not status:
            findings.append(
                Finding(
                    category="auth",
                    severity="medium",
                    message=f"No {mechanism.upper()} result in Authentication-Results header",
                    evidence={"mechanism": mechanism},
                )
            )
            continue
        if status == "pass":
            findings.append(
                Finding(
                    category="auth",
                    severity="info",
                    message=f"{mechanism.upper()} passed",
                    evidence={"status": status},
                )
            )
        elif status in ("fail", "hardfail"):
            findings.append(
                Finding(
                    category="auth",
                    severity="critical",
                    message=f"{mechanism.upper()} failed — strong phishing indicator",
                    evidence={"status": status},
                )
            )
        else:
            findings.append(
                Finding(
                    category="auth",
                    severity="medium",
                    message=f"{mechanism.upper()} result: {status}",
                    evidence={"status": status},
                )
            )

    # From vs Return-Path mismatch
    rp_domain = _domain_from_address(return_path)
    if from_domain and rp_domain and from_domain != rp_domain:
        findings.append(
            Finding(
                category="auth",
                severity="high",
                message="From domain does not match Return-Path domain",
                evidence={"from": from_domain, "return_path": rp_domain},
            )
        )

    # Reply-To different from From (common in BEC/phishing)
    reply_to = get_header(msg, "Reply-To")
    reply_domain = _domain_from_address(reply_to)
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            Finding(
                category="auth",
                severity="high",
                message="Reply-To domain differs from From domain",
                evidence={"from": from_domain, "reply_to": reply_domain},
            )
        )

    summary["from_return_path_match"] = not (
        from_domain and rp_domain and from_domain != rp_domain
    )
    return summary, findings


def _fetch_dmarc_policy(from_domain: str) -> tuple[str, str]:
    """Return (policy, raw_txt) from _dmarc DNS record."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{from_domain}", "TXT")
    except Exception as exc:
        return "missing", str(exc)

    for rdata in answers:
        txt = "".join(
            s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings
        )
        match = re.search(r"\bp=(\w+)", txt, re.IGNORECASE)
        if match:
            return match.group(1).lower(), txt
    return "none", ""


def check_dmarc_policy(from_domain: str) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    if not from_domain:
        return {}, findings

    try:
        policy, raw = _fetch_dmarc_policy(from_domain)
    except Exception as exc:
        findings.append(
            Finding(
                category="dmarc_dns",
                severity="low",
                message=f"Could not query DMARC for {from_domain}: {exc}",
                evidence={"domain": from_domain},
            )
        )
        return {"error": str(exc)}, findings

    info: dict[str, Any] = {"domain": from_domain, "dmarc_policy": policy, "record": raw}

    if policy == "none":
        findings.append(
            Finding(
                category="dmarc_dns",
                severity="low",
                message=f"Sender domain {from_domain} has weak DMARC policy (p=none)",
                evidence={"policy": policy},
            )
        )
    elif policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                category="dmarc_dns",
                severity="info",
                message=f"Sender domain publishes strict DMARC (p={policy})",
                evidence={"policy": policy},
            )
        )

    return info, findings


def domain_looks_like_spoof(url_or_domain: str, trusted_domains: list[str]) -> bool:
    """Heuristic: typosquat / lookalike vs trusted shop domains."""
    domain = url_or_domain.lower()
    if "://" in domain:
        domain = urlparse(domain).netloc or domain
    domain = domain.split(":")[0]
    if domain in trusted_domains:
        return False
    for trusted in trusted_domains:
        if trusted in domain or domain in trusted:
            continue
        # homoglyph-style: paypa1.com vs paypal.com
        if _levenshtein(domain, trusted) <= 2 and domain != trusted:
            return True
    return False


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]
