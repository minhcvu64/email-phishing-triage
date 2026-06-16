"""Extract URLs and common phishing patterns from email body."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from src.auth_check import domain_looks_like_spoof
from src.models import Finding

URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)


def extract_urls(plain: str, html: str) -> list[str]:
    urls: set[str] = set()
    for text in (plain, html):
        urls.update(URL_RE.findall(text))
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("http://", "https://")):
                urls.add(href)
        # Hidden text / display:none tricks
        for hidden in soup.find_all(style=re.compile(r"display\s*:\s*none", re.I)):
            if hidden.string:
                urls.update(URL_RE.findall(hidden.string))
    return sorted(urls)


def analyze_urls(urls: list[str], trusted_domains: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if not host:
            continue

        if trusted_domains and host in trusted_domains:
            findings.append(
                Finding(
                    category="url",
                    severity="info",
                    message=f"URL points to trusted domain: {host}",
                    evidence={"url": url},
                )
            )
            continue

        if trusted_domains and domain_looks_like_spoof(host, trusted_domains):
            findings.append(
                Finding(
                    category="url",
                    severity="critical",
                    message=f"Possible typosquat / lookalike domain: {host}",
                    evidence={"url": url},
                )
            )

        if parsed.scheme == "http":
            findings.append(
                Finding(
                    category="url",
                    severity="medium",
                    message=f"Non-HTTPS link: {url}",
                    evidence={"url": url},
                )
            )

        # IP-based URLs
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append(
                Finding(
                    category="url",
                    severity="high",
                    message=f"URL uses raw IP address: {url}",
                    evidence={"url": url},
                )
            )

    return findings


def analyze_content_patterns(plain: str, html: str) -> list[Finding]:
    findings: list[Finding] = []
    combined = f"{plain}\n{html}".lower()

    urgency_phrases = [
        "verify your account",
        "account suspended",
        "urgent action required",
        "click immediately",
        "confirm your password",
        "unusual activity",
        "invoice attached",
        "payment failed",
    ]
    for phrase in urgency_phrases:
        if phrase in combined:
            findings.append(
                Finding(
                    category="content",
                    severity="medium",
                    message=f"Urgency / credential lure phrase detected: '{phrase}'",
                    evidence={"phrase": phrase},
                )
            )

    if html and len(plain.strip()) < 20:
        img_count = html.lower().count("<img")
        if img_count >= 1 and img_count >= html.lower().count("<p"):
            findings.append(
                Finding(
                    category="content",
                    severity="medium",
                    message="Email is mostly images with little text (common in QR phishing)",
                    evidence={"image_tags": img_count},
                )
            )

    return findings
