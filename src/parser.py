"""Parse raw email bytes or .eml files into a structured message object."""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Any


def load_eml(path: str | Path) -> EmailMessage:
    raw = Path(path).read_bytes()
    return parse_bytes(raw)


def parse_bytes(raw: bytes) -> EmailMessage:
    return email.message_from_bytes(raw, policy=policy.default)


def get_header(msg: EmailMessage, name: str, default: str = "") -> str:
    value = msg.get(name, default)
    if isinstance(value, str):
        return value
    if value is None:
        return default
    return str(value)


def get_all_header_lines(msg: EmailMessage, name: str) -> list[str]:
    lines: list[str] = []
    for key, value in msg.items():
        if key.lower() == name.lower():
            lines.append(str(value))
    return lines


def extract_text_bodies(msg: EmailMessage) -> tuple[str, str]:
    """Return (plain_text, html) from message parts."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                continue
            if not isinstance(payload, str):
                continue
            if ctype == "text/plain":
                plain_parts.append(payload)
            elif ctype == "text/html":
                html_parts.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if isinstance(payload, str):
            if msg.get_content_type() == "text/html":
                html_parts.append(payload)
            else:
                plain_parts.append(payload)

    return "\n".join(plain_parts).strip(), "\n".join(html_parts).strip()


def iter_attachments(msg: EmailMessage) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if not filename and "attachment" not in disposition:
            continue
        if not filename:
            filename = "unnamed_attachment"
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        attachments.append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(data),
                "data": data,
            }
        )
    return attachments


def iter_inline_images(msg: EmailMessage) -> list[dict[str, Any]]:
    """Images embedded in HTML (cid:) or inline disposition."""
    images: list[dict[str, Any]] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if not ctype.startswith("image/"):
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disposition and "inline" not in disposition:
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        if not data:
            continue
        images.append(
            {
                "filename": part.get_filename() or f"inline.{ctype.split('/')[-1]}",
                "content_type": ctype,
                "data": data,
            }
        )
    return images


def is_encrypted(msg: EmailMessage) -> tuple[bool, str]:
    """
    Detect common encryption wrappers.
    Returns (is_encrypted, encryption_type).
    """
    ctype = msg.get_content_type().lower()
    if ctype in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
        return True, "S/MIME"
    if ctype == "multipart/encrypted":
        return True, "PGP/MIME"
    for part in msg.walk():
        ptype = part.get_content_type().lower()
        if ptype in ("application/pkcs7-mime", "application/pgp-encrypted"):
            return True, "S/MIME or PGP"
        if ptype == "application/octet-stream":
            filename = (part.get_filename() or "").lower()
            if filename.endswith((".pgp", ".gpg", ".asc")):
                return True, "PGP attachment"
    # PGP inline armor in body
    plain, _ = extract_text_bodies(msg)
    if "-----BEGIN PGP MESSAGE-----" in plain:
        return True, "PGP inline"
    return False, ""
