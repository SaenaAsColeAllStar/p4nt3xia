"""Target URL/domain/IP parsing helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    """Return a usable URL or host string."""
    value = raw.strip()
    if not value:
        raise ValueError("Target cannot be empty")
    if "://" not in value:
        # Assume HTTPS for bare domains; leave IPs as-is for nmap
        try:
            ipaddress.ip_address(value.split("/")[0].split(":")[0])
            return value
        except ValueError:
            return f"https://{value}"
    return value


def extract_host(raw: str) -> str:
    """Extract hostname/IP from URL or host string."""
    value = raw.strip()
    if "://" not in value:
        return value.split("/")[0].split(":")[0]
    parsed = urlparse(value)
    host = parsed.hostname or value
    return host


def extract_domain(raw: str) -> str:
    """Best-effort apex/domain for subdomain tools."""
    host = extract_host(raw)
    # Strip common www prefix
    if host.startswith("www."):
        host = host[4:]
    return host


def is_valid_target(raw: str) -> bool:
    value = raw.strip()
    if not value:
        return False
    try:
        host = extract_host(value)
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        # Basic domain / hostname check
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-.]{0,251}[a-zA-Z0-9])?$", host))
    except Exception:
        return False


def base_url(raw: str) -> str:
    """Return scheme://host[:port] for fuzzing/crawling."""
    value = normalize_target(raw)
    if "://" not in value:
        return f"https://{value}"
    parsed = urlparse(value)
    netloc = parsed.netloc or extract_host(value)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{netloc}"
