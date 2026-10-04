"""Extract lexical URL features without resolving or visiting the destination."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "slash_count",
    "question_count",
    "equals_count",
    "percent_count",
    "digit_count",
    "digit_ratio",
    "subdomain_count",
    "has_https",
    "has_ip_address",
    "has_punycode",
    "has_username_or_password",
    "has_nonstandard_port",
    "has_shortener_domain",
    "suspicious_term_count",
    "has_double_slash_in_path",
)

SUSPICIOUS_TERMS = (
    "account", "billing", "confirm", "credential", "invoice", "login",
    "password", "payment", "secure", "signin", "suspended", "unlock",
    "update", "verify", "wallet",
)
SHORTENER_DOMAINS = frozenset(
    {"bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "rebrand.ly", "t.co", "tinyurl.com"}
)


@dataclass(frozen=True)
class URLAnalysis:
    normalized_url: str
    hostname: str
    protocol: str
    features: dict[str, float]
    indicators: list[str]

    def as_vector(self) -> list[float]:
        return [self.features[name] for name in FEATURE_NAMES]


def _parse_url(value: str) -> tuple[str, SplitResult, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a URL or domain to analyze.")
    if any(character.isspace() for character in raw):
        raise ValueError("URLs cannot contain spaces.")

    candidate = raw if re.match(r"^[a-z][a-z\d+.-]*://", raw, re.IGNORECASE) else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid URL with a complete hostname.") from error

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
    if not hostname or "." not in hostname.strip("[]"):
        raise ValueError("Enter a complete domain, such as example.com.")

    _ = port  # Accessing parsed.port above validates malformed and out-of-range ports.
    normalized = parsed.geturl()
    return normalized, parsed, hostname.lower().rstrip(".")


def analyze_url(value: str) -> URLAnalysis:
    """Return ordered lexical features and human-readable URL indicators."""
    normalized, parsed, hostname = _parse_url(value)
    host_without_brackets = hostname.strip("[]")
    try:
        ipaddress.ip_address(host_without_brackets)
        has_ip = 1.0
    except ValueError:
        has_ip = 0.0

    host_labels = hostname.split(".")
    address = normalized.lower()
    suspicious_count = sum(term in address for term in SUSPICIOUS_TERMS)
    is_shortener = any(hostname == domain or hostname.endswith(f".{domain}") for domain in SHORTENER_DOMAINS)
    has_credentials = bool(parsed.username or parsed.password)
    try:
        port = parsed.port
    except ValueError:
        port = None
    has_nonstandard_port = bool(port and port not in {80, 443})
    digits = sum(character.isdigit() for character in normalized)
    features = {
        "url_length": float(len(normalized)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "dot_count": float(hostname.count(".")),
        "hyphen_count": float(hostname.count("-")),
        "at_count": float(normalized.count("@")),
        "slash_count": float(normalized.count("/")),
        "question_count": float(normalized.count("?")),
        "equals_count": float(normalized.count("=")),
        "percent_count": float(normalized.count("%")),
        "digit_count": float(digits),
        "digit_ratio": digits / max(len(normalized), 1),
        "subdomain_count": float(max(len(host_labels) - 2, 0)),
        "has_https": float(parsed.scheme.lower() == "https"),
        "has_ip_address": has_ip,
        "has_punycode": float("xn--" in hostname),
        "has_username_or_password": float(has_credentials),
        "has_nonstandard_port": float(has_nonstandard_port),
        "has_shortener_domain": float(is_shortener),
        "suspicious_term_count": float(suspicious_count),
        "has_double_slash_in_path": float("//" in parsed.path),
    }

    indicators = []
    if parsed.scheme.lower() != "https":
        indicators.append("The URL does not use HTTPS.")
    if has_ip:
        indicators.append("The host is an IP address rather than a domain name.")
    if has_credentials:
        indicators.append("The URL contains embedded username or password information.")
    if "xn--" in hostname:
        indicators.append("The hostname contains encoded international characters (punycode).")
    if len(host_labels) >= 5:
        indicators.append("The hostname has several subdomain levels.")
    if is_shortener:
        indicators.append("A URL-shortening service obscures the final destination.")
    if suspicious_count:
        indicators.append("The address contains words commonly used in account or payment lures.")
    if has_nonstandard_port:
        indicators.append("The URL uses a non-standard web port.")
    if len(normalized) > 100:
        indicators.append("The URL is unusually long.")
    if hostname.count("-") >= 3:
        indicators.append("The hostname contains several hyphens.")

    return URLAnalysis(
        normalized_url=normalized,
        hostname=hostname,
        protocol=parsed.scheme.lower(),
        features=features,
        indicators=indicators,
    )
