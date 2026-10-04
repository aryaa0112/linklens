"""Transparent, offline URL risk scoring."""

from __future__ import annotations

from dataclasses import dataclass

from .features import URLAnalysis, analyze_url


@dataclass(frozen=True)
class RiskAssessment:
    """A heuristic score with evidence, not a probability or verdict."""

    analysis: URLAnalysis
    score: int
    level: str
    summary: str
    findings: list[dict[str, object]]

    def as_dict(self) -> dict[str, object]:
        return {
            "url": self.analysis.normalized_url,
            "hostname": self.analysis.hostname,
            "protocol": self.analysis.protocol,
            "score": self.score,
            "level": self.level,
            "summary": self.summary,
            "findings": self.findings,
            "features": self.analysis.features,
            "notice": (
                "This is an offline heuristic, not a probability or a confirmation that a site is safe. "
                "HTTPS does not prove a site is legitimate."
            ),
        }


def assess_analysis(analysis: URLAnalysis) -> RiskAssessment:
    """Score lexical indicators deterministically and preserve their explanations."""
    features = analysis.features
    findings: list[dict[str, object]] = []

    def add(condition: bool, points: int, title: str, detail: str) -> None:
        if condition:
            findings.append(
                {"points": points, "title": title, "detail": detail}
            )

    add(
        bool(features["has_username_or_password"]),
        30,
        "Embedded login information",
        "User information before the @ can make a different host appear trustworthy.",
    )
    add(
        bool(features["has_ip_address"]),
        25,
        "IP address used as the host",
        "The destination uses a numeric address instead of a recognizable domain.",
    )
    add(
        bool(features["has_punycode"]),
        20,
        "Encoded international hostname",
        "Punycode can be used in legitimate domains, but can also disguise lookalike characters.",
    )
    add(
        bool(features["has_shortener_domain"]),
        15,
        "Shortened destination",
        "The final destination is hidden until the short link is followed.",
    )
    add(
        bool(features["has_nonstandard_port"]),
        15,
        "Unusual web port",
        "The address uses a port other than the common HTTP or HTTPS ports.",
    )
    add(
        features["subdomain_count"] >= 3,
        10,
        "Many subdomain levels",
        "A long chain of subdomains can bury the actual registered domain.",
    )
    add(
        analysis.protocol != "https",
        8,
        "No HTTPS",
        "The connection is not encrypted; this alone does not establish malicious intent.",
    )
    add(
        features["suspicious_term_count"] > 0,
        min(int(features["suspicious_term_count"]) * 4, 12),
        "Sensitive-action wording",
        "The address contains account, sign-in, payment, or verification language.",
    )
    add(
        features["url_length"] > 100,
        8,
        "Unusually long address",
        "Long URLs can make the actual destination or action harder to inspect.",
    )
    add(
        features["hyphen_count"] >= 3,
        5,
        "Several hostname hyphens",
        "Several hyphens can make a hostname harder to read and compare.",
    )
    add(
        bool(features["has_double_slash_in_path"]),
        8,
        "Extra slash in the path",
        "A double slash in the path can visually obscure where the destination leads.",
    )

    score = min(sum(int(finding["points"]) for finding in findings), 100)
    if score >= 50:
        level = "high"
        summary = "Several strong warning signs are present. Do not enter credentials or payment details."
    elif score >= 25:
        level = "elevated"
        summary = "Some warning signs are present. Verify the destination through a trusted route."
    else:
        level = "lower"
        summary = "Few URL-pattern warning signs were detected. This does not mean the site is safe."

    return RiskAssessment(
        analysis=analysis,
        score=score,
        level=level,
        summary=summary,
        findings=findings,
    )


def assess_url(value: str) -> RiskAssessment:
    """Analyze a URL and return its explainable heuristic risk assessment."""
    return assess_analysis(analyze_url(value))
