from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class SectionSpec:
    key: str
    heading: str
    not_found: str


SECTIONS: List[SectionSpec] = [
    SectionSpec("6.1", "Broken Access Control", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.2", "Security Misconfiguration", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.3", "Software Supply Chain Failures", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.4", "Cryptographic Failures", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.5", "Injection", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.6", "Insecure Design", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.7", "Authentication Failures", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.8", "Software and Data Integrity Failures", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.9", "Security logging and monitoring failures", "Ushbu turdagi zaiflik aniqlanmadi."),
    SectionSpec("6.10", "Mishandling of Exceptional Conditions", "Ushbu turdagi zaiflik aniqlanmadi."),
]


def _attr(item, name: str, default=""):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def severity_counts(findings: Iterable[object]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        risk = str(_attr(finding, "risk", "")).strip().lower()
        if risk in {"critical", "high"}:
            counts["high"] += 1
        elif risk == "medium":
            counts["medium"] += 1
        else:
            counts["low"] += 1
    return counts


def map_finding_to_section(finding: object) -> str:
    title = str(_attr(finding, "title", "")).lower()
    evidence = str(_attr(finding, "evidence", "")).lower()
    tool = str(_attr(finding, "tool", "")).lower()
    owasp_id = str(_attr(finding, "owasp_id", "")).upper()
    haystack = " ".join(part for part in [title, evidence, tool] if part)

    exceptional_keywords = [
        "exception",
        "error",
        "traceback",
        "stack trace",
        "sql error",
        "warning:",
        "fatal error",
        "xatolik",
    ]
    if any(keyword in haystack for keyword in exceptional_keywords):
        return "6.10"

    if owasp_id.startswith("A09") or any(word in haystack for word in ["audit", "logging", "monitoring", "log "]):
        return "6.9"
    if owasp_id.startswith("A01"):
        return "6.1"
    if owasp_id.startswith("A05"):
        return "6.2"
    if owasp_id.startswith("A06"):
        return "6.3"
    if owasp_id.startswith("A02"):
        return "6.4"
    if owasp_id.startswith("A03"):
        return "6.5"
    if owasp_id.startswith("A04"):
        return "6.6"
    if owasp_id.startswith("A07"):
        return "6.7"
    if owasp_id.startswith("A08"):
        return "6.8"

    if any(word in haystack for word in ["idor", "broken access control", "403 bypass", "acl"]):
        return "6.1"
    if any(word in haystack for word in ["misconfig", "directory listing", "phpmyadmin", "cors", "header"]):
        return "6.2"
    if any(word in haystack for word in ["cve-", "outdated component", "vulnerable component", "supply chain"]):
        return "6.3"
    if any(word in haystack for word in ["tls", "ssl", "jwt", "crypto", "cryptographic"]):
        return "6.4"
    if any(word in haystack for word in ["sqli", "xss", "xxe", "ssrf", "cmdi", "lfi", "injection"]):
        return "6.5"
    if any(word in haystack for word in ["business logic", "rate limit", "insecure design"]):
        return "6.6"
    if any(word in haystack for word in ["auth", "session fixation", "default credential", "username enumeration"]):
        return "6.7"
    if any(word in haystack for word in ["deserialization", "integrity"]):
        return "6.8"

    return "6.2"


def group_findings_by_section(findings: Iterable[object]) -> "OrderedDict[str, List[object]]":
    grouped = OrderedDict((section.key, []) for section in SECTIONS)
    for finding in findings:
        grouped[map_finding_to_section(finding)].append(finding)
    return grouped
