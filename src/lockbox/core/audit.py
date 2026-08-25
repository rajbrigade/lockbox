"""Local security audit.

Analyses only the items already decrypted in memory. Nothing is sent anywhere,
and no finding claims that a credential was *breached* -- that word is reserved
for results produced from a local breach dataset by core/breach.py.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from ..tools.analysis import analyze
from ..tools.commonlist import is_common
from .model import Item
from .search import _domain

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "cf", "tk", "ml"}


@dataclass
class Finding:
    item_id: str
    title: str
    kind: str
    severity: str
    message: str
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "item_id": self.item_id,
            "title": self.title,
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    breach_status: str = "not checked"

    def by_severity(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {s: [] for s in SEVERITIES}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out

    def by_kind(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.findings:
            out[f.kind].append(f)
        return dict(out)

    def score(self) -> int:
        """A 0-100 health score. Presentational only, not a security guarantee."""
        total = max(1, int(self.stats.get("items_with_passwords", 0)))
        weights = {"critical": 12, "high": 7, "medium": 3, "low": 1, "info": 0}
        penalty = sum(weights.get(f.severity, 1) for f in self.findings)
        return max(0, min(100, int(100 - (penalty * 100) / (total * 20))))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score(),
            "stats": dict(self.stats),
            "breach_status": self.breach_status,
            "findings": [f.to_dict() for f in self.findings],
        }


def _looks_suspicious(url: str) -> Optional[str]:
    if not url:
        return None
    lowered = url.strip().lower()
    host = _domain(lowered)
    if lowered.startswith("http://"):
        return "uses plain HTTP, so credentials are sent unencrypted"
    if not host:
        return None
    if "@" in lowered.split("//")[-1].split("/")[0]:
        return "URL embeds credentials in the host part"
    if host.startswith("xn--") or ".xn--" in host:
        return "punycode host: may be a homograph of a real domain"
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        return f"unusual top-level domain (.{tld}) often used in phishing"
    if host.count("-") >= 3 or host.count(".") >= 4:
        return "unusually complex hostname"
    return None


def audit(
    items: Iterable[Item],
    settings: Optional[Dict[str, Any]] = None,
    breach_lookup: Optional[Any] = None,
    now: Optional[int] = None,
) -> AuditReport:
    settings = settings or {}
    current = int(time.time() if now is None else now)
    min_length = int(settings.get("min_password_length", 12))
    age_days = int(settings.get("password_age_warning_days", 365))

    items = list(items)
    report = AuditReport()
    password_map: Dict[str, List[Item]] = defaultdict(list)
    identity_map: Dict[tuple, List[Item]] = defaultdict(list)
    with_passwords = 0

    for item in items:
        if item.password:
            with_passwords += 1
            password_map[item.password].append(item)
        key = (item.type, item.title.strip().lower(), item.username.strip().lower(),
               _domain(item.url))
        if item.title or item.username:
            identity_map[key].append(item)

    for item in items:
        label = item.title or "(untitled)"

        if item.type in ("login", "api_key") and not item.password:
            report.findings.append(
                Finding(item.id, label, "empty", "high",
                        "No password stored on a login item")
            )
        if item.password:
            if len(item.password) < min_length:
                report.findings.append(
                    Finding(item.id, label, "short",
                            "critical" if len(item.password) < 8 else "high",
                            f"Password is {len(item.password)} characters "
                            f"(minimum {min_length})")
                )
            if is_common(item.password):
                report.findings.append(
                    Finding(item.id, label, "common", "critical",
                            "Password appears in the bundled common-password list")
                )
            analysis = analyze(item.password)
            if analysis.estimated_bits < 40 and len(item.password) >= min_length:
                report.findings.append(
                    Finding(item.id, label, "weak", "high",
                            f"Weak password: about {analysis.estimated_bits:.0f} bits "
                            f"of estimated entropy",
                            "; ".join(analysis.patterns[:3]))
                )
            age = (current - int(item.password_updated)) / 86400
            if age > age_days:
                report.findings.append(
                    Finding(item.id, label, "old", "low",
                            f"Password unchanged for {age / 365.25:.1f} years",
                            "Age alone is not compromise; rotate high-value items.")
                )

        if item.type == "login" and item.password and not item.totp_secret:
            report.findings.append(
                Finding(item.id, label, "no_totp", "info",
                        "No TOTP secret stored for this login",
                        "Only relevant if the site supports 2FA.")
            )
        reason = _looks_suspicious(item.url)
        if reason:
            report.findings.append(
                Finding(item.id, label, "suspicious_url", "medium",
                        f"URL looks risky: {reason}", item.url)
            )
        if item.type == "login" and item.password and not item.url:
            report.findings.append(
                Finding(item.id, label, "no_url", "info",
                        "No URL stored, so this item cannot be matched to a site")
            )

    for password, group in password_map.items():
        if len(group) > 1:
            names = ", ".join(sorted(i.title or "(untitled)" for i in group))
            for item in group:
                report.findings.append(
                    Finding(item.id, item.title or "(untitled)", "reused", "high",
                            f"Password reused across {len(group)} items",
                            f"Shared with: {names}")
                )

    for key, group in identity_map.items():
        if len(group) > 1:
            for item in group:
                report.findings.append(
                    Finding(item.id, item.title or "(untitled)", "duplicate", "low",
                            f"{len(group)} items share the same title, username and site",
                            "Possibly a duplicate entry.")
                )

    if breach_lookup is not None:
        checked = 0
        for item in items:
            if not item.password:
                continue
            hit = breach_lookup(item.password)
            if hit is None:
                continue
            checked += 1
            if hit:
                report.findings.append(
                    Finding(item.id, item.title or "(untitled)", "breached", "critical",
                            "Password found in the LOCAL breach dataset",
                            "Change it wherever it is used.")
                )
        report.breach_status = (
            f"checked {checked} passwords against the local dataset"
            if checked
            else "local dataset present but no lookups completed"
        )
    else:
        report.breach_status = (
            "not checked - no local breach dataset configured. Lockbox will not "
            "send passwords anywhere to check them."
        )

    report.stats = {
        "items": len(items),
        "items_with_passwords": with_passwords,
        "reused_passwords": sum(1 for g in password_map.values() if len(g) > 1),
        "unique_passwords": len(password_map),
        "with_totp": sum(1 for i in items if i.totp_secret),
        "findings": len(report.findings),
        "critical": sum(1 for f in report.findings if f.severity == "critical"),
        "high": sum(1 for f in report.findings if f.severity == "high"),
    }
    order = {s: i for i, s in enumerate(SEVERITIES)}
    report.findings.sort(key=lambda f: (order.get(f.severity, 9), f.title.lower()))
    return report
