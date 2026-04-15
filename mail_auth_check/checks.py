"""Core email-authentication checks: SPF, DKIM, DMARC, MX."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.version


# Common DKIM selectors to probe. Providers publish their key under a
# predictable selector name; listing the common ones covers the vast majority
# of legitimate DKIM deployments without authenticated access.
COMMON_SELECTORS = [
    # Generic
    "default", "selector1", "selector2", "mail", "dkim", "email", "key1", "key2",
    # Google Workspace
    "google",
    # Microsoft 365
    "selector1", "selector2",
    # Mailchimp / Mandrill
    "k1", "k2", "k3", "mte1",
    # SendGrid
    "s1", "s2", "smtpapi",
    # Amazon SES
    "amazonses",
    # Postmark
    "20210112", "pm",
    # Zoho
    "zoho", "zmail",
    # Fastmail
    "fm1", "fm2", "fm3", "mesmtp",
    # Yandex
    "mail",
    # Older MS
    "selector",
    # Proofpoint / Mimecast
    "pp", "mimecast",
    # Modern ESPs
    "resend",          # Resend
    "hs1", "hs2",      # HubSpot
    "scph0920",        # SparkPost
    "klaviyo",         # Klaviyo
    # Misc
    "MDaemon", "domk", "dkim2024", "dkim2025",
]

# MX hostnames that exist but are NOT valid receiving MX (sending endpoints
# mistakenly used as MX). Flagging these catches a common misconfiguration.
SENDING_ONLY_ENDPOINTS = {
    "smtp.google.com", "smtp.gmail.com",
    "smtp.office365.com", "smtp-mail.outlook.com",
    "smtp.sendgrid.net", "smtp.mailgun.org",
    "smtp.mailjet.com", "smtp.postmarkapp.com",
}


@dataclass
class SPFResult:
    record: Optional[str] = None
    found: bool = False
    policy: Optional[str] = None  # "hard_fail", "soft_fail", "neutral", "pass_all"
    lookup_count: int = 0


@dataclass
class DKIMResult:
    selectors_checked: int = 0
    selectors_found: list[str] = field(default_factory=list)


@dataclass
class DMARCResult:
    record: Optional[str] = None
    found: bool = False
    policy: Optional[str] = None  # "none", "quarantine", "reject"
    percent: int = 100
    reporting: list[str] = field(default_factory=list)


@dataclass
class MXResult:
    records: list[tuple[int, str]] = field(default_factory=list)
    has_records: bool = False
    uses_sending_only_endpoint: bool = False
    primary: Optional[str] = None


@dataclass
class DomainResult:
    domain: str
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    mx: MXResult

    @property
    def overall_status(self) -> str:
        """Returns 'pass', 'partial', or 'fail'."""
        passing = sum([
            self.spf.found and self.spf.policy in ("hard_fail", "soft_fail"),
            bool(self.dkim.selectors_found),
            self.dmarc.found and self.dmarc.policy in ("quarantine", "reject"),
            self.mx.has_records and not self.mx.uses_sending_only_endpoint,
        ])
        if passing == 4:
            return "pass"
        if passing >= 2:
            return "partial"
        return "fail"


def _query_txt(name: str, timeout: float = 5.0) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        # TXT strings may be split across chunks; join them per record.
        results: list[str] = []
        for rdata in answers:
            parts = [b.decode("utf-8", errors="replace") for b in rdata.strings]
            results.append("".join(parts))
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _query_mx(name: str, timeout: float = 5.0) -> list[tuple[int, str]]:
    try:
        answers = dns.resolver.resolve(name, "MX", lifetime=timeout)
        return sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_spf(domain: str) -> SPFResult:
    """Look up SPF record and parse policy."""
    result = SPFResult()
    records = _query_txt(domain)
    for record in records:
        if record.startswith("v=spf1"):
            result.record = record
            result.found = True
            break

    if not result.record:
        return result

    if "-all" in result.record:
        result.policy = "hard_fail"
    elif "~all" in result.record:
        result.policy = "soft_fail"
    elif "?all" in result.record:
        result.policy = "neutral"
    elif "+all" in result.record:
        result.policy = "pass_all"

    # RFC 7208 limits SPF to 10 DNS-lookup mechanisms
    result.lookup_count = len(re.findall(
        r"\b(include|a|mx|ptr|exists|redirect)\b", result.record, re.IGNORECASE
    ))
    return result


def check_dkim(domain: str, selectors: Optional[list[str]] = None) -> DKIMResult:
    """Probe common DKIM selectors at _domainkey.<domain>."""
    if selectors is None:
        selectors = COMMON_SELECTORS
    result = DKIMResult(selectors_checked=len(selectors))
    seen = set()
    for selector in selectors:
        if selector in seen:
            continue
        seen.add(selector)
        records = _query_txt(f"{selector}._domainkey.{domain}")
        for record in records:
            if "v=DKIM1" in record or "k=rsa" in record or "p=" in record:
                if selector not in result.selectors_found:
                    result.selectors_found.append(selector)
                break
    return result


def check_dmarc(domain: str) -> DMARCResult:
    """Look up DMARC at _dmarc.<domain> and parse policy."""
    result = DMARCResult()
    records = _query_txt(f"_dmarc.{domain}")
    for record in records:
        if record.startswith("v=DMARC1"):
            result.record = record
            result.found = True
            break

    if not result.record:
        return result

    policy_match = re.search(r"p=([a-z]+)", result.record)
    if policy_match:
        result.policy = policy_match.group(1)

    pct_match = re.search(r"pct=(\d+)", result.record)
    if pct_match:
        result.percent = int(pct_match.group(1))

    for tag in ("rua", "ruf"):
        addr_match = re.search(rf"{tag}=([^;]+)", result.record)
        if addr_match:
            result.reporting.append(f"{tag}: {addr_match.group(1).strip()}")

    return result


def check_mx(domain: str) -> MXResult:
    """Look up MX records and flag sending-only endpoints."""
    result = MXResult()
    records = _query_mx(domain)
    result.records = records
    result.has_records = bool(records)
    if records:
        result.primary = records[0][1]
        for _, host in records:
            if host.lower().rstrip(".") in SENDING_ONLY_ENDPOINTS:
                result.uses_sending_only_endpoint = True
                break
    return result


def check_domain(domain: str, dkim_selectors: Optional[list[str]] = None) -> DomainResult:
    """Run all checks against a domain and return a DomainResult."""
    domain = domain.lower().strip().rstrip(".")
    return DomainResult(
        domain=domain,
        spf=check_spf(domain),
        dkim=check_dkim(domain, dkim_selectors),
        dmarc=check_dmarc(domain),
        mx=check_mx(domain),
    )
