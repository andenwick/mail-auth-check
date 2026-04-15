"""Command-line entry point for mail-auth-check."""
from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

from mail_auth_check.checks import DomainResult, check_domain


def _colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    codes = {
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "cyan": "\033[36m",
        "dim": "\033[2m",
        "bold": "\033[1m",
    }
    return f"{codes.get(color, '')}{text}\033[0m"


def _status_symbol(ok: bool, warn: bool = False) -> tuple[str, str]:
    if ok:
        return "+", "green"
    if warn:
        return "~", "yellow"
    return "-", "red"


def format_text(result: DomainResult, out: TextIO, use_color: bool = True) -> None:
    c = lambda t, clr: _colorize(t, clr, use_color)
    out.write(f"\n=== Email authentication for {result.domain} ===\n\n")

    # SPF
    sym, clr = _status_symbol(
        result.spf.found and result.spf.policy in ("hard_fail", "soft_fail"),
        warn=result.spf.found and result.spf.policy == "neutral",
    )
    out.write(f"  {c(sym, clr)}  SPF    ")
    if not result.spf.found:
        out.write(c("No SPF record published", "red") + "\n")
    else:
        policy_desc = {
            "hard_fail": c("hard fail (-all)", "green"),
            "soft_fail": c("soft fail (~all)", "yellow"),
            "neutral": c("neutral (?all)", "yellow"),
            "pass_all": c("permissive (+all)", "red"),
        }.get(result.spf.policy, c("present, no qualifier", "yellow"))
        out.write(f"{policy_desc}\n")
        out.write(c(f"         record: {result.spf.record}\n", "dim"))
        if result.spf.lookup_count > 10:
            out.write(c(f"         ! {result.spf.lookup_count} DNS lookups (RFC 7208 limit is 10)\n", "red"))

    # DKIM
    sym, clr = _status_symbol(bool(result.dkim.selectors_found))
    out.write(f"  {c(sym, clr)}  DKIM   ")
    if result.dkim.selectors_found:
        out.write(c(f"configured at selector(s): {', '.join(result.dkim.selectors_found)}", "green") + "\n")
    else:
        out.write(c(f"no selector found (probed {result.dkim.selectors_checked})", "red") + "\n")

    # DMARC
    sym, clr = _status_symbol(
        result.dmarc.found and result.dmarc.policy in ("quarantine", "reject"),
        warn=result.dmarc.found and result.dmarc.policy == "none",
    )
    out.write(f"  {c(sym, clr)}  DMARC  ")
    if not result.dmarc.found:
        out.write(c("No DMARC record published", "red") + "\n")
    else:
        policy_desc = {
            "reject": c("p=reject (enforcing)", "green"),
            "quarantine": c("p=quarantine (enforcing)", "green"),
            "none": c("p=none (monitoring only)", "yellow"),
        }.get(result.dmarc.policy, c(f"p={result.dmarc.policy}", "yellow"))
        out.write(f"{policy_desc}, pct={result.dmarc.percent}\n")
        out.write(c(f"         record: {result.dmarc.record}\n", "dim"))
        for r in result.dmarc.reporting:
            out.write(c(f"         {r}\n", "dim"))

    # MX
    sym, clr = _status_symbol(
        result.mx.has_records and not result.mx.uses_sending_only_endpoint,
        warn=result.mx.uses_sending_only_endpoint,
    )
    out.write(f"  {c(sym, clr)}  MX     ")
    if not result.mx.has_records:
        out.write(c("No MX records (domain cannot receive mail)", "red") + "\n")
    elif result.mx.uses_sending_only_endpoint:
        out.write(c(f"points to sending-only endpoint: {result.mx.primary}", "yellow") + "\n")
        out.write(c(f"         (not a valid receiving MX; inbound mail may be failing)\n", "dim"))
    else:
        out.write(c(f"{result.mx.primary}", "green"))
        if len(result.mx.records) > 1:
            out.write(c(f" (+{len(result.mx.records)-1} more)", "dim"))
        out.write("\n")

    out.write("\n")
    overall = result.overall_status
    overall_color = {"pass": "green", "partial": "yellow", "fail": "red"}[overall]
    out.write(f"  Overall: {c(overall.upper(), overall_color)}\n\n")


def format_json(result: DomainResult) -> str:
    return json.dumps({
        "domain": result.domain,
        "overall": result.overall_status,
        "spf": {
            "found": result.spf.found,
            "record": result.spf.record,
            "policy": result.spf.policy,
            "lookup_count": result.spf.lookup_count,
        },
        "dkim": {
            "selectors_checked": result.dkim.selectors_checked,
            "selectors_found": result.dkim.selectors_found,
        },
        "dmarc": {
            "found": result.dmarc.found,
            "record": result.dmarc.record,
            "policy": result.dmarc.policy,
            "percent": result.dmarc.percent,
            "reporting": result.dmarc.reporting,
        },
        "mx": {
            "records": [{"preference": p, "host": h} for p, h in result.mx.records],
            "primary": result.mx.primary,
            "uses_sending_only_endpoint": result.mx.uses_sending_only_endpoint,
        },
    }, indent=2)


def format_markdown(result: DomainResult) -> str:
    d = result.domain
    lines = [f"# Email authentication for {d}", ""]

    lines.append("## SPF")
    if result.spf.found:
        lines.append(f"- Record: `{result.spf.record}`")
        lines.append(f"- Policy: `{result.spf.policy}`")
        if result.spf.lookup_count > 10:
            lines.append(f"- WARNING: {result.spf.lookup_count} DNS lookups (RFC 7208 limit is 10)")
    else:
        lines.append("- **No SPF record published.** Any host on the internet can send mail claiming to be from this domain.")
    lines.append("")

    lines.append("## DKIM")
    if result.dkim.selectors_found:
        lines.append(f"- Found at selector(s): `{', '.join(result.dkim.selectors_found)}`")
    else:
        lines.append(f"- **No DKIM selector found** (probed {result.dkim.selectors_checked} common selectors)")
    lines.append("")

    lines.append("## DMARC")
    if result.dmarc.found:
        lines.append(f"- Record: `{result.dmarc.record}`")
        lines.append(f"- Policy: `p={result.dmarc.policy}`, pct={result.dmarc.percent}")
        for r in result.dmarc.reporting:
            lines.append(f"- {r}")
    else:
        lines.append("- **No DMARC record published.** No policy exists to tell receivers what to do with unauthenticated mail.")
    lines.append("")

    lines.append("## MX")
    if not result.mx.has_records:
        lines.append("- **No MX records.** Domain cannot receive mail.")
    else:
        for pref, host in result.mx.records:
            lines.append(f"- `{pref} {host}`")
        if result.mx.uses_sending_only_endpoint:
            lines.append(f"- WARNING: Primary MX `{result.mx.primary}` is a sending-only endpoint, not a valid receiving MX.")
    lines.append("")

    lines.append(f"**Overall: {result.overall_status.upper()}**")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mail-auth-check",
        description="Check SPF, DKIM, DMARC, and MX records for a domain.",
    )
    parser.add_argument("domain", help="Domain to check (e.g. example.com)")
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--markdown", action="store_true", help="Output Markdown",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in text output",
    )
    parser.add_argument(
        "--selector", action="append", default=None,
        help="Additional DKIM selector to probe (can be passed multiple times)",
    )
    parsed = parser.parse_args(argv)

    selectors = None
    if parsed.selector:
        from mail_auth_check.checks import COMMON_SELECTORS
        selectors = list(COMMON_SELECTORS) + parsed.selector

    result = check_domain(parsed.domain, dkim_selectors=selectors)

    if parsed.json:
        print(format_json(result))
    elif parsed.markdown:
        print(format_markdown(result))
    else:
        format_text(result, sys.stdout, use_color=not parsed.no_color)

    # Exit code reflects posture: 0 = pass, 1 = partial, 2 = fail
    return {"pass": 0, "partial": 1, "fail": 2}[result.overall_status]


if __name__ == "__main__":
    sys.exit(main())
