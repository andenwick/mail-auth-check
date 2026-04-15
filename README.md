# mail-auth-check

Check SPF, DKIM, DMARC, and MX records for a domain. Verify email-authentication posture in one command.

Every finding comes from direct DNS queries. No API keys, no cloud service, no telemetry. Run it, read the output, fix what's missing.

## Install

```
pip install mail-auth-check
```

Requires Python 3.10+. Only external dependency is [dnspython](https://www.dnspython.org/).

## Usage

```
$ mail-auth-check example.com

=== Email authentication for example.com ===

  +  SPF    hard fail (-all)
         record: v=spf1 include:_spf.google.com -all
  +  DKIM   configured at selector(s): google
  +  DMARC  p=quarantine (enforcing), pct=100
         record: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
         rua: mailto:dmarc@example.com
  +  MX     aspmx.l.google.com (+4 more)

  Overall: PASS
```

### Options

| Flag | Effect |
|------|--------|
| `--json` | Machine-readable JSON output (for scripting or CI) |
| `--markdown` | Clean Markdown suitable for pasting into docs or reports |
| `--no-color` | Disable ANSI colors in text output |
| `--selector NAME` | Probe an additional DKIM selector (can be repeated) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass (SPF + DKIM + DMARC enforcing + valid MX) |
| `1` | Partial (at least two controls in place) |
| `2` | Fail (fewer than two controls in place) |

Useful in CI: fail a deployment if a domain regresses from pass to partial.

## What it checks

**SPF** — looks up `TXT` records at the root, extracts the `v=spf1` policy, reports the qualifier (`-all` hard fail, `~all` soft fail, `?all` neutral, `+all` permissive). Also counts DNS-lookup mechanisms and warns if the SPF record exceeds the RFC 7208 limit of 10.

**DKIM** — probes ~35 common selectors at `<selector>._domainkey.<domain>`, including generic selectors (`default`, `selector1`, `selector2`, `mail`) and provider-specific selectors (Google Workspace, Microsoft 365, SendGrid, Mailchimp, Amazon SES, Postmark, Zoho, Fastmail, Yandex, Proofpoint, Mimecast). Additional selectors can be supplied with `--selector NAME`.

**DMARC** — looks up `_dmarc.<domain>`, parses the policy (`none`, `quarantine`, `reject`), percentage, and reporting addresses (`rua`, `ruf`).

**MX** — lists MX records and flags a common misconfiguration: MX records pointing to sending-only SMTP endpoints (like `smtp.google.com`, `smtp.sendgrid.net`) that don't accept inbound mail. The correct Google Workspace receiving MX is `aspmx.l.google.com` plus `alt1-4.aspmx.l.google.com`.

## What it doesn't do

No authenticated access. No mail server probing. No relay testing. No deliverability testing. No header analysis. No certificate checks.

This tool does one thing: tell you if email authentication DNS records are published correctly. If they're not, fix them.

## Why

Missing SPF, DKIM, and DMARC are the single most common finding in external security reviews of small and mid-sized businesses. Fixing them is cheap (a few DNS records) and has outsized impact on both security and email deliverability.

This tool exists because:
1. Those checks should be run in 30 seconds, not 30 minutes.
2. The output should be readable without training.
3. The tool should be free and scriptable.

## License

MIT. See [LICENSE](LICENSE).

## Author

Built by [Sentry Peak LLC](https://sentrypeak.com). Contact: [anden@sentrypeak.com](mailto:anden@sentrypeak.com).
