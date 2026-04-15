"""mail-auth-check: verify SPF, DKIM, DMARC, and MX records for a domain."""
from mail_auth_check.checks import check_domain, DomainResult

__version__ = "0.1.0"
__all__ = ["check_domain", "DomainResult"]
