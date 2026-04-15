DNS_TIMEOUT = 5.0
SMTP_TIMEOUT = 8
HTTP_TIMEOUT = 5

COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
]

MAX_MX_TO_CHECK = 3

USER_AGENT = "domain-email-audit-toolkit/1.0"