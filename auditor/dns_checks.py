import dns.resolver
import dns.exception

TIMEOUT = 5.0

def resolve_record(name: str, record_type: str):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    resolver.timeout = TIMEOUT

    try:
        answers = resolver.resolve(name, record_type)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    except Exception:
        return []

def get_mx_records(domain: str):
    return resolve_record(domain, "MX")

def get_txt_records(domain: str):
    return resolve_record(domain, "TXT")

def get_spf_record(domain: str):
    txt_records = get_txt_records(domain)
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if cleaned.lower().startswith("v=spf1"):
            return cleaned
    return None

def get_dmarc_record(domain: str):
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = resolve_record(dmarc_domain, "TXT")
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if cleaned.lower().startswith("v=dmarc1"):
            return cleaned
    return None

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail"
]

def get_dkim_record(domain: str, selector: str):
    name = f"{selector}._domainkey.{domain}"
    txt_records = resolve_record(name, "TXT")
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if "v=DKIM1" in cleaned.upper():
            return cleaned
    return None

def check_common_dkim_selectors(domain: str):
    results = {}
    for selector in COMMON_DKIM_SELECTORS:
        results[selector] = get_dkim_record(domain, selector)
    return results

def parse_mx_hosts(mx_records):
    hosts = []
    for record in mx_records:
        parts = record.split()
        if len(parts) >= 2:
            hosts.append({
                "priority": parts[0],
                "host": parts[1].rstrip(".")
            })
    return hosts

def get_mta_sts_dns_record(domain: str):
    name = f"_mta-sts.{domain}"
    txt_records = resolve_record(name, "TXT")
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if cleaned.lower().startswith("v=stsv1"):
            return cleaned
    return None
    
def get_tls_rpt_record(domain: str):
    name = f"_smtp._tls.{domain}"
    txt_records = resolve_record(name, "TXT")
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if cleaned.lower().startswith("v=tlsrptv1"):
            return cleaned
    return None