import requests
from config import HTTP_TIMEOUT, USER_AGENT

def fetch_mta_sts_policy(domain: str):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if response.status_code == 200:
            return response.text
        return None
    except Exception:
        return None

def get_tls_rpt_record(domain: str):
    name = f"_smtp._tls.{domain}"
    txt_records = resolve_record(name, "TXT")
    for record in txt_records:
        cleaned = record.replace('" "', '').replace('"', '')
        if cleaned.lower().startswith("v=tlsrptv1"):
            return cleaned
    return None

def parse_spf_strength(spf_record: str):
    if not spf_record:
        return {"status": "missing", "message": "No SPF record found"}

    record = spf_record.lower()
    if record.endswith("-all"):
        return {"status": "strong", "message": "Strict SPF policy"}
    if record.endswith("~all"):
        return {"status": "moderate", "message": "Softfail SPF policy"}
    if record.endswith("?all"):
        return {"status": "weak", "message": "Neutral SPF policy"}
    if record.endswith("+all"):
        return {"status": "dangerous", "message": "Permissive SPF policy"}
    return {"status": "unknown", "message": "Unable to classify SPF"}

def parse_dmarc_policy(dmarc_record: str):
    if not dmarc_record:
        return {"status": "missing", "policy": None}

    lower = dmarc_record.lower()
    if "p=reject" in lower:
        return {"status": "strong", "policy": "reject"}
    if "p=quarantine" in lower:
        return {"status": "moderate", "policy": "quarantine"}
    if "p=none" in lower:
        return {"status": "weak", "policy": "none"}
    return {"status": "unknown", "policy": None}