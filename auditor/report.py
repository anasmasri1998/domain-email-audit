import json

from auditor.dns_checks import (
    get_mx_records,
    parse_mx_hosts,
    get_spf_record,
    get_dmarc_record,
    check_common_dkim_selectors,
    get_mta_sts_dns_record,
    get_tls_rpt_record,
)
from auditor.smtp_checks import check_starttls
from auditor.parser import parse_spf_strength, parse_dmarc_policy, fetch_mta_sts_policy
from auditor.scoring import calculate_score

def run_audit(domain: str):
    mx_records = get_mx_records(domain)
    mx_hosts = parse_mx_hosts(mx_records)

    spf_record = get_spf_record(domain)
    dmarc_record = get_dmarc_record(domain)
    dkim_records = check_common_dkim_selectors(domain)
    mta_sts_dns = get_mta_sts_dns_record(domain)
    tls_rpt = get_tls_rpt_record(domain)
    mta_sts_policy = fetch_mta_sts_policy(domain)

    smtp_results = []
    for mx in mx_hosts[:3]:
        smtp_results.append(check_starttls(mx["host"]))

    results = {
        "domain": domain,
        "mx_records": mx_records,
        "spf_record": spf_record,
        "spf_analysis": parse_spf_strength(spf_record),
        "dmarc_record": dmarc_record,
        "dmarc_analysis": parse_dmarc_policy(dmarc_record),
        "dkim_records": dkim_records,
        "mta_sts_dns": mta_sts_dns,
        "mta_sts_policy": mta_sts_policy,
        "tls_rpt": tls_rpt,
        "smtp_checks": smtp_results,
    }

    results["score"] = calculate_score(results)
    return json.dumps(results, indent=2)