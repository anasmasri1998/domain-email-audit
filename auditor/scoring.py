def calculate_score(results: dict):
    score = 0
    findings = []

    if results.get("mx_records"):
        score += 10
    else:
        findings.append("No MX records found")

    if results.get("spf_record"):
        score += 15
    else:
        findings.append("Missing SPF")

    dmarc = results.get("dmarc_analysis", {})
    if dmarc.get("status") == "strong":
        score += 20
    elif dmarc.get("status") == "moderate":
        score += 10
    elif dmarc.get("status") == "weak":
        score += 5
    else:
        findings.append("Missing or weak DMARC")

    dkim_found = any(v for v in results.get("dkim_records", {}).values())
    if dkim_found:
        score += 15
    else:
        findings.append("No common DKIM selector found")

    if results.get("mta_sts_dns"):
        score += 10
    else:
        findings.append("Missing MTA-STS DNS record")

    if results.get("tls_rpt"):
        score += 10
    else:
        findings.append("Missing TLS-RPT")

    smtp_checks = results.get("smtp_checks", [])
    if any(item.get("supports_starttls") for item in smtp_checks):
        score += 20
    else:
        findings.append("No MX host with STARTTLS detected")

    return {
        "score": min(score, 100),
        "findings": findings
    }