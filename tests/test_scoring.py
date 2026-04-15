from auditor.scoring import calculate_score


def test_calculate_score_strong_domain():
    results = {
        "mx_records": ["10 mail.example.com."],
        "spf_record": "v=spf1 -all",
        "dmarc_analysis": {"status": "strong"},
        "dkim_records": {"default": "v=DKIM1; k=rsa; p=abc123"},
        "mta_sts_dns": "v=STSv1; id=20260101T000000;",
        "tls_rpt": "v=TLSRPTv1; rua=mailto:tls@example.com",
        "smtp_checks": [
            {"supports_starttls": True}
        ],
    }

    score = calculate_score(results)

    assert score["score"] == 100
    assert score["findings"] == []


def test_calculate_score_missing_everything():
    results = {
        "mx_records": [],
        "spf_record": None,
        "dmarc_analysis": {"status": "missing"},
        "dkim_records": {},
        "mta_sts_dns": None,
        "tls_rpt": None,
        "smtp_checks": [],
    }

    score = calculate_score(results)

    assert score["score"] == 0
    assert "No MX records found" in score["findings"]
    assert "Missing SPF" in score["findings"]
    assert "Missing or weak DMARC" in score["findings"]
    assert "No common DKIM selector found" in score["findings"]
    assert "Missing MTA-STS DNS record" in score["findings"]
    assert "Missing TLS-RPT" in score["findings"]
    assert "No MX host with STARTTLS detected" in score["findings"]


def test_calculate_score_moderate_domain():
    results = {
        "mx_records": ["10 mail.example.com."],
        "spf_record": "v=spf1 ~all",
        "dmarc_analysis": {"status": "moderate"},
        "dkim_records": {"default": None, "selector1": None},
        "mta_sts_dns": None,
        "tls_rpt": None,
        "smtp_checks": [
            {"supports_starttls": True}
        ],
    }

    score = calculate_score(results)

    assert score["score"] == 55
    assert "No common DKIM selector found" in score["findings"]
    assert "Missing MTA-STS DNS record" in score["findings"]
    assert "Missing TLS-RPT" in score["findings"]


def test_calculate_score_caps_at_100():
    results = {
        "mx_records": ["10 mail.example.com."],
        "spf_record": "v=spf1 -all",
        "dmarc_analysis": {"status": "strong"},
        "dkim_records": {"default": "v=DKIM1; p=abc"},
        "mta_sts_dns": "v=STSv1; id=1;",
        "tls_rpt": "v=TLSRPTv1; rua=mailto:test@example.com",
        "smtp_checks": [{"supports_starttls": True}],
    }

    score = calculate_score(results)

    assert score["score"] <= 100