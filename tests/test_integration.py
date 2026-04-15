import json
import pytest
from auditor.report import run_audit


def test_run_audit_with_mocked_dependencies(monkeypatch):
    monkeypatch.setattr("auditor.report.get_mx_records", lambda domain: ["10 mail.example.com."])
    monkeypatch.setattr(
        "auditor.report.parse_mx_hosts",
        lambda mx_records: [{"priority": "10", "host": "mail.example.com"}]
    )
    monkeypatch.setattr("auditor.report.get_spf_record", lambda domain: "v=spf1 -all")
    monkeypatch.setattr(
        "auditor.report.get_dmarc_record",
        lambda domain: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    )
    monkeypatch.setattr(
        "auditor.report.check_common_dkim_selectors",
        lambda domain: {"default": "v=DKIM1; k=rsa; p=abc123"}
    )
    monkeypatch.setattr(
        "auditor.report.get_mta_sts_dns_record",
        lambda domain: "v=STSv1; id=20260101T000000;"
    )
    monkeypatch.setattr(
        "auditor.report.get_tls_rpt_record",
        lambda domain: "v=TLSRPTv1; rua=mailto:tls@example.com"
    )
    monkeypatch.setattr(
        "auditor.report.fetch_mta_sts_policy",
        lambda domain: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400"
    )
    monkeypatch.setattr(
        "auditor.report.check_starttls",
        lambda host: {
            "host": host,
            "port": 25,
            "connectable": True,
            "supports_starttls": True,
            "banner": "220 mail.example.com ESMTP",
            "error": None,
        }
    )

    result = run_audit("example.com")
    data = json.loads(result)

    assert data["domain"] == "example.com"
    assert data["spf_analysis"]["status"] == "strong"
    assert data["dmarc_analysis"]["status"] == "strong"
    assert data["score"]["score"] > 0



def test_run_audit_returns_json_for_real_domain():
    result = run_audit("example.com")
    data = json.loads(result)

    assert isinstance(data, dict)
    assert data["domain"] == "example.com"
    assert "mx_records" in data
    assert "spf_record" in data
    assert "dmarc_record" in data
    assert "score" in data