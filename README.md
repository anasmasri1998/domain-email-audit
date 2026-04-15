# domain-email-audit
Security audit tool for analyzing domain and email infrastructure using DNS, SMTP, and TLS checks, including SPF, DKIM, DMARC, MTA-STS, and STARTTLS.

# Overview
Email security depends heavily on correct DNS records and secure mail transport.
Misconfigurations can lead to:

- Email spoofing
- Weak sender authentication
- Insecure mail delivery
- Lack of visibility into TLS failures
- Poor domain reputation
This project helps identify those issues automatically.

# Features

- MX record lookup
- SPF detection and policy analysis
- DMARC detection and enforcement analysis
- DKIM common selector checks
- MTA-STS DNS + policy file checks
- TLS-RPT checks
- SMTP STARTTLS support checks
- JSON reporting
- Security scoring
- Docker support
- Unit and integration tests

# Installation (Local)

1. Clone the repository
git clone https://github.com/anasmasri1998/domain-email-audit
cd domain-email-audit
2. Create virtual environment
python3 -m venv venv
source venv/bin/activate
3. Install dependencies
pip install -r requirements.txt

# Usage (Local)

Run an audit:

python main.py example.com

Examples:

python main.py gmail.com
python main.py microsoft.com
python main.py proton.me

Save output to file:

mkdir -p output
python main.py gmail.com > output/gmail.json

Validate JSON:

python -m json.tool output/gmail.json

# Docker Usage

Build Docker Image
docker build -t domain-audit .
Run Audit in Docker
docker run --rm domain-audit example.com

Examples:

docker run --rm domain-audit gmail.com
docker run --rm domain-audit microsoft.com
Save Docker Output
docker run --rm domain-audit gmail.com > output/gmail_docker.json

# Example Output

{
  "domain": "example.com",
  "mx_records": [
    "10 mail.example.com."
  ],
  "spf_record": "v=spf1 -all",
  "spf_analysis": {
    "status": "strong",
    "message": "Strict SPF policy"
  },
  "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
  "dmarc_analysis": {
    "status": "strong",
    "policy": "reject"
  },
  "dkim_records": {
    "default": null,
    "selector1": "v=DKIM1; k=rsa; p=ABC123..."
  },
  "mta_sts_dns": "v=STSv1; id=20260101T000000;",
  "tls_rpt": "v=TLSRPTv1; rua=mailto:tls@example.com",
  "smtp_checks": [
    {
      "host": "mail.example.com",
      "port": 25,
      "connectable": true,
      "supports_starttls": true
    }
  ],
  "score": {
    "score": 90,
    "findings": []
  }
}
