import sys
from auditor.report import run_audit

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    result = run_audit(domain)
    print(result)

if __name__ == "__main__":
    main()