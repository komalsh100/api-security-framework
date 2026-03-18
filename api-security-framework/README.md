# Secure API Testing Framework

Automated API security testing framework using **OWASP ZAP** and **Python**, targeting the **OWASP API Top 10 (2023)**. Supports JWT/session authentication, generates an HTML reporting dashboard, and integrates into CI/CD pipelines via GitHub Actions.

---

## Features

- OWASP API Top 10 targeted checks
- JWT, Bearer token, Session cookie, and Basic auth support
- Active + AJAX spider for full endpoint discovery
- HTML dashboard with severity breakdown and OWASP categorization
- JSON report output for pipeline integration
- GitHub Actions workflow with automatic PR comments
- Build gate — fails CI on high severity findings

---

## Quick Start

### Prerequisites
- Python 3.9+
- OWASP ZAP running in daemon mode
- Docker (for CI/CD usage)

### Install
```bash
git clone https://github.com/yourusername/api-security-framework
cd api-security-framework
pip install -r requirements.txt
```

### Start ZAP in daemon mode
```bash
docker run -d --name zap --network host \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -port 8080 -config api.key=changeme
```

### Run a scan

**Unauthenticated:**
```bash
python scanner.py --target http://localhost:8080
```

**With JWT auth:**
```bash
python scanner.py \
  --target http://localhost:8080 \
  --auth-type jwt \
  --auth-token eyJhbGciOiJIUzI1NiJ9...
```

**With session cookie:**
```bash
python scanner.py \
  --target http://localhost:8080 \
  --auth-type session \
  --auth-cookie "JSESSIONID=abc123def456"
```

**With severity filter:**
```bash
python scanner.py \
  --target http://localhost:8080 \
  --min-severity High \
  --output-html reports/dashboard.html
```

---

## Output

### HTML Dashboard
Open `reports/dashboard.html` in a browser:
- Summary stat cards (Total / High / Medium / Low)
- OWASP API Top 10 category breakdown table
- Individual finding cards with remediation guidance

### JSON Report
`reports/findings.json` — structured output for pipeline consumption:
```json
{
  "target": "http://localhost:8080",
  "scan_date": "2025-01-15T14:32:00",
  "summary": { "High": 2, "Medium": 3, "Low": 5, "Informational": 1 },
  "zap_findings": [...],
  "custom_findings": [...]
}
```

---

## CI/CD Integration

Add to your repository and configure:

**Secrets required:**
- `ZAP_API_KEY` — ZAP daemon API key
- `API_AUTH_TOKEN` — Bearer token for authenticated scans (optional)

**Pipeline behavior:**
- Runs on every push to `main`/`develop` and every PR
- Posts a summary comment directly on the PR
- Uploads full HTML dashboard as a workflow artifact
- Fails the build if any High severity findings are detected

---

## OWASP API Top 10 Coverage

| # | Category | Coverage |
|---|----------|----------|
| API1 | Broken Object Level Authorization | IDOR detection via URL pattern analysis |
| API2 | Broken Authentication | ZAP auth tests + weak auth detection |
| API3 | Broken Object Property Level Auth | ZAP parameter tampering checks |
| API4 | Unrestricted Resource Consumption | Rate limiting probe |
| API8 | Security Misconfiguration | ZAP active scan rules |
| API9 | Improper Inventory Management | Exposed docs detection |

---

## Project Structure

```
api-security-framework/
├── scanner.py                        # Main scanner
├── report.py                         # HTML dashboard generator
├── requirements.txt
├── .github/
│   └── workflows/
│       └── api-security.yml          # CI/CD pipeline
└── reports/                          # Scan output (gitignored)
    ├── findings.json
    └── dashboard.html
```
