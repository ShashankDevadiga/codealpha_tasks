# SecureAudit — Secure Code Review Dashboard

A React dashboard documenting a security audit of a vulnerable Python Flask application.

## Project Structure

```
secure-audit/
├── public/
│   └── index.html
├── src/
│   ├── data/
│   │   └── vulnerabilities.js     # All 8 vulnerability records
│   ├── components/
│   │   ├── SeverityBadge.jsx      # Coloured severity label
│   │   ├── CodeBlock.jsx          # Syntax block with copy button
│   │   ├── RiskMeter.jsx          # SVG arc gauge
│   │   └── VulnDetail.jsx         # Modal with 3-tab detail view
│   ├── App.jsx                    # Main dashboard layout
│   └── index.js                   # React entry point
├── vulnerable_app.py              # Target: intentionally insecure Flask app
├── package.json
└── README.md
```

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Run the dashboard
```bash
npm start
```
Opens at **http://localhost:3000**

---

## Vulnerabilities Covered

| ID    | Severity | Title                          | OWASP      | CWE          |
|-------|----------|--------------------------------|------------|--------------|
| V-001 | CRITICAL | SQL Injection                  | A03:2021   | CWE-89       |
| V-002 | CRITICAL | Server-Side Template Injection | A03:2021   | CWE-94       |
| V-003 | CRITICAL | OS Command Injection           | A03:2021   | CWE-78       |
| V-004 | CRITICAL | Insecure Deserialization       | A08:2021   | CWE-502      |
| V-005 | HIGH     | Weak Password Hashing (MD5)    | A02:2021   | CWE-327      |
| V-006 | HIGH     | Path Traversal                 | A01:2021   | CWE-22       |
| V-007 | HIGH     | YAML Code Execution            | A08:2021   | CWE-502      |
| V-008 | HIGH     | Hardcoded Secrets & Debug Mode | A05:2021   | CWE-798      |

---

## Tools Used
- **Bandit** — Python SAST (static analysis)
- **Semgrep** — Pattern-based code scanning  
- **Manual Review** — Logic-level OWASP mapping

## Dashboard Features
- Click any row → opens detail modal
- **Overview** tab — description + metadata
- **Code** tab — vulnerable vs. fixed snippet, copy button
- **Remediation** tab — numbered action steps
- Filter by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Search by vulnerability name, OWASP code, or CWE
- Sort by severity or line number
