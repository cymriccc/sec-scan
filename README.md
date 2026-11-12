# sec-scan 🛡️

![License](https://img.shields.io/badge/license-MIT-007EC6?style=flat-square)
![Go Version](https://img.shields.io/badge/Go-1.22%2B-7FD5EA?style=flat-square&logo=go&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-AppSec%20%7C%20WAF-E05D44?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-3371E3?style=flat-square&logo=fedora&logoColor=white)
[![Build Status](https://github.com/cymriccc/sec-scan/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cymriccc/sec-scan/actions/workflows/security-scan.yml)

> A lightweight, modular security auditing CLI written in Go to evaluate web application header configurations, SSL/TLS certificates, CORS misconfigurations, cookie security flags, tech stack disclosures, and sensitive endpoint exposures.

## 📸 Preview

```text
[+] Auditing security headers for: https://math-mosaic.vercel.app

[PASS] Strict-Transport-Security    : max-age=63072000; includeSubDomains; preload
[PASS] X-Frame-Options              : DENY
[PASS] X-Content-Type-Options       : nosniff
[FAIL] Content-Security-Policy      : MISSING (Recommended: default-src 'self')
[PASS] Referrer-Policy              : strict-origin-when-cross-origin
[FAIL] Permissions-Policy           : MISSING (Recommended: geolocation=(), microphone=())

[+] Auditing SSL/TLS Certificate...

  Issuer         : WR1
  Protocol       : TLS 1.3
  Status         : VALID (84 days remaining)

[+] Auditing CORS Configuration...

[FAIL] CORS Configuration         : Wildcard (*) Access-Control-Allow-Origin header detected. (Risk: MEDIUM)

[+] Auditing Server Technology Disclosure...

[WARN] Server               : Vercel
[SAFE] X-Powered-By         : HIDDEN
[SAFE] X-AspNet-Version     : HIDDEN
[SAFE] X-Generator          : HIDDEN
[SAFE] Via                  : HIDDEN

[+] Probing sensitive endpoints & files...

[SAFE] /.env                : 404
[SAFE] /.git/HEAD           : 404
[SAFE] /config.json         : 404
[SAFE] /admin               : 404
[SAFE] /robots.txt          : 404
[SAFE] /sitemap.xml         : 404

[+] Auditing Cookie Security Flags...

[SAFE] Set-Cookie Headers         : No insecure cookies detected

[+] Security Posture Summary:
  Overall Score  : 75 / 100
  Security Grade : C
```

## ✨ Features

- 🔐 **HTTP Security Header Audit**: Probes target URLs for missing foundational defenses (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- 📜 **SSL/TLS Certificate Inspector**: Evaluates certificate validity, expiration countdowns, issuer authority, and active TLS protocol versions (`TLS 1.3`).
- 🌐 **CORS Security Auditor**: Detects wildcards (`*`) and dangerous arbitrary origin reflection with credentials enabled.
- 🍪 **Cookie Security Auditor**: Inspects `Set-Cookie` headers for missing `Secure`, `HttpOnly`, and `SameSite` attributes to mitigate session hijacking and CSRF.
- 🕵️ **Server Technology Disclosure Detection**: Flags verbose server headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`) exposing backend stack details.
- 🎯 **Sensitive Endpoint & Asset Probing**: Audits common leak paths like environment files (`.env`), Git internal configurations (`.git/HEAD`), config files, and admin portals.
- 🎨 **Modern Interactive HTML Dashboard**: Generates visual security reports featuring Tailwind CSS, Chart.js posture score gauges, Lucide icons, JetBrains Mono font, and smooth Light/Dark mode toggling.
- 📝 **Structured Markdown Reports**: Exports clean, GitHub-flavored Markdown audit summaries (`-md report.md`) ideal for PR comments, wikis, and documentation.
- 📊 **Automated JSON Export & CI/CD Gating**: Supports automated JSON output (`-o report.json`), stdout streaming (`-json-stdout`), quiet mode (`-q`), and risk threshold gating (`-fail-on-risk`) for automated pipelines.

## 🛠️ Installation & Setup

### Prerequisites

- [Go 1.22+](https://golang.org/dl/)
- Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/cymriccc/sec-scan.git
cd sec-scan

# Build the executable
go build -o sec-scan.exe ./cmd/sec-scan
```

## 🚀 Usage

### Single Target Scan
Pass the target URL directly as a positional argument:

```bash
# Windows PowerShell / CMD
.\sec-scan.exe https://target-website.com

# Linux / macOS
./sec-scan https://target-website.com

# Go Run (Development)
go run cmd/sec-scan/main.go https://target-website.com
```

---

### Exporting Security Audit Reports
Use `-o` for JSON export, `-html` for HTML visual reports, and `-md` for Markdown reports:

```bash
# Export JSON report
go run cmd/sec-scan/main.go -o report.json https://target-website.com

# Export HTML visual report
go run cmd/sec-scan/main.go -html report.html https://target-website.com

# Export Markdown report
go run cmd/sec-scan/main.go -md report.md https://target-website.com

# Export JSON, HTML & Markdown reports simultaneously
go run cmd/sec-scan/main.go -o report.json -html report.html -md report.md https://target-website.com

# Stream JSON results to stdout (ideal for jq piping)
go run cmd/sec-scan/main.go -json-stdout -q https://target-website.com | jq .
```

---

### Batch Target Scanning & Concurrency
Use `-f` to supply a list of targets and `-c` to control concurrent worker threads:

```bash
# Scan targets from file with default 5 worker threads
go run cmd/sec-scan/main.go -f targets.txt

# Batch scan with 10 concurrent workers and HTML export
go run cmd/sec-scan/main.go -f targets.txt -c 10 -html report.html
```

---

### CI/CD Pipeline Gating
Use `-fail-on-risk` in automated workflows to fail builds when critical vulnerabilities or an `F` grade are detected:

```bash
go run cmd/sec-scan/main.go -fail-on-risk -f targets.txt
```

---

### ⚙️ Available Flags

| Flag | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `-c` | `int` | Number of concurrent workers for batch scanning | `5` |
| `-f` | `string` | Path to text file containing target URLs for batch scanning | `""` |
| `-o` | `string` | Path to export JSON report (e.g. `-o report.json`) | `""` |
| `-html` | `string` | Path to export HTML visual report (e.g. `-html report.html`) | `""` |
| `-md` | `string` | Path to export Markdown report (e.g. `-md report.md`) | `""` |
| `-ua` | `string` | Custom User-Agent header for HTTP requests | `"sec-scan/1.0"` |
| `-timeout` | `int` | HTTP request timeout in seconds | `10` |
| `-q` | `bool` | Quiet mode: Suppress banner and standard terminal outputs | `false` |
| `-json-stdout` | `bool` | Print JSON audit results directly to stdout for piping | `false` |
| `-fail-on-risk` | `bool` | Exit with non-zero code (`1`) if critical vulnerabilities or F grade detected | `false` |

## 📁 Project Architecture

```text
sec-scan/
├── cmd/
│   └── sec-scan/
│       └── main.go          # CLI Entrypoint & Workflow Router
├── internal/
│   ├── scanner/             # Core Auditing Engines & CLI Output
│   │   ├── headers.go       # HTTP Security Header Auditor
│   │   ├── tls.go           # SSL/TLS Certificate Inspector
│   │   ├── cors.go          # CORS Misconfiguration Auditor
│   │   ├── cookies.go       # Set-Cookie Security Auditor
│   │   ├── cookies_test.go  # Cookie Auditor Unit Tests
│   │   ├── info.go          # Technology Leak Detector
│   │   ├── probes.go        # Sensitive Endpoint & Asset Probe
│   │   ├── remediation.go   # Security Fix & Remediation Guides
│   │   ├── risk.go          # Security Score & Risk Calculator
│   │   ├── concurrent.go    # Batch Worker Pool Scanner
│   │   └── printer.go       # Modular ANSI Terminal Color Renderer
│   └── report/              # Report Generators
│       ├── output.go        # JSON Exporter
│       ├── html.go          # Interactive Glassmorphism HTML Generator
│       └── md.go            # Structured Markdown Exporter
├── .gitignore
├── go.mod
└── README.md
```

## 📝 License

Distributed under the MIT License. See `LICENSE` for details.

## 👤 Author

- GitHub: [@cymriccc](https://github.com/cymriccc)
