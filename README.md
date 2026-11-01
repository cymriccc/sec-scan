# sec-scan 🛡️

![License](https://img.shields.io/badge/license-MIT-007EC6?style=flat-square)
![Go Version](https://img.shields.io/badge/Go-1.22%2B-7FD5EA?style=flat-square&logo=go&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-AppSec%20%7C%20WAF-E05D44?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-3371E3?style=flat-square&logo=fedora&logoColor=white)

> A lightweight, modular security auditing CLI written in Go to evaluate web application header configurations, SSL/TLS certificates, tech stack disclosures, and sensitive endpoint exposures.

## 📸 Preview

```text
[+] Auditing security headers for: https://math-mosaic.vercel.app

[PASS] X-Frame-Options              : DENY
[PASS] X-Content-Type-Options       : nosniff
[FAIL] Content-Security-Policy      : MISSING (Recommended: default-src 'self')
[PASS] Referrer-Policy              : strict-origin-when-cross-origin
[FAIL] Permissions-Policy           : MISSING (Recommended: geolocation=(), microphone=())
[PASS] Strict-Transport-Security    : max-age=63072000; includeSubDomains; preload

[+] Auditing SSL/TLS Certificate...

  Issuer         : WR1
  Protocol       : TLS 1.3
  Status         : VALID (89 days remaining until 2027-01-29)

[+] Auditing Server Technology Disclosure...

  [SAFE] Server               : HIDDEN
  [SAFE] X-Powered-By         : HIDDEN

[+] Probing sensitive endpoints & files...

  [SAFE] /.env                : 404
  [SAFE] /.git/HEAD           : 404
  [SAFE] /config.json         : 404
```

## ✨ Features

* 🔐 **HTTP Security Header Audit**: Probes target URLs for missing foundational defenses (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
* 📜 **SSL/TLS Certificate Inspector**: Evaluates certificate validity, expiration countdowns, issuer authority, and active TLS protocol versions (`TLS 1.3`).
* 🕵️ **Server Technology Disclosure Detection**: Flags verbose server headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) that expose backend stack details.
* 🎯 **Sensitive Endpoint & Asset Probing**: Audits common leak paths like environment files (`.env`), Git internal configurations (`.git/HEAD`), and admin portals.
* 📊 **Automated JSON Export**: Supports single-flag automated output (`-o report.json`) for CI/CD integration and compliance archiving.

## 🛠️ Installation & Setup

### Prerequisites

* [Go 1.22+](https://golang.org/dl/)
* Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/cymriccc/sec-scan.git
cd sec-scan

# Build the executable
go build -o sec-scan.exe ./cmd/sec-scan
```

## 🚀 Usage

### Standard Scan

```powershell
.\sec-scan.exe https://target-website.com
```

### Scan and Export Report to JSON

```powershell
.\sec-scan.exe -o report.json https://target-website.com
```

## 📁 Project Architecture

```text
sec-scan/
├── cmd/
│   └── sec-scan/
│       └── main.go       # CLI Entrypoint & ANSI Terminal Renderer
├── internal/
│   ├── scanner/          # Core Auditing Engines
│   │   ├── headers.go    # HTTP Security Header Auditor
│   │   ├── tls.go        # SSL/TLS Certificate Inspector
│   │   ├── info.go       # Technology Leak Detector
│   │   └── probes.go     # Sensitive Endpoint & Asset Probe
│   └── report/
│       └── output.go     # Multi-Module JSON Report Exporter
├── .gitignore
├── go.mod
└── README.txt
```

## 📝 License

Distributed under the MIT License. See `LICENSE` for details.

## 👤 Author

* GitHub: [@cymriccc](https://github.com/cymriccc)