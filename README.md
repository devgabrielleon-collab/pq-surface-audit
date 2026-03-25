# pq-surface-audit 🌐

[![CI](https://github.com/devgabrielleon-collab/pq-surface-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/devgabrielleon-collab/pq-surface-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**External post-quantum readiness auditor for authorized HTTPS/TLS and SSH assets.**

`pq-surface-audit` is a specialized tool for security teams and infrastructure managers to audit the external cryptographic surface of their organization. It identifies classical cryptographic algorithms in use on public-facing services that will require migration to Post-Quantum Cryptography (PQC).

> "Which internet-facing assets still depend on quantum-vulnerable public-key cryptography, and which ones should we review first?"

## 🚀 Key Features

- **HTTPS/TLS Auditing**: Inspects certificates, TLS versions, and cipher suites.
- **SSH Surface Mapping**: Identifies exposed SSH services and classical host key algorithms.
- **Risk Scoring**: Automatically prioritizes assets based on cryptographic vulnerability and security hygiene.
- **Professional Reporting**: Generates structured JSON and human-readable HTML dashboards.

## 📦 Installation

```bash
git clone https://github.com/devgabrielleon-collab/pq-surface-audit.git
cd pq-surface-audit
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[ssh,dev]
```

## 🛠️ Usage

### Single Target Scan
```bash
pqaudit scan https://example.com --output ./out
```

### Batch Audit
Create a `targets.txt` file with one host per line:
```bash
pqaudit batch targets.txt --output ./reports
```

## 📊 Why this project matters?

As the industry moves towards **Quantum-Safe** standards (NIST PQC), organizations must inventory their external cryptographic dependencies. This tool separates two critical ideas:

1.  **Current Security Hygiene**: Identifies expired certs, missing HSTS, and old TLS versions.
2.  **Post-Quantum Readiness**: Maps classical public-key certs and SSH host keys that will eventually need migration planning.

## 🛠️ Development & CI/CD

### Running Tests
```bash
pytest tests/ -v
```

### GitHub Actions
This project uses **GitHub Actions** for Continuous Integration. Every push to `main` triggers an automated test suite across multiple Python versions to ensure reliability.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Securing the future, one audit at a time.*
# pq-surface-audit

External **post-quantum readiness** scanner for **authorized** HTTPS/TLS and SSH assets.

`pq-surface-audit` helps security teams answer a practical question:

> "Which internet-facing assets still depend on quantum-vulnerable public-key cryptography, and which ones should we review first?"

It does **not** exploit systems. It performs a safe, defensive audit of:
- TLS endpoints (`https://`, `host:443`)
- X.509 certificates and certificate metadata
- basic HTTP security headers
- SSH banners, and optionally SSH host-key type if `paramiko` is installed

It produces:
- `report.json`
- `report.html`
- per-asset risk scores and prioritization

## Why this project matters

Most organizations will need a **cryptographic inventory** and an **initial migration plan** before they can move toward post-quantum cryptography. This tool is designed to help with that first phase for internet-facing services.

## Safety boundaries

Use this tool **only** on systems you own or are explicitly authorized to assess.

This project is intentionally scoped to:
- passive-ish protocol handshakes
- certificate inspection
- HTTP header checks
- safe banner collection

It is intentionally **not** a vulnerability exploiter, brute-forcer, or credential tool.

## Features

- Scan one asset or a batch list
- Parse TLS version, cipher, cert subject, issuer, validity, SANs, signature algorithm, public-key algorithm, key size
- Flag quantum-relevant classical PKI usage (RSA, ECDSA, EdDSA, DH/ECDH family in context)
- Check basic HTTP posture: HSTS, redirect to HTTPS, CSP presence
- Check SSH exposure and banner
- Optional SSH host-key discovery with `paramiko`
- Generate JSON + HTML reports
- Score assets by urgency for PQ migration planning

## Install

```bash
pip install -e .[dev]
# optional SSH host-key discovery
pip install -e .[ssh]
```

## Usage

Scan one target:

```bash
pqaudit scan https://example.com --output ./out
```

Scan a host without scheme:

```bash
pqaudit scan example.com --output ./out
```

Scan a batch file:

```bash
pqaudit batch ./samples/sample_assets.txt --output ./out
```

## Output example

```json
{
  "summary": {
    "assets_scanned": 2,
    "high_priority": 1,
    "medium_priority": 1,
    "low_priority": 0
  }
}
```

## Risk philosophy

This project separates two ideas:

1. **Current security hygiene**
   - expired certs
   - missing HSTS
   - old TLS versions

2. **Post-quantum migration readiness**
   - classical public-key certs
   - classical SSH host keys
   - exposed services that will eventually need migration planning

That means an asset can be secure **today** and still need PQ migration planning.

## Project structure

```text
pq-surface-audit/
├─ src/pq_surface_audit/
│  ├─ cli.py
│  ├─ models.py
│  ├─ scanner.py
│  ├─ scoring.py
│  └─ report.py
├─ samples/
├─ tests/
├─ MANUS_PROMPT.md
└─ README.md
```

## Run tests

```bash
pytest -q
```

## Good portfolio demo idea

Use the sample assets file or create a demo lab with:
- one HTTPS site with a normal RSA cert
- one service with expired/near-expiry cert metadata in mocked tests
- one SSH service exposed to the internet

Then show the generated HTML report in your README screenshots.


## GitHub Actions

O projeto inclui os workflows `.github/workflows/ci.yml` e `.github/workflows/main.yml` para rodar testes automaticamente no GitHub Actions.
