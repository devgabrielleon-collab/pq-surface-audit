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
