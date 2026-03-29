# LA CNA Registry / Accio Data Integration Bridge — Deployment Guide

## Architecture Overview

This service acts as a secure bridge between Accio Data's CRA platform and the Louisiana CNA/DSW Nurse Aide Registry. It receives candidate SSNs from Accio, performs real-time lookups against the state registry, and pushes certification results back to Accio.

### Integration Pathway: HTTP POST (Primary)

The LA CNA search form is a classic ASP.NET WebForms page with standard ViewState/EventValidation. It has no JavaScript dependencies beyond standard form submission. Our integration uses direct HTTP POST via httpx (async) — this is 5-10x faster than Playwright, has a smaller attack surface, and requires no browser binary.

A Playwright fallback module is included for disaster recovery only.

### Security Architecture

SSNs follow a strict lifecycle:

```
Accio API (HTTPS) -> RAM -> LA Form POST -> Parse Result -> Push to Accio -> DESTROY
                    ^                                                      ^
               SecureSSN()                                          .destroy()
            (non-interned copy)                              (ctypes memset + del + gc)
```

SSNs are never written to disk, logs, databases, environment variables, or any persistent storage.

---

## Repository Structure

```
la-cna-accio-bridge/
├── .github/
│   └── workflows/
│       └── ci.yml                  # CI pipeline (security scan + tests + Docker build)
├── tests/
│   ├── __init__.py
│   ├── test_security.py            # 19 security tests (SSN handling, leak detection)
│   └── test_parser.py              # 8 parser tests (all result scenarios)
├── la_cna_accio_bridge.py          # Main application (all-in-one)
├── la_cna_playwright_fallback.py   # Playwright fallback (disaster recovery)
├── Dockerfile                      # Production Docker image
├── docker-compose.yml              # Docker Compose with security hardening
├── requirements.txt                # Pinned dependencies
├── .env.example                    # Environment variable template
├── .gitignore                      # Git ignore rules
└── DEPLOYMENT.md                   # This file
```

---

## Step-by-Step: GitHub to Live

### 1. Create Private GitHub Repository

```bash
gh repo create your-org/la-cna-accio-bridge --private --clone
cd la-cna-accio-bridge
git add .
git commit -m "Initial commit: LA CNA Registry / Accio Data bridge"
git push origin main
```

### 2. Configure GitHub Secrets

Go to **Settings -> Secrets and variables -> Actions** and add:

| Secret Name | Description |
|---|---|
| ACCIO_API_BASE_URL | Your Accio instance URL |
| ACCIO_API_ACCOUNT | Accio API account name |
| ACCIO_API_USERNAME | Accio API username |
| ACCIO_API_PASSWORD | Accio API password |
| WEBHOOK_SECRET | Generate with: python -c "import secrets; print(secrets.token_hex(32))" |

### 3. Verify CI Passes

Push to main and verify all CI checks pass:
- Security scan (Bandit + SSN leak detection)
- Unit tests (27 tests)
- Docker build + health check

### 4. Deploy to Render.com

1. Go to https://dashboard.render.com
2. Click "New" -> "Web Service"
3. Connect the la-cna-accio-bridge GitHub repo
4. Render will auto-detect the render.yaml and Dockerfile
5. Add environment variables in the Render dashboard (secrets marked sync: false)
6. Deploy

### 5. Configure Accio Data Webhook

In your Accio Data admin panel:

1. Go to **Operations -> Vendors -> Manage Vendor Dispatch Rules**
2. Create a new vendor for "LA CNA Registry Bridge"
3. Set the **Instructions/Post-Back URL** to your Render URL + /webhook/accio/cna-verify
4. Configure a dispatch rule for search type "CNA Credential Verification"

### 6. Test with Accio Test Subjects

Use Accio's built-in test mode:
- Set ACCIO_API_MODE=TEST in your environment
- Place an order using test subject "Johnny Good" or "Johnny Bad"
- Verify the CNA lookup completes and results are posted back

---

## Monitoring (Zero-PII)

The service logs only non-PII operational metrics.

### Health Check

```bash
curl https://your-render-url.onrender.com/health
# Returns: {"status": "healthy", "service": "la-cna-accio-bridge", "timestamp": "..."}
```

---

## Security Checklist

Before going live, verify:

- [ ] Repository is **private**
- [ ] .env file is NOT committed (check .gitignore)
- [ ] WEBHOOK_SECRET is a cryptographically random 64-character hex string
- [ ] Accio API credentials are correct and have minimum required permissions
- [ ] TLS is enabled (Render provides this automatically)
- [ ] CI pipeline passes all security scans
- [ ] No SSN patterns found in source code (CI verifies this)
- [ ] Rate limiting is configured (MAX_CONCURRENT_LOOKUPS=3)

---

## Troubleshooting

| Issue | Solution |
|---|---|
| "Missing required environment variables" | Check all vars in .env.example are set |
| Health check fails | Verify container is running on Render dashboard |
| LA form returns "No Data" | SSN may not be in CNA registry — this is a valid result |
| Accio push fails | Check Accio API credentials and post-back URL configuration |
| Timeout errors | Increase HTTP_TIMEOUT_SECONDS (default: 30) |
| Rate limiting from LA site | Reduce MAX_CONCURRENT_LOOKUPS (default: 3) |
