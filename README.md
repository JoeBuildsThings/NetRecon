<div align="center">

# NetRecon

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=22&duration=3500&pause=1200&color=22D3EE&center=true&vCenter=true&width=720&lines=External+attack+surface+audit;DNS+%7C+TLS+%7C+Headers+%7C+ASN+%7C+Ports;SSRF-guarded+%C2%B7+ownership-gated)](https://git.io/typing-svg)

**One-pass reconnaissance workbench for public domains and IPs.**

[![Live Demo](https://img.shields.io/badge/Live-netrecon.vercel.app-22d3ee?style=for-the-badge&logo=vercel&logoColor=white)](https://netrecon.vercel.app)
[![CI](https://img.shields.io/github/actions/workflow/status/JoeBuildsThings/NetRecon/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/JoeBuildsThings/NetRecon/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)

<br />

[Live App](https://netrecon.vercel.app) · [Privacy](https://netrecon.vercel.app/privacy) · [Report Issue](https://github.com/JoeBuildsThings/NetRecon/issues)

</div>

---

## What it does

NetRecon runs a parallel, SSRF-guarded audit against a public target and returns:

| Module | Output |
|--------|--------|
| **DNS** | A/AAAA, MX, NS, TXT, PTR · SPF / DMARC posture |
| **Web** | TLS availability & verification · security header scoring · grade |
| **Geo / ASN** | City, country, org, ASN from public IP intel |
| **Ports** | Common-port probe **only after** DNS TXT ownership proof |

Active TCP probing is ownership-gated on production. Private, loopback, CGNAT, and metadata ranges are rejected at validation time.

---

## Stack

```text
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Browser UI │────▶│  Flask / Vercel  │────▶│  recon modules  │
│  static JS  │◀────│  rate limit +    │◀────│  dns · geo ·    │
│  dark SOC   │     │  security hdrs   │     │  web · ports    │
└─────────────┘     └──────────────────┘     └─────────────────┘
```

- **Backend:** Flask, concurrent modules (`ThreadPoolExecutor`), ProxyFix
- **Intel:** dnspython, requests, public DNS + IP geolocation APIs
- **Optional:** Upstash Redis REST for distributed rate limits
- **Frontend:** Space Grotesk · Plus Jakarta Sans · JetBrains Mono

---

## Quick start

```bash
git clone https://github.com/JoeBuildsThings/NetRecon.git
cd NetRecon

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt

python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

### API sketch

```bash
# Health
curl -s https://netrecon.vercel.app/api/health | jq

# Recon (POST JSON)
curl -s -X POST https://netrecon.vercel.app/api/recon \
  -H 'Content-Type: application/json' \
  -d '{"target":"github.com","include_ports":true}' | jq
```

```python
# Response shape (simplified)
{
  "ok": True,
  "elapsed_ms": 1234.5,
  "partial": False,
  "target": {"host": "github.com", "primary_ip": "...", "is_ip": False},
  "ownership": {"verified": False, "txt_host": "...", "txt_value": "..."},
  "geo": {"asn": "...", "org": "...", "country": "..."},
  "dns": {"posture": {"spf_status": "...", "dmarc_policy": "..."}},
  "web": {"grade": "A", "score": 92, "tls": {"available": True}},
  "ports": {"status": "verification_required", "open_ports": []}
}
```

---

## Security posture

| Control | Detail |
|---------|--------|
| **SSRF guards** | Global-unicast allowlist only — no RFC1918, loopback, link-local, CGNAT, metadata |
| **Ownership gate** | TXT challenge before active port scans in production |
| **Rate limit** | 25 req / 60s per client IP (in-memory + optional Upstash) |
| **Headers** | HSTS, CSP, `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy |
| **Data** | No persistent user scan DB — history stays in browser `localStorage` |

---

## Tests & CI

```bash
pytest tests/ -v
ruff check .
```

GitHub Actions runs **ruff + pytest** on every push to `main` (Python 3.11 / 3.12).

---

## Environment (optional)

| Variable | Purpose |
|----------|---------|
| `UPSTASH_REDIS_REST_URL` | Distributed rate-limit store |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash REST token |

Core operation stays on free tiers — no paid services required.

---

## Project layout

```text
NetRecon/
├── app.py                 # Flask entry + /api/recon
├── recon/
│   ├── validator.py       # Target normalize + SSRF blocklist
│   ├── dns_intel.py
│   ├── geo_intel.py
│   ├── web_audit.py
│   ├── ownership.py
│   ├── port_scanner.py
│   └── logger.py
├── static/
│   ├── styles.css
│   └── app.js
├── templates/
│   ├── index.html
│   ├── privacy.html
│   └── 404.html
├── tests/
│   └── test_security.py
└── .github/workflows/ci.yml
```

---

## License

[MIT](LICENSE) © Adebiyi Joseph Ayomide / JoeBuildsThings

> **Authorized testing only.** Use NetRecon only on systems you own or have explicit permission to audit.
