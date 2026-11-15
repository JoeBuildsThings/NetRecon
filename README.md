# NetRecon

External attack surface and infrastructure audit workbench.

SSRF guarded DNS posture, TLS certificate health, HTTP security headers, ASN geolocation, and ownership gated port exposure in one pass.

**Live:** https://netrecon.vercel.app

## What it does

- Resolves public domains and IPs with strict global unicast allowlisting (blocks private, loopback, CGNAT, metadata ranges).
- Parallel modules for geo/ASN, DNS (SPF/DMARC/NS/MX), web posture (TLS + header scoring), and optional active port probes.
- Domain ownership verification via DNS TXT before any active TCP probing on hosted deployments.
- Per IP rate limiting (in memory + optional Upstash Redis).
- Clean light UI with metrics strip, tabbed findings, markdown/JSON export, and privacy policy.

## Stack

- Flask + Vercel Python runtime
- dnspython, requests
- Optional Upstash Redis for distributed rate limits
- Static UI: Space Grotesk / Plus Jakarta Sans / JetBrains Mono, D3 orthographic globe (graceful fallback)

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
python app.py
```

Open http://127.0.0.1:5000

## Security posture

- Input validation and SSRF guards in `recon/validator.py`
- No private/internal targets accepted
- Port scans require ownership proof on production
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Rate limit 25 requests / 60s per client IP
- No persistent user database of scan results

## Tests

```bash
pytest tests/ -v
```

CI runs on every push to main (ruff + pytest).

## Environment (optional)

| Variable | Purpose |
|---|---|
| `UPSTASH_REDIS_REST_URL` | Distributed rate limit store |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash token |

Free tier only. No paid services required for core operation.

## License

MIT. See LICENSE.

Authorized security testing and infrastructure verification only.
Use only on systems you own or have explicit permission to audit.
