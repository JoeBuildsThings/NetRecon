# NetRecon

**External surface intelligence for domains and public IP addresses.**

NetRecon brings DNS intelligence, TLS and HTTP posture, IP geolocation, and scoped TCP exposure checks into one reconnaissance workbench.

[Live application](https://netrecon.vercel.app) · [Source](https://github.com/JoeBuildsThings/NetRecon) · [MIT License](LICENSE)

## Capabilities

| Module | What it reports |
| --- | --- |
| DNS | A/AAAA, CNAME, MX, NS, TXT, PTR, SPF and DMARC posture |
| Web | HTTPS reachability, TLS certificate verification, security headers and posture score |
| Network | IP version, approximate location, ASN, organisation and ISP metadata |
| TCP | Common exposed TCP services, connection latency and service banners |
| Exports | Readable scan summary and complete JSON result |

Passive DNS, web and IP-intelligence checks run concurrently for valid public targets. The interactive 3D Canvas tracking globe renders locally with zero external map tiles, plotting only verified coordinates returned by a geolocation provider alongside its source and lookup time. IP geolocation is approximate and must not be treated as a physical address.

## Active scan policy

The previous per-domain DNS TXT ownership challenge has been removed. Active TCP probes start automatically when a submitted target matches the deployment operator's server-side scan scope. There is no user-facing ownership workflow.

Configure `NETRECON_ACTIVE_SCAN_ALLOWLIST` in the hosting environment. Supported entries are exact hostnames, explicit wildcard subdomains, IP addresses and CIDR ranges. See [the active-scan scope guide](docs/active-scan-scope.md) for examples and deployment notes.

When no scope is configured, passive reconnaissance remains available and active probing stays disabled. Targets outside the configured scope receive passive results and an explicit port-module status. Only configure systems and ranges the deployment operator is authorised to assess.

## Security controls

- Public, globally routable target validation. Private, loopback, link-local, CGNAT, reserved and internal destinations are rejected.
- DNS is resolved before a scan and network checks use the validated, pinned IP address.
- Request body size is limited and target input rejects control characters, malformed URLs and embedded credentials.
- Scan submissions are rate limited to 25 requests per client IP per 60-second window.
- Optional Upstash Redis provides a shared rate-limit counter for serverless deployments.
- Security response headers, SSRF-aware redirect inspection, module-level failure handling and safe frontend text rendering.
- No scan history is stored by the server. Recent targets remain in browser local storage.

## Quick start

```bash
git clone https://github.com/JoeBuildsThings/NetRecon.git
cd NetRecon

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

For local active probes, create a `.env` file or export the scope variable in the shell before starting Flask:

```bash
export NETRECON_ACTIVE_SCAN_ALLOWLIST=example.com,api.example.com
python app.py
```

For wildcard scope, use an explicit entry such as `*.example.com`. It matches subdomains of the domain, not the apex.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `NETRECON_ACTIVE_SCAN_ALLOWLIST` | Comma-separated exact hostnames, wildcard subdomains, IP addresses or CIDR ranges allowed for active TCP probes |
| `UPSTASH_REDIS_REST_URL` | Optional HTTPS endpoint for shared rate limiting |
| `UPSTASH_REDIS_REST_TOKEN` | Optional server-side Upstash token. Never expose it to the browser. |

In Vercel, configure these under the project's encrypted Environment Variables settings and redeploy. The Upstash token must remain server-side. When the Upstash service is unavailable, the application falls back to a process-local limiter. That fallback is not a shared limit across serverless instances.

## API

### `GET /api/health`

Returns service status and version.

### `POST /api/recon`

```json
{
  "target": "example.com"
}
```

The response contains `target`, `active_scope`, `geo`, `dns`, `web`, `ports`, `scanned_at`, `elapsed_ms` and partial-module status. The `ports.status` field distinguishes a completed probe from an out-of-scope target or a deployment where active probing has not been configured.

## Test and lint

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --tb=short
ruff check .
mypy recon app.py --ignore-missing-imports
```

## Project layout

```text
NetRecon/
├── app.py
├── recon/
│   ├── dns_intel.py
│   ├── geo_intel.py
│   ├── logger.py
│   ├── port_scanner.py
│   ├── scope.py
│   ├── validator.py
│   └── web_audit.py
├── static/
│   ├── api.js
│   ├── app.js
│   ├── globe.js
│   ├── render.js
│   └── styles.css
├── templates/
│   ├── 404.html
│   ├── 500.html
│   ├── index.html
│   └── privacy.html
├── docs/
│   └── active-scan-scope.md
└── tests/
    └── test_security.py
```

## License

MIT. See [LICENSE](LICENSE).

**Authorised testing only.** Use NetRecon only on systems you own or have explicit permission to assess.
