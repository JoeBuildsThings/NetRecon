<div align="center">

# NetRecon

**External Attack-Surface, DNS, TLS & Geolocation Reconnaissance Workbench**

<p>
  <a href="https://netrecon.vercel.app"><img src="https://img.shields.io/badge/Live%20Workbench-netrecon.vercel.app-F59E0B?style=flat-square&logo=vercel&logoColor=0B0C0E" alt="Live Workbench" /></a>
  <img src="https://img.shields.io/badge/Python-3.12%20%7C%20Flask-111317?style=flat-square&logo=python&logoColor=F59E0B" alt="Python Flask" />
  <img src="https://img.shields.io/badge/Security-SSRF%20Guarded-111317?style=flat-square&logo=shield&logoColor=10B981" alt="SSRF Guarded" />
  <img src="https://img.shields.io/badge/Engine-Concurrent%20TCP%20%2B%20DNS-111317?style=flat-square&logo=cloudflare&logoColor=F3F4F6" alt="Concurrent TCP and DNS" />
</p>

**[Open Live Deployment -> netrecon.vercel.app](https://netrecon.vercel.app)**

</div>

---

### Overview

NetRecon is an external reconnaissance and infrastructure auditing workbench built with **Python**, **Flask**, and **dnspython**. Given any public domain, URL, IPv4, or IPv6 address, it executes four independent intelligence pipelines in parallel and streams structured telemetry into a responsive, high-contrast command interface with an interactive **3D Cartographic Canvas Globe**.

---

### Telemetry & Execution Pipeline

```text
  [ Target Input: URL / Domain / IPv4 / IPv6 ]
                       │
                       ▼
        ┌──────────────────────────────┐
        │   recon/validator.py         │
        │   · Strip scheme/port/path   │
        │   · Resolve getaddrinfo()    │
        │   · Block RFC1918, Loopback, │
        │     Link-Local, CGNAT & Resv │
        └──────────────┬───────────────┘
                       │ Public Routable Target
                       ▼
        ┌──────────────────────────────┐
        │   ThreadPoolExecutor (x4)    │
        └──┬────────┬────────┬──────┬──┘
           │        │        │      │
    ┌──────▼──┐ ┌───▼────┐ ┌─▼────┐ ┌▼─────────┐
    │Geo / ASN│ │22-Port │ │ DNS  │ │TLS & HTTP│
    │Resolver │ │Scanner │ │& PTR │ │ Grader   │
    └──────┬──┘ └───┬────┘ └─┬────┘ └┬─────────┘
           └────────┴────────┴───────┘
                       │
                       ▼
        [ Structured JSON -> UI + 3D Globe ]
```

---

### Engineering & Security Architecture

| Module | Responsibility & Guardrails |
| :--- | :--- |
| **`recon/validator.py`** | Normalizes raw URLs, hostnames, and bracketed IPv6 literals; resolves all `AF_INET`/`AF_INET6` records and rejects loopback (`127.0.0.0/8`, `::1`), RFC1918 private (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`), CGNAT (`100.64/10`), multicast, and reserved blocks to prevent SSRF. |
| **`recon/port_scanner.py`** | Probes **22 high-signal TCP ports** concurrently (`16` worker threads), recording per-port connect latency (`ms`), exposure classification (`info`, `warn`, `high`), and read-only service banners (`HTTP`/`HTTPS` `HEAD` headers, `SSH`/`SMTP`/`FTP` greetings). |
| **`recon/dns_intel.py`** | Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `_dmarc`, and reverse `PTR` records over `1.1.1.1` / `8.8.8.8`, automatically fingerprinting DNS/edge providers (Cloudflare, Vercel, AWS Route 53, Google Cloud, Azure) and mail infrastructure (Google Workspace, Microsoft 365, Zoho, Proton) plus `SPF`/`DMARC` status. |
| **`recon/web_audit.py`** | Performs a live TLS handshake on `443/tcp` to extract TLS protocol version, cipher suite, issuer CA, SAN count, and certificate expiration countdown, then grades (`A+` to `F`) defensive HTTP headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) and flags `Server` / `X-Powered-By` leaks. |
| **`recon/geo_intel.py`** | Resolves IP geolocation, coordinates, timezone, ASN, and organization metadata over HTTPS (`ipwho.is` primary with automatic `ipapi.co` fallback). |
| **`app.py`** | Flask WSGI entrypoint enforcing a per-IP sliding-window rate limiter (`25` scans/min), strict response security headers (`X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`), and sanitized error responses. |
| **`templates/index.html`** | Responsive hairline-grid UI (`Space Grotesk` + `IBM Plex Sans` + `IBM Plex Mono`) featuring a zero-dependency **3D Canvas Globe** (Fibonacci dot-matrix sphere, continental coastlines, global IXP nodes, geodesic target arc, drag/swipe inertia), one-click **Copy Markdown**, **Export JSON**, and `localStorage` scan history. |

---

### API Reference

#### `POST /api/recon`

Execute a full reconnaissance sweep against a public target:

```bash
curl -X POST https://netrecon.vercel.app/api/recon \
  -H "Content-Type: application/json" \
  -d '{"target": "github.com"}'
```

**Response (`200 OK`):**

```json
{
  "ok": true,
  "elapsed_ms": 642.4,
  "target": {
    "input": "github.com",
    "host": "github.com",
    "primary_ip": "140.82.121.4",
    "all_ips": ["140.82.121.4"],
    "is_ip": false
  },
  "geo": {
    "asn": "AS36459",
    "org": "GitHub, Inc.",
    "city": "Frankfurt am Main",
    "country": "Germany",
    "latitude": 50.1109,
    "longitude": 8.6821
  },
  "ports": {
    "scanned_count": 22,
    "open_count": 3,
    "scan_ms": 418.2,
    "open_ports": [
      { "port": 22, "service": "SSH", "risk": "warn", "latency_ms": 41.3, "banner": "SSH-2.0-babeld-..." },
      { "port": 80, "service": "HTTP", "risk": "info", "latency_ms": 39.8, "banner": "" },
      { "port": 443, "service": "HTTPS", "risk": "info", "latency_ms": 40.1, "banner": "TLSv1.3" }
    ]
  },
  "dns": {
    "posture": {
      "dns_provider": "AWS Route 53",
      "mail_provider": "Google Workspace",
      "spf_configured": true,
      "dmarc_configured": true
    }
  },
  "web": {
    "grade": "A+",
    "score": 100
  }
}
```

#### `GET /api/health`

Returns service liveness and version metadata (`{"status": "ok", "service": "netrecon", "version": "2.0.0"}`).

---

### Local Setup

```bash
git clone https://github.com/JoeBuildsThings/NetRecon.git
cd NetRecon
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

---

### Usage Notice

Built for authorized security assessments, infrastructure verification, and educational reconnaissance on systems you own or have explicit permission to test.

Built by **[@JoeBuildsThings](https://github.com/JoeBuildsThings)**.
