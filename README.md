<div align="center">

# NetRecon

**Modular External Attack-Surface, DNS, TLS & Geolocation Reconnaissance Workbench**

<p>
  <a href="https://netrecon.vercel.app"><img src="https://img.shields.io/badge/Live%20App-netrecon.vercel.app-38BDF8?style=flat-square&logo=vercel&logoColor=090C10" alt="Live App" /></a>
  <img src="https://img.shields.io/badge/Python-3.12%20%7C%20Flask-090C10?style=flat-square&logo=python&logoColor=3776AB" alt="Python Flask" />
  <img src="https://img.shields.io/badge/Security-SSRF%20Protected-090C10?style=flat-square&logo=shield&logoColor=10B981" alt="SSRF Protected" />
</p>

**[Launch Live Workbench](https://netrecon.vercel.app)**

</div>

---

### Overview

NetRecon is a responsive web reconnaissance workbench built with **Python**, **Flask**, and **dnspython** for rapid passive and active external footprinting of public domains and IP addresses.

Instead of sequential blocking scripts, NetRecon orchestrates four independent intelligence modules concurrently via `ThreadPoolExecutor` and streams structured JSON into an adaptive dark-slate dashboard featuring an interactive 3D Canvas geolocation globe.

---

### Core Capabilities

* **SSRF-Safe Target Normalization (`recon/validator.py`):** Accepts raw URLs, hostnames, IPv4, or IPv6 addresses, resolves all `getaddrinfo` records, and blocks loopback, RFC1918 private, link-local, CGNAT (`100.64.0.0/10`), multicast, and reserved ranges before opening any outbound socket.
* **Concurrent TCP Port & Banner Scanner (`recon/port_scanner.py`):** Probes 22 high-signal TCP ports concurrently with per-port handshake latency (`ms`), exposure classification (`info`, `warn`, `high`), and read-only service banner grabbing.
* **DNS & Infrastructure Fingerprinting (`recon/dns_intel.py`):** Resolves `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `DMARC`, and reverse `PTR` records over `1.1.1.1` / `8.8.8.8`, automatically identifying DNS/edge providers (Cloudflare, Vercel, Route 53, Google Cloud) and mail providers (Google Workspace, Microsoft 365, Zoho, Proton).
* **TLS Certificate & HTTP Security Header Audit (`recon/web_audit.py`):** Inspects live TLS protocol/cipher versions, issuer, SANs, and certificate expiration countdowns, then grades (`A+` to `F`) defensive HTTP headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) and flags `Server` / `X-Powered-By` disclosures.
* **Interactive 3D Telemetry Globe & Operator Exports (`templates/index.html`):** Dependency-free HiDPI Canvas 3D globe that rotates in standby and locks onto target coordinates on scan completion, paired with one-click **Copy Markdown**, **Export JSON**, and local scan history.

---

### Architecture

```text
NetRecon/
├── app.py                    # Flask WSGI entrypoint, sliding-window rate limiter & security headers
├── recon/
│   ├── validator.py          # URL/domain/IP normalizer + SSRF private-range blocklist
│   ├── geo_intel.py          # HTTPS geolocation & ASN resolver with automatic provider fallback
│   ├── port_scanner.py       # Concurrent TCP connect scanner, latency timer & banner grabber
│   ├── dns_intel.py          # Multi-record DNS + PTR resolver & cloud/mail fingerprinter
│   └── web_audit.py          # Live TLS cert inspector & HTTP security header grader
├── templates/
│   └── index.html            # Mobile/tablet/desktop responsive UI + 3D Canvas globe
├── requirements.txt          # Flask, requests, dnspython
└── vercel.json               # Vercel Python serverless routing
```

---

### Local Development

```bash
git clone https://github.com/JoeBuildsThings/NetRecon.git
cd NetRecon
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

### Disclaimer

Built for authorized security assessments, infrastructure verification, and educational reconnaissance on systems you own or have explicit permission to test.

Built by **[@JoeBuildsThings](https://github.com/JoeBuildsThings)**.
