# NetRecon

External attack surface reconnaissance for public domains and IP addresses. Enter a target and get DNS, TLS, web header, geolocation and optional port probe results, ranked into findings by severity.

Live demo: https://netrecon.vercel.app

## What it does

* **Geo and network:** location, ASN and network owner, with provider fallback and caching.
* **DNS:** A, AAAA, CNAME, MX, NS and TXT records, reverse DNS, DNS and mail provider detection, SPF and DMARC policy parsing.
* **Web:** TLS certificate health (including why validation failed), protocol and cipher, HTTP to HTTPS redirect check, and defensive headers scored by value, not just presence.
* **Ports:** 22 common services with banner grabbing. Off by default, needs explicit confirmation.
* **Findings:** every result is turned into a ranked finding with a short fix.
* **Output:** Markdown summary, JSON download, and a print stylesheet for a clean PDF report.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `HOST=0.0.0.0` only if you want it reachable on your network.

## API

```bash
curl -s -X POST https://netrecon.vercel.app/api/recon \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com"}'
```

Request fields:

* `target` (required): domain, IP or URL.
* `active` (optional, default false): run the port probe.
* `authorized` (required when `active` is true): confirms you own the target or have written permission.

The response contains `target`, `geo`, `dns`, `web`, `ports`, `findings` and a `summary` of counts per severity. If a probe times out, the rest still return and `scan.partial` lists what is missing.

## Architecture

```
Browser
  |  POST /api/recon  (JSON, same origin only)
  v
Flask app
  |  rate limit, consent gate, origin check, security headers
  v
Validator  resolves the name once, allows only global unicast IPs, pins the IP
  |
  +--> Geo      cached provider lookup
  +--> DNS      parallel queries over fixed public resolvers
  +--> Web      TLS and HEAD over the pinned IP, no redirects, no body
  +--> Ports    TCP connect scan of the pinned IP (active mode only)
  |
  v
Findings engine  ranks results by severity
```

## Threat model

NetRecon makes network requests to addresses chosen by strangers, so the server is the target. The controls below exist for that reason.

* **SSRF to internal networks.** Only globally routable unicast addresses pass. Loopback, private, link local, CGNAT, multicast and reserved ranges are rejected, including IPv4 hidden inside IPv4 mapped, 6to4 and NAT64 IPv6 addresses. Odd IPv4 notations like `127.1` and `0x7f.0.0.1` are caught because the check runs on resolved addresses.
* **DNS rebinding.** The name is resolved once. Every probe then connects to that pinned IP, so a second DNS answer cannot redirect traffic.
* **Redirect based SSRF.** The web audit sends a raw HEAD over the pinned socket. Redirects are reported as data and never followed, and no response body is read, which also removes slow body and oversized body attacks.
* **Port scanner abuse.** Active probing is off by default, needs an explicit authorization flag, and has its own stricter rate limit.
* **Rate limiting on serverless.** The client IP comes from the trusted proxy hop only, not from a client controlled header. Counters live in memory by default and in Upstash Redis when `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` are set, so limits hold across instances.
* **Cross site abuse.** The API accepts JSON only and rejects requests with a foreign `Origin`. Request bodies are capped at 4 KB.
* **XSS.** All dynamic output is escaped, and a nonce based content security policy blocks inline injection. The page uses no inline event handlers or style attributes.
* **Supply chain.** Browser libraries are pinned to exact versions with subresource integrity hashes. Python dependencies are pinned and audited in CI.
* **Timeouts.** Each probe has its own budget. A slow probe returns partial results instead of hanging the request.

Known limits: results for sites behind a CDN describe the CDN edge, not the origin, and the tool says so. Geolocation comes from third party databases and can be wrong.

## Tests and CI

```bash
pip install -r requirements_dev.txt
pytest -q
ruff check . --select E,F,W,B --ignore E501
bandit -q -r app.py recon -s B110
python -m pip_audit -r requirements.txt
```

The suite covers the validator against private ranges and address tricks, DNS rebinding style answers, header scoring, findings logic, the consent gate, the rate limiter, origin checks and the content security policy. GitHub Actions runs lint, the security scan, the dependency audit and the tests on every push and pull request. Dependabot proposes updates with a 14 day cooldown.

## Deploy

Deploys to Vercel as is (`vercel.json` included). Optional environment variables:

* `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`: shared rate limit counters.
* `TRUSTED_PROXIES`: number of proxy hops to trust. Defaults to 1 on Vercel and 0 elsewhere.

## Responsible use

Only scan systems you own or have written permission to test. Active probing sends real traffic to the target from the server. See the privacy page at `/privacy` for what is collected.

## License

MIT
