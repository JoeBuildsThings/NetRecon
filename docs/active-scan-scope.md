# Active scan scope

NetRecon runs passive DNS, web-posture, and IP-geolocation checks for valid public targets. TCP port probes are started automatically when a submitted target matches the deployment operator's configured scope.

The old per-domain DNS TXT challenge has been removed. The replacement is a server-side allowlist, not a user-facing ownership workflow.

## Configure the scope

Set NETRECON_ACTIVE_SCAN_ALLOWLIST in the deployment environment. Separate entries with commas.

Supported entries:

- example.com matches that exact hostname.
- *.example.com matches subdomains of that domain, not the apex itself.
- 203.0.113.24 matches that exact IP.
- 203.0.113.0/24 matches a target whose resolved primary IP is in that network.

Use only hosts and address ranges that the deployment operator is authorized to assess. Keep the variable empty when active probing should remain disabled. The application does not expose the configured entries to visitors.

A target outside the configured scope still receives passive checks. It receives no TCP probes, and the result explains why the port module did not run.

## Rate limiting

The API limits scan submissions to 25 requests per client IP per 60-second window. For serverless deployments, configure both UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN to use a shared counter across instances. The token must remain in the hosting provider's encrypted environment-variable store and must never be placed in frontend code.

When Upstash is unavailable, the process-local limiter is used as a fallback. Process-local limits are not a substitute for a shared limiter across multiple serverless instances.

## Location data

The location panel uses the IP geolocation provider returned by the backend. It displays the provider name and lookup timestamp. The plotted point is approximate network geolocation, not a street address or device location. A map marker is omitted when the provider returns no usable coordinates.
