from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import socket
import ssl
import time
from recon.logger import get_logger, log_event

logger = get_logger("netrecon.ports")

COMMON_PORTS: list[tuple[int, str, str, str]] = [
    (21, "FTP", "warn", "Cleartext file transfer"),
    (22, "SSH", "warn", "Remote shell access"),
    (23, "Telnet", "high", "Unencrypted legacy shell"),
    (25, "SMTP", "info", "Mail transfer agent"),
    (53, "DNS", "info", "Domain name resolver"),
    (80, "HTTP", "info", "Cleartext web service"),
    (110, "POP3", "warn", "Cleartext mail retrieval"),
    (143, "IMAP", "warn", "Cleartext mail access"),
    (443, "HTTPS", "info", "TLS encrypted web service"),
    (445, "SMB", "high", "Windows file sharing exposed"),
    (465, "SMTPS", "info", "TLS mail submission"),
    (587, "Submission", "info", "Authenticated mail relay"),
    (993, "IMAPS", "info", "TLS encrypted IMAP"),
    (995, "POP3S", "info", "TLS encrypted POP3"),
    (1433, "MSSQL", "high", "Database port publicly reachable"),
    (3306, "MySQL", "high", "Database port publicly reachable"),
    (3389, "RDP", "high", "Remote desktop exposed"),
    (5432, "PostgreSQL", "high", "Database port publicly reachable"),
    (6379, "Redis", "high", "In memory datastore exposed"),
    (8080, "HTTP Alt", "info", "Alternate web or proxy port"),
    (8443, "HTTPS Alt", "info", "Alternate TLS web port"),
    (27017, "MongoDB", "high", "NoSQL database exposed"),
]

CDN_KEYWORDS: dict[str, str] = {
    "cloudflare": "Cloudflare Edge",
    "vercel": "Vercel Edge Network",
    "fastly": "Fastly CDN",
    "akamai": "Akamai Edge",
    "cloudfront": "AWS CloudFront",
    "amazon": "AWS Edge / EC2",
    "google": "Google Cloud / Edge",
    "netlify": "Netlify Edge",
}


def _format_host_header(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def detect_edge_network(org: str, dns_provider: str = "") -> tuple[bool, str]:
    combined = f"{org} {dns_provider}".lower()
    for key, label in CDN_KEYWORDS.items():
        if key in combined:
            return True, label
    return False, ""


def sanitize_banner(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    for line in lines:
        if line.lower().startswith("server:"):
            return line[:110]
    cleaned = "".join(ch if 32 <= ord(ch) <= 126 else " " for ch in lines[0])
    return " ".join(cleaned.split())[:110]


def _grab_banner(sock: socket.socket, port: int, host: str) -> str:
    sock.settimeout(0.6)
    host_header = _format_host_header(host)
    try:
        if port in (80, 8080):
            req = f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: NetRecon/2.2\r\n\r\n".encode()
            sock.sendall(req)
            return sanitize_banner(sock.recv(512))
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.settimeout(0.6)
                req = f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: NetRecon/2.2\r\n\r\n".encode()
                tls_sock.sendall(req)
                banner = sanitize_banner(tls_sock.recv(512))
                proto = tls_sock.version() or "TLS"
                return f"{proto} | {banner}" if banner else proto
        if port in (21, 22, 23, 25, 110, 143, 587):
            return sanitize_banner(sock.recv(256))
    except Exception as exc:
        log_event(
            logger,
            logging.DEBUG,
            "banner_grab_skipped",
            port=port,
            error_type=type(exc).__name__,
        )
        return ""
    return ""


def _probe_single_port(ip: str, host: str, port_meta: tuple[int, str, str, str]) -> dict | None:
    port, service, risk, note = port_meta
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(0.65)
    t0 = time.perf_counter()
    try:
        code = sock.connect_ex((ip, port))
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        if code != 0:
            return None
        banner = _grab_banner(sock, port, host)
        return {
            "port": port,
            "service": service,
            "risk": risk,
            "note": note,
            "latency_ms": latency_ms,
            "banner": banner,
        }
    except Exception as exc:
        log_event(
            logger,
            logging.DEBUG,
            "port_probe_error",
            port=port,
            error_type=type(exc).__name__,
        )
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_common_ports(ip: str, host: str, org: str = "", dns_provider: str = "") -> dict:
    """Concurrently probe high signal TCP ports on the pinned IP and label CDN edge attribution."""
    t_start = time.perf_counter()
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(_probe_single_port, ip, host, meta) for meta in COMMON_PORTS]
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])
    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)
    edge_cdn, edge_provider = detect_edge_network(org, dns_provider)

    return {
        "status": "completed",
        "scanned_ip": ip,
        "edge_cdn": edge_cdn,
        "edge_provider": edge_provider,
        "scanned_count": len(COMMON_PORTS),
        "open_count": len(open_ports),
        "scan_ms": elapsed_ms,
        "open_ports": open_ports,
    }
