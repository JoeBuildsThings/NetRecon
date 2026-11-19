(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);

  function setText(element, value) {
    if (!element) return;
    element.textContent = value === null || value === undefined || value === "" ? "N/A" : String(value);
  }

  function makeEl(tag, className, value) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (value !== undefined && value !== null) el.textContent = String(value);
    return el;
  }

  function formatDate(value) {
    if (!value) return "N/A";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "N/A";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
  }

  function formatCoords(lat, lon) {
    if (typeof lat !== "number" || typeof lon !== "number") return "Coordinates unavailable";
    const ns = lat >= 0 ? "N" : "S";
    const ew = lon >= 0 ? "E" : "W";
    return Math.abs(lat).toFixed(4) + " " + ns + ", " + Math.abs(lon).toFixed(4) + " " + ew;
  }

  function gradeTone(grade) {
    const val = String(grade || "").toUpperCase();
    if (val.startsWith("A")) return "tone-good";
    if (val.startsWith("B")) return "tone-fair";
    if (val.startsWith("C")) return "tone-warn";
    if (val === "D" || val === "F") return "tone-bad";
    return "tone-muted";
  }

  function addKeyValue(container, label, value, toneClass) {
    const card = makeEl("div", "kv-card");
    card.appendChild(makeEl("span", "kv-label", label));
    const valEl = makeEl("strong", "kv-value" + (toneClass ? " " + toneClass : ""), value);
    card.appendChild(valEl);
    container.appendChild(card);
  }

  function renderSummary(data) {
    const target = data.target || {};
    const ports = data.ports || {};
    const web = data.web || {};
    const openPorts = Array.isArray(ports.open_ports) ? ports.open_ports : [];
    const grade = web.grade || "N/A";
    const ipCount = Array.isArray(target.all_ips) ? target.all_ips.length : 0;

    setText($("#metricIp"), target.primary_ip || "Unavailable");
    $("#metricIp").classList.toggle("summary-value-muted", !target.primary_ip);
    setText(
      $("#metricHost"),
      (target.host || "Resolved address") + (ipCount > 1 ? " (" + ipCount + " IPs)" : "")
    );

    const portMetric = ports.status === "completed"
      ? String(ports.open_count ?? openPorts.length)
      : (ports.status === "scope_required" ? "Scoped" : (ports.status === "disabled" ? "Passive" : "N/A"));
    setText($("#metricPorts"), portMetric);
    const portNote = ports.status === "completed"
      ? String(ports.scanned_count || 0) + " common TCP ports probed"
      : (ports.edge_cdn && ports.edge_provider ? "Edge: " + ports.edge_provider : (ports.reason || "Passive telemetry only"));
    setText($("#metricPortNote"), portNote);

    setText($("#metricGrade"), grade);
    $("#metricGrade").className = "summary-value " + gradeTone(grade);
    setText(
      $("#metricScore"),
      typeof web.score === "number" ? String(web.score) + " / 100 security controls" : "TLS and HTTP controls"
    );

    setText($("#metricTime"), formatDate(data.scanned_at));
    setText(
      $("#metricDuration"),
      data.elapsed_ms !== undefined ? String(data.elapsed_ms) + " ms total latency" : "Elapsed time unavailable"
    );
    setText($("#resultTarget"), target.host ? target.host.toUpperCase() : "NO TARGET LOCKED");
  }

  function renderGlobeTelemetry(geo, scannedAt, globeInstance) {
    const source = String(geo && geo.source ? geo.source : "").toLowerCase();
    const hasLat = geo && geo.latitude !== null && geo.latitude !== undefined && geo.latitude !== "";
    const hasLon = geo && geo.longitude !== null && geo.longitude !== undefined && geo.longitude !== "";
    const lat = hasLat ? Number(geo.latitude) : Number.NaN;
    const lon = hasLon ? Number(geo.longitude) : Number.NaN;
    const validCoords = Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
    const validSource = source !== "" && source !== "fallback" && source !== "unavailable" && source !== "timeout";

    const place = [geo && geo.city, geo && geo.region, geo && geo.country]
      .filter((item) => item && item !== "Unknown" && item !== "Unavailable")
      .join(", ");

    setText($("#geoPlace"), place || "Location unavailable");
    const orgLine = [geo && geo.asn && geo.asn !== "N/A" ? geo.asn : "", geo && geo.org ? geo.org : ""]
      .filter(Boolean)
      .join(" | ");
    setText($("#geoNetwork"), orgLine || "Network owner unavailable");
    setText($("#geoCoords"), validCoords && validSource ? formatCoords(lat, lon) : "No coordinate lock");
    setText($("#geoSource"), validSource ? geo.source : "Unavailable");
    setText($("#geoTimestamp"), formatDate((geo && geo.lookup_at) || scannedAt));

    const lockBadge = $("#globeLockBadge");
    if (validCoords && validSource) {
      if (lockBadge) {
        lockBadge.textContent = "TARGET LOCKED";
        lockBadge.dataset.state = "locked";
      }
      if (globeInstance) {
        globeInstance.plotTarget({
          lat,
          lon,
          label: (geo.city && geo.city !== "Unknown" ? geo.city : geo.country) || geo.ip || "Target"
        });
      }
    } else {
      if (lockBadge) {
        lockBadge.textContent = "NO COORD LOCK";
        lockBadge.dataset.state = "idle";
      }
      if (globeInstance) {
        globeInstance.clearTarget();
      }
    }
  }

  function collectFindings(data) {
    const items = [];
    const ports = data.ports || {};
    const web = data.web || {};
    const dns = data.dns || {};
    const posture = dns.posture || {};
    const tls = web.tls || {};
    const disclosures = Array.isArray(web.disclosures) ? web.disclosures : [];
    const redirect = web.redirect || null;
    const score = Number(web.score);

    if (web.reachable && web.https_active === false) {
      items.push({
        level: "high",
        title: "Cleartext HTTP endpoint detected",
        detail: "The target responded over unencrypted HTTP without an active HTTPS connection on TCP/443."
      });
    }

    if (tls.available && !tls.verified) {
      items.push({
        level: "high",
        title: "TLS certificate verification failed",
        detail: tls.verify_error || "A TLS listener answered on TCP/443 but failed standard certificate verification."
      });
    }

    if (tls.available && tls.verified && typeof tls.days_remaining === "number" && tls.days_remaining <= 30) {
      items.push({
        level: tls.days_remaining <= 7 ? "high" : "medium",
        title: tls.days_remaining < 0 ? "TLS certificate expired" : "TLS certificate expiring soon",
        detail: "Certificate expires in " + String(tls.days_remaining) + " days (" + (tls.expires_on || "unknown date") + ")."
      });
    }

    if (redirect && redirect.ssrf_target_blocked) {
      items.push({
        level: "high",
        title: "Redirect points to a restricted destination",
        detail: "Redirect target (" + redirect.location + ") failed public routing validation and was not followed."
      });
    }

    if (ports.status === "completed") {
      (Array.isArray(ports.open_ports) ? ports.open_ports : []).forEach((port) => {
        const risk = String(port.risk || "info").toLowerCase();
        const level = risk === "high" ? "high" : (risk === "warn" || risk === "medium" ? "medium" : "info");
        items.push({
          level,
          title: String(port.service || "Service") + " exposed on TCP/" + String(port.port),
          detail: port.banner ? (port.note + " | Banner: " + port.banner) : (port.note || "Accepted TCP connection.")
        });
      });
    }

    if (web.reachable && Number.isFinite(score) && score < 70) {
      items.push({
        level: score < 45 ? "high" : "medium",
        title: "HTTP security posture needs hardening",
        detail: "Response headers scored " + score + " / 100 (Grade " + (web.grade || "N/A") + "). Review missing controls in Web posture."
      });
    }

    if (disclosures.length) {
      const names = disclosures.map((d) => d.header + ": " + d.value).join(" | ");
      items.push({
        level: "info",
        title: "Server technology headers disclosed",
        detail: names
      });
    }

    if (posture.spf_configured === false && posture.spf_status && posture.spf_status !== "N/A" && posture.spf_status !== "Unavailable") {
      const isWeak = posture.spf_status.toLowerCase().includes("insecure") || posture.spf_status.toLowerCase().includes("neutral");
      items.push({
        level: isWeak ? "high" : "medium",
        title: isWeak ? "Weak SPF sender policy" : "SPF record missing",
        detail: posture.spf_status
      });
    }

    const dmarcPolicy = String(posture.dmarc_policy || "").toLowerCase();
    if (dmarcPolicy === "missing") {
      items.push({
        level: "medium",
        title: "DMARC record missing",
        detail: "No _dmarc TXT policy was returned, leaving domain spoofing controls unenforced."
      });
    } else if (dmarcPolicy === "none") {
      items.push({
        level: "medium",
        title: "DMARC set to monitoring only",
        detail: "Published DMARC policy uses p=none without reject or quarantine enforcement."
      });
    }

    if (ports.status === "scope_required") {
      items.push({
        level: "info",
        title: "Active TCP probe skipped (out of scope)",
        detail: "Passive DNS, TLS, header, and geolocation telemetry completed. Active port probing requires operator scope."
      });
    } else if (ports.status === "disabled") {
      items.push({
        level: "info",
        title: "Active TCP probe disabled",
        detail: "Operator has not configured NETRECON_ACTIVE_SCAN_ALLOWLIST on this deployment."
      });
    }

    return items;
  }

  function renderRisks(data) {
    const list = $("#riskList");
    list.replaceChildren();
    const items = collectFindings(data);

    if (!items.length) {
      const item = makeEl("div", "empty-inline");
      item.appendChild(makeEl("span", "empty-mark tone-good", "OK"));
      const copy = makeEl("div");
      copy.appendChild(makeEl("strong", "", "No high-signal risks flagged"));
      copy.appendChild(makeEl("p", "", "Passive surface checks returned clean baseline controls. This is not a full penetration test."));
      item.appendChild(copy);
      list.appendChild(item);
      return;
    }

    items.slice(0, 10).forEach((finding) => {
      const row = makeEl("div", "risk-item");
      const badgeLabel = finding.level === "high" ? "HIGH" : (finding.level === "medium" ? "MED" : "INFO");
      const marker = makeEl("span", "risk-marker risk-" + finding.level, badgeLabel);
      const copy = makeEl("div", "risk-copy");
      copy.appendChild(makeEl("strong", "", finding.title));
      copy.appendChild(makeEl("p", "", finding.detail));
      row.appendChild(marker);
      row.appendChild(copy);
      list.appendChild(row);
    });
  }

  function renderOverview(data) {
    $("#overviewEmpty").hidden = true;
    const grid = $("#overviewGrid");
    grid.hidden = false;
    grid.replaceChildren();

    const target = data.target || {};
    const geo = data.geo || {};
    const dns = data.dns || {};
    const web = data.web || {};
    const ports = data.ports || {};
    const scope = data.active_scope || {};
    const posture = dns.posture || {};

    addKeyValue(grid, "Canonical host", target.host || "Unavailable");
    addKeyValue(grid, "Primary IP", target.primary_ip || "Unavailable");
    addKeyValue(grid, "Resolved IPs", (target.all_ips || []).join(", ") || "Unavailable");
    addKeyValue(grid, "ASN and owner", [geo.asn, geo.org].filter((v) => v && v !== "N/A").join(" | ") || "Unavailable");
    addKeyValue(grid, "ISP / Timezone", [geo.isp, geo.timezone].filter(Boolean).join(" | ") || "Unavailable");
    addKeyValue(grid, "DNS provider", posture.dns_provider || "Unavailable");
    addKeyValue(grid, "Mail provider", posture.mail_provider || "Unavailable");
    addKeyValue(grid, "Edge / CDN", ports.edge_cdn && ports.edge_provider ? ports.edge_provider : "Direct / Unclassified");
    addKeyValue(grid, "Web endpoint", web.reachable ? (web.final_url || "Reachable") : "No HTTP response");
    addKeyValue(grid, "Active probe", scope.active_probe_started ? "Completed in scope" : (ports.status || "Passive only"));
  }

  function renderWeb(web) {
    const empty = $("#webEmpty");
    const box = $("#webBox");
    if (!web) {
      empty.hidden = false;
      box.hidden = true;
      return;
    }

    empty.hidden = true;
    box.hidden = false;

    const score = Math.max(0, Math.min(100, Number(web.score || 0)));
    const tls = web.tls || {};
    setText($("#scoreValue"), String(score) + " / 100");
    setText($("#scoreGrade"), web.grade || "N/A");
    $("#scoreGrade").className = "score-grade " + gradeTone(web.grade);
    $("#scoreFill").style.width = score + "%";

    const grid = $("#tlsGrid");
    grid.replaceChildren();
    addKeyValue(grid, "HTTP status", web.reachable ? String(web.status_code || "Reachable") + " (" + (web.https_active ? "HTTPS" : "HTTP") + ")" : "Unreachable");
    addKeyValue(grid, "TLS protocol", tls.protocol || (tls.available ? "Detected" : "Unavailable"));
    addKeyValue(grid, "Cipher suite", tls.cipher || "Unavailable");
    addKeyValue(grid, "Certificate issuer", tls.issuer || "Unavailable");
    addKeyValue(
      grid,
      "Verification",
      tls.available ? (tls.verified ? "Trusted chain" : (tls.verify_error || "Unverified")) : "No TLS",
      tls.available ? (tls.verified ? "tone-good" : "tone-bad") : "tone-muted"
    );
    addKeyValue(
      grid,
      "Certificate expiry",
      typeof tls.days_remaining === "number"
        ? String(tls.days_remaining) + " days remaining"
        : (tls.expires_on || "Unavailable"),
      typeof tls.days_remaining === "number" && tls.days_remaining <= 30 ? "tone-warn" : ""
    );
    addKeyValue(grid, "Common name", tls.common_name || "Unavailable");
    addKeyValue(
      grid,
      "Subject alt names",
      typeof tls.san_count === "number" && tls.san_count > 0
        ? String(tls.san_count) + " SANs (" + (tls.sans || []).slice(0, 3).join(", ") + ")"
        : "None reported"
    );

    const headerList = $("#headerList");
    headerList.replaceChildren();
    const headers = Array.isArray(web.headers) ? web.headers : [];
    if (!headers.length) {
      headerList.appendChild(makeEl("li", "finding-row", "No HTTP security header data returned."));
    } else {
      headers.forEach((header) => {
        const row = makeEl("li", "finding-row header-audit-row");
        const left = makeEl("div", "finding-meta");
        const titleLine = makeEl("div", "finding-title-line");
        titleLine.appendChild(makeEl("strong", "finding-name", header.header || header.label || "Header"));
        const pts = String(header.points ?? 0) + "/" + String(header.max_points ?? 0) + " pts";
        const qualityTone = header.points === header.max_points ? "pill-good" : (header.points > 0 ? "pill-warn" : "pill-bad");
        titleLine.appendChild(makeEl("span", "status-pill " + qualityTone, (header.quality || "Unknown") + " | " + pts));
        left.appendChild(titleLine);
        if (header.advice) {
          left.appendChild(makeEl("span", "finding-advice", header.advice));
        }
        row.appendChild(left);
        row.appendChild(makeEl("span", "finding-value", header.value || "Not sent by server"));
        headerList.appendChild(row);
      });
    }

    const extraBox = $("#webExtras");
    extraBox.replaceChildren();

    const disclosures = Array.isArray(web.disclosures) ? web.disclosures : [];
    if (disclosures.length) {
      const sec = makeEl("div", "extra-block");
      sec.appendChild(makeEl("h4", "extra-title", "Server disclosures"));
      const ul = makeEl("ul", "finding-list");
      disclosures.forEach((item) => {
        const li = makeEl("li", "finding-row");
        li.appendChild(makeEl("strong", "finding-name", item.header));
        li.appendChild(makeEl("span", "finding-value", item.value));
        ul.appendChild(li);
      });
      sec.appendChild(ul);
      extraBox.appendChild(sec);
    }

    if (web.redirect) {
      const sec = makeEl("div", "extra-block");
      sec.appendChild(makeEl("h4", "extra-title", "Single-hop redirect inspection"));
      const p1 = makeEl("p", "extra-copy", "Location: " + web.redirect.location);
      const p2 = makeEl(
        "p",
        "extra-copy " + (web.redirect.ssrf_target_blocked ? "tone-bad" : "tone-muted"),
        web.redirect.note || "Redirect not followed."
      );
      sec.appendChild(p1);
      sec.appendChild(p2);
      extraBox.appendChild(sec);
    }
  }

  function renderDns(dns) {
    const empty = $("#dnsEmpty");
    const box = $("#dnsBox");
    if (!dns) {
      empty.hidden = false;
      box.hidden = true;
      return;
    }

    empty.hidden = true;
    box.hidden = false;
    const posture = dns.posture || {};
    const summary = $("#dnsSummary");
    summary.replaceChildren();
    addKeyValue(summary, "DNS provider", posture.dns_provider || "Unavailable");
    addKeyValue(summary, "Mail provider", posture.mail_provider || "Unavailable");
    addKeyValue(
      summary,
      "SPF policy",
      posture.spf_status || (posture.spf_configured ? "Configured" : "Missing"),
      posture.spf_configured ? "tone-good" : "tone-warn"
    );
    addKeyValue(
      summary,
      "DMARC policy",
      posture.dmarc_status || posture.dmarc_policy || "Unavailable",
      posture.dmarc_configured ? "tone-good" : "tone-warn"
    );

    const records = $("#dnsRecords");
    records.replaceChildren();

    if (Array.isArray(dns.ptr) && dns.ptr.length) {
      const ptr = makeEl("div", "ptr-record");
      ptr.appendChild(makeEl("span", "kv-label", "PTR Reverse DNS"));
      ptr.appendChild(makeEl("strong", "", dns.ptr.join(", ")));
      records.appendChild(ptr);
    }

    const recordObject = dns.records || {};
    Object.keys(recordObject).forEach((key) => {
      const rawVals = Array.isArray(recordObject[key]) ? recordObject[key] : [recordObject[key]];
      const values = rawVals.filter((v) => v !== null && v !== undefined && v !== "");
      if (!values.length) return;
      const section = makeEl("section", "dns-record-group");
      section.appendChild(makeEl("div", "dns-record-title", key + " (" + values.length + ")"));
      const list = makeEl("ul", "finding-list");
      values.forEach((value) => {
        const row = makeEl("li", "finding-row");
        row.appendChild(makeEl("strong", "finding-name", key));
        row.appendChild(makeEl("span", "finding-value", typeof value === "object" ? JSON.stringify(value) : String(value)));
        list.appendChild(row);
      });
      section.appendChild(list);
      records.appendChild(section);
    });

    if (!records.children.length) {
      records.appendChild(makeEl("p", "empty-inline-note", "No DNS records were returned for this target."));
    }
  }

  function renderPorts(ports) {
    const summary = $("#portSummary");
    const empty = $("#portsEmpty");
    const table = $("#portsTableWrap");
    const body = $("#portsBody");
    summary.replaceChildren();
    body.replaceChildren();
    table.hidden = true;

    const status = ports && ports.status ? ports.status : "unavailable";
    const message = ports && ports.reason ? ports.reason : "No active port result is available.";
    const summaryRow = makeEl("div", "port-state port-state-" + status);
    const titleText = status === "completed"
      ? String(ports.open_count || 0) + " open ports detected" + (ports.edge_cdn && ports.edge_provider ? " | Edge: " + ports.edge_provider : "")
      : (status === "scope_required" ? "Outside active scan scope" : (status === "disabled" ? "Active probe disabled" : "Port results unavailable"));
    summaryRow.appendChild(makeEl("strong", "", titleText));
    summaryRow.appendChild(
      makeEl(
        "span",
        "",
        status === "completed"
          ? String(ports.scanned_count || 0) + " common TCP ports checked in " + String(ports.scan_ms || 0) + " ms"
          : message
      )
    );
    summary.appendChild(summaryRow);

    const openPorts = Array.isArray(ports && ports.open_ports) ? ports.open_ports : [];
    if (status !== "completed" || !openPorts.length) {
      empty.hidden = false;
      if (status === "completed") {
        setText(empty.querySelector("strong"), "No open common TCP ports");
        setText(empty.querySelector("span"), "None of the scanned common TCP ports accepted a connection.");
      } else {
        setText(
          empty.querySelector("strong"),
          status === "scope_required" ? "Active probe not run" : (status === "disabled" ? "Active probe not configured" : "No port results")
        );
        setText(empty.querySelector("span"), message);
      }
      return;
    }

    empty.hidden = true;
    table.hidden = false;
    openPorts.forEach((entry) => {
      const row = document.createElement("tr");
      const risk = String(entry.risk || "info").toLowerCase();
      const severity = risk === "high" ? "High" : (risk === "warn" || risk === "medium" ? "Review" : "Info");
      const cells = [
        entry.port,
        entry.service || "Unknown",
        entry.latency_ms !== undefined ? String(entry.latency_ms) + " ms" : "N/A",
        severity,
        entry.banner || "No banner",
        "Open"
      ];
      cells.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value === undefined || value === null ? "N/A" : String(value);
        row.appendChild(cell);
      });
      body.appendChild(row);
    });
  }

  function buildSummaryText(data) {
    const target = data.target || {};
    const geo = data.geo || {};
    const web = data.web || {};
    const dns = data.dns || {};
    const posture = dns.posture || {};
    const ports = data.ports || {};
    const tls = web.tls || {};
    const findings = collectFindings(data);

    const lines = [
      "NETRECON EXTERNAL POSTURE BRIEF",
      "Target: " + (target.host || "Unknown") + " (" + (target.primary_ip || "Unavailable") + ")",
      "Network: " + [geo.asn, geo.org].filter((v) => v && v !== "N/A").join(" | "),
      "Approx Location: " + [geo.city, geo.region, geo.country].filter((v) => v && v !== "Unknown" && v !== "Unavailable").join(", "),
      "Web Posture: Grade " + (web.grade || "N/A") + " (" + String(web.score ?? 0) + "/100) | TLS: " + (tls.protocol || "Unavailable") + " | Verified: " + (tls.verified ? "Yes" : "No"),
      "Mail Controls: SPF (" + (posture.spf_status || "N/A") + ") | DMARC (" + (posture.dmarc_status || "N/A") + ")",
      "TCP Probe: " + (ports.status === "completed" ? String(ports.open_count || 0) + " open of " + String(ports.scanned_count || 0) : (ports.status || "Unavailable")),
      "Scanned At: " + formatDate(data.scanned_at) + " (" + String(data.elapsed_ms ?? 0) + " ms)",
      "",
      "Key Observations:"
    ];

    if (!findings.length) {
      lines.push("* No high-signal exposure indicators flagged.");
    } else {
      findings.slice(0, 6).forEach((item) => {
        lines.push("* [" + item.level.toUpperCase() + "] " + item.title + ": " + item.detail);
      });
    }
    return lines.join("\n");
  }

  window.NetReconRender = {
    setText,
    makeEl,
    formatDate,
    renderSummary,
    renderGlobeTelemetry,
    renderRisks,
    renderOverview,
    renderWeb,
    renderDns,
    renderPorts,
    buildSummaryText
  };
})();
