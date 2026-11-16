(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  const form = $("#reconForm");
  const input = $("#targetInput");
  const scanButton = $("#scanBtn");
  const scanButtonText = $("#scanBtnText");
  const errorBox = $("#errorBox");
  const runState = $("#runState");
  const workbench = $("#workbench");
  const recentTargets = $("#recentTargets");
  const HISTORY_KEY = "netrecon_recent_v3";
  const REQUEST_TIMEOUT_MS = 25000;
  const MAX_HISTORY = 6;

  let latestData = null;
  let scanInProgress = false;
  let mapInstance = null;
  let mapMarker = null;

  function text(element, value) {
    if (element) element.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function makeElement(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined && value !== null) element.textContent = String(value);
    return element;
  }

  function setStatus(state, detail) {
    runState.dataset.state = state;
    const labels = { idle: "Idle", scanning: "Scanning", completed: "Completed", error: "Error" };
    text($("#statusLabel"), labels[state] || "Idle");
    text($("#statusDetail"), detail || "Ready for a target");
    text($("#statusCode"), state === "scanning" ? "NR / 01" : (state === "completed" ? "NR / 02" : (state === "error" ? "NR / !!" : "NR / 00")));
  }

  function setApiStatus(online) {
    const indicator = $("#apiIndicator");
    indicator.dataset.state = online ? "online" : "offline";
    text($("#apiStatus"), online ? "API ONLINE" : "API OFFLINE");
  }

  function showError(message, warning) {
    errorBox.hidden = false;
    errorBox.textContent = message;
    errorBox.classList.toggle("is-warning", Boolean(warning));
  }

  function clearError() {
    errorBox.hidden = true;
    errorBox.classList.remove("is-warning");
    errorBox.textContent = "";
  }

  function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
  }

  function loadHistory() {
    try {
      const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(value) ? value.filter((item) => typeof item === "string").slice(0, MAX_HISTORY) : [];
    } catch (_error) {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
    } catch (_error) {
      // Recent-target storage is optional; the scan itself must remain usable.
    }
  }

  function renderHistory() {
    recentTargets.replaceChildren();
    const history = loadHistory();
    if (!history.length) return;
    recentTargets.appendChild(makeElement("span", "recent-label", "RECENT"));
    history.forEach((host) => {
      const button = makeElement("button", "recent-chip", host);
      button.type = "button";
      button.dataset.host = host;
      button.title = "Use " + host + " as the next target";
      recentTargets.appendChild(button);
    });
  }

  function saveTarget(host) {
    const next = [host].concat(loadHistory().filter((item) => item !== host));
    saveHistory(next);
    renderHistory();
  }

  function addKeyValue(container, label, value) {
    const card = makeElement("div", "kv-card");
    card.appendChild(makeElement("span", "kv-label", label));
    card.appendChild(makeElement("strong", "kv-value", value));
    container.appendChild(card);
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

    addKeyValue(grid, "Canonical host", target.host || "Unavailable");
    addKeyValue(grid, "Resolved address", target.primary_ip || "Unavailable");
    addKeyValue(grid, "All resolved IPs", (target.all_ips || []).join(", ") || "Unavailable");
    addKeyValue(grid, "IP network owner", geo.org || "Unavailable");
    addKeyValue(grid, "DNS provider", dns.posture && dns.posture.dns_provider ? dns.posture.dns_provider : "Unavailable");
    addKeyValue(grid, "Web endpoint", web.reachable ? "Reachable" : "No response");
    addKeyValue(grid, "Active probe", scope.active_probe_started ? "Started in configured scope" : "Not started");
    addKeyValue(grid, "Port module", ports.status || "Unavailable");
  }

  function gradeTone(grade) {
    const value = String(grade || "").toUpperCase();
    if (value.startsWith("A")) return "tone-good";
    if (value.startsWith("B")) return "tone-fair";
    if (value.startsWith("C")) return "tone-warn";
    if (value === "D" || value === "F") return "tone-bad";
    return "tone-muted";
  }

  function renderSummary(data) {
    const target = data.target || {};
    const ports = data.ports || {};
    const web = data.web || {};
    const openPorts = Array.isArray(ports.open_ports) ? ports.open_ports : [];
    const grade = web.grade || "N/A";

    text($("#metricIp"), target.primary_ip || "Unavailable");
    $("#metricIp").classList.toggle("summary-value-muted", !target.primary_ip);
    text($("#metricHost"), target.host || "Resolved address");
    text($("#metricPorts"), ports.status === "completed" ? String(ports.open_count ?? openPorts.length) : (ports.status === "scope_required" ? "Out of scope" : (ports.status === "disabled" ? "Disabled" : "—")));
    text($("#metricPortNote"), ports.status === "completed" ? String(ports.scanned_count || 0) + " common ports checked" : (ports.reason || "No active probe"));
    text($("#metricGrade"), grade);
    $("#metricGrade").className = "summary-value " + gradeTone(grade);
    text($("#metricScore"), typeof web.score === "number" ? String(web.score) + " / 100 posture score" : "TLS and response controls");
    text($("#metricTime"), formatDate(data.scanned_at));
    text($("#metricDuration"), data.elapsed_ms !== undefined ? String(data.elapsed_ms) + " ms elapsed" : "Elapsed time unavailable");
    text($("#resultTarget"), target.host ? target.host.toUpperCase() : "NO TARGET SELECTED");
  }

  function renderRisks(data) {
    const list = $("#riskList");
    list.replaceChildren();
    const items = [];
    const ports = data.ports || {};
    const web = data.web || {};
    const dns = data.dns || {};
    const posture = dns.posture || {};
    const tls = web.tls || {};
    const score = Number(web.score);

    if (ports.status === "scope_required") {
      items.push({ level: "info", title: "Active probe not started", detail: "The target is outside the server-configured active scan scope. Passive checks still completed." });
    } else if (ports.status === "disabled") {
      items.push({ level: "info", title: "Active probing is not configured", detail: "The operator has not configured an active scan scope for this deployment." });
    }

    if (ports.status === "completed") {
      (Array.isArray(ports.open_ports) ? ports.open_ports : []).forEach((port) => {
        const risk = String(port.risk || "info").toLowerCase();
        const level = risk === "high" ? "high" : (risk === "warn" || risk === "medium" ? "medium" : "info");
        items.push({
          level: level,
          title: String(port.service || "Service") + " exposed on TCP/" + String(port.port),
          detail: port.note || "The service accepted a TCP connection from the scanner."
        });
      });
    }

    if (tls.available && !tls.verified) {
      items.push({ level: "high", title: "TLS certificate verification failed", detail: tls.verify_error || "A TLS endpoint was detected but certificate verification did not succeed." });
    }

    if (Number.isFinite(score) && score < 70) {
      items.push({
        level: score < 45 ? "high" : "medium",
        title: "Web posture needs review",
        detail: "The current HTTP and TLS checks returned a score of " + score + " out of 100."
      });
    }

    if (posture.spf_configured === false && posture.spf_status && posture.spf_status !== "N/A" && posture.spf_status !== "Unavailable") {
      items.push({ level: "medium", title: "SPF record not detected", detail: "No SPF policy was returned for the target domain." });
    }

    if (String(posture.dmarc_policy || "").toLowerCase() === "none") {
      items.push({ level: "medium", title: "DMARC policy is monitoring only", detail: "The domain publishes a DMARC record without reject or quarantine enforcement." });
    }

    if (!items.length) {
      const item = makeElement("div", "empty-inline");
      item.appendChild(makeElement("span", "empty-mark", "✓"));
      const copy = makeElement("div");
      copy.appendChild(makeElement("strong", "", "No high-signal issues returned"));
      copy.appendChild(makeElement("p", "", "The available checks did not report a risk indicator. This is not a full security certification."));
      item.appendChild(copy);
      list.appendChild(item);
      return;
    }

    items.slice(0, 8).forEach((finding) => {
      const row = makeElement("div", "risk-item");
      const marker = makeElement("span", "risk-marker risk-" + finding.level, finding.level === "high" ? "!" : (finding.level === "medium" ? "•" : "i"));
      marker.setAttribute("aria-hidden", "true");
      const copy = makeElement("div", "risk-copy");
      copy.appendChild(makeElement("strong", "", finding.title));
      copy.appendChild(makeElement("p", "", finding.detail));
      row.appendChild(marker);
      row.appendChild(copy);
      list.appendChild(row);
    });
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
    text($("#scoreValue"), String(score) + " / 100");
    text($("#scoreGrade"), web.grade || "N/A");
    $("#scoreGrade").className = "score-grade " + gradeTone(web.grade);
    $("#scoreFill").style.width = score + "%";

    const grid = $("#tlsGrid");
    grid.replaceChildren();
    addKeyValue(grid, "HTTP reachable", web.reachable ? "Yes" : "No");
    addKeyValue(grid, "TLS available", tls.available ? "Yes" : "No");
    addKeyValue(grid, "Certificate verified", tls.verified ? "Yes" : "No");
    addKeyValue(grid, "Verification detail", tls.verify_error || "No verification error returned");

    const headerList = $("#headerList");
    headerList.replaceChildren();
    const headers = Array.isArray(web.headers) ? web.headers : [];
    if (!headers.length) {
      headerList.appendChild(makeElement("li", "finding-row", "No header findings returned."));
    } else {
      headers.forEach((header) => {
        const row = makeElement("li", "finding-row");
        row.appendChild(makeElement("strong", "finding-name", header.name || header.header || "Unnamed header"));
        row.appendChild(makeElement("span", "finding-value", header.value || header.status || "No value returned"));
        headerList.appendChild(row);
      });
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
    addKeyValue(summary, "SPF", posture.spf_status || (posture.spf_configured ? "Configured" : "Not detected"));
    addKeyValue(summary, "DMARC", posture.dmarc_status || posture.dmarc_policy || "Unavailable");

    const records = $("#dnsRecords");
    records.replaceChildren();
    const recordObject = dns.records || {};
    Object.keys(recordObject).forEach((key) => {
      const section = makeElement("section", "dns-record-group");
      const heading = makeElement("div", "dns-record-title", key);
      const values = Array.isArray(recordObject[key]) ? recordObject[key] : [recordObject[key]];
      const list = makeElement("ul", "finding-list");
      values.forEach((value) => {
        const row = makeElement("li", "finding-row");
        row.appendChild(makeElement("strong", "finding-name", key));
        row.appendChild(makeElement("span", "finding-value", typeof value === "object" ? JSON.stringify(value) : String(value)));
        list.appendChild(row);
      });
      section.appendChild(heading);
      section.appendChild(list);
      records.appendChild(section);
    });

    if (Array.isArray(dns.ptr) && dns.ptr.length) {
      const ptr = makeElement("div", "ptr-record");
      ptr.appendChild(makeElement("span", "kv-label", "PTR"));
      ptr.appendChild(makeElement("strong", "", dns.ptr.join(", ")));
      records.prepend(ptr);
    }

    if (!records.children.length) {
      records.appendChild(makeElement("p", "empty-inline-note", "No DNS records were returned."));
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
    const summaryRow = makeElement("div", "port-state port-state-" + status);
    summaryRow.appendChild(makeElement("strong", "", status === "completed" ? String(ports.open_count || 0) + " open ports" : (status === "scope_required" ? "Outside configured scope" : (status === "disabled" ? "Active probe disabled" : "Port results unavailable"))));
    summaryRow.appendChild(makeElement("span", "", status === "completed" ? String(ports.scanned_count || 0) + " common TCP ports checked" : message));
    summary.appendChild(summaryRow);

    const openPorts = Array.isArray(ports && ports.open_ports) ? ports.open_ports : [];
    if (status !== "completed" || !openPorts.length) {
      empty.hidden = false;
      if (status === "completed") {
        text(empty.querySelector("strong"), "No open ports reported");
        text(empty.querySelector("span"), "No open ports were returned from the configured common-port set.");
      } else {
        text(empty.querySelector("strong"), status === "scope_required" ? "Active probe not run" : (status === "disabled" ? "Active probe is not configured" : "No port results"));
        text(empty.querySelector("span"), message);
      }
      return;
    }

    empty.hidden = true;
    table.hidden = false;
    openPorts.forEach((entry) => {
      const row = document.createElement("tr");
      const risk = String(entry.risk || "info").toLowerCase();
      const severity = risk === "high" ? "High" : (risk === "warn" || risk === "medium" ? "Review" : "Info");
      [entry.port, entry.service || "Unknown", entry.latency_ms !== undefined ? String(entry.latency_ms) + " ms" : "—", severity, "Open"].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value === undefined || value === null ? "—" : String(value);
        row.appendChild(cell);
      });
      body.appendChild(row);
    });
  }

  function initializeMap() {
    if (!window.L) {
      $("#mapEmpty").hidden = false;
      text($("#mapEmpty").querySelector("strong"), "Map library unavailable");
      text($("#mapEmpty").querySelector("span"), "Location details remain available below.");
      return;
    }

    mapInstance = window.L.map("geoMap", {
      zoomControl: true,
      scrollWheelZoom: false,
      worldCopyJump: true
    }).setView([18, 0], 2);

    window.L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      subdomains: "abcd",
      maxZoom: 19,
      attribution: "&copy; OpenStreetMap contributors &copy; CARTO"
    }).addTo(mapInstance);
  }

  function renderMap(geo, scannedAt) {
    const empty = $("#mapEmpty");
    const source = String(geo && geo.source ? geo.source : "").toLowerCase();
    const hasLatitude = geo && geo.latitude !== null && geo.latitude !== undefined && geo.latitude !== "";
    const hasLongitude = geo && geo.longitude !== null && geo.longitude !== undefined && geo.longitude !== "";
    const lat = hasLatitude ? Number(geo.latitude) : Number.NaN;
    const lon = hasLongitude ? Number(geo.longitude) : Number.NaN;
    const validCoords = Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
    const validSource = source !== "" && source !== "fallback" && source !== "unavailable" && source !== "timeout";
    const place = [geo && geo.city, geo && geo.region, geo && geo.country].filter((value) => value && value !== "Unknown" && value !== "Unavailable").join(", ");

    text($("#geoPlace"), place || "Location unavailable");
    text($("#geoNetwork"), geo && geo.org ? geo.org : "Network owner unavailable");
    text($("#geoSource"), validSource ? geo.source : "Unavailable");
    text($("#geoTimestamp"), formatDate((geo && geo.lookup_at) || scannedAt));

    if (!mapInstance || !validCoords || !validSource) {
      empty.hidden = false;
      text(empty.querySelector("strong"), "Location not plotted");
      text(empty.querySelector("span"), "The geolocation provider returned no usable coordinates.");
      return;
    }

    empty.hidden = true;
    if (mapMarker) mapMarker.remove();
    mapMarker = window.L.circleMarker([lat, lon], {
      radius: 8,
      color: "#c6ff83",
      weight: 2,
      fillColor: "#c6ff83",
      fillOpacity: 0.8
    }).addTo(mapInstance);
    mapMarker.bindPopup("<strong>" + place.replace(/[&<>\"']/g, "") + "</strong><br>Approximate IP location");
    mapInstance.setView([lat, lon], 5, { animate: false });
    window.setTimeout(() => mapInstance.invalidateSize(), 80);
  }

  function renderScan(data) {
    latestData = data;
    const target = data.target || {};
    renderSummary(data);
    renderRisks(data);
    renderOverview(data);
    renderWeb(data.web);
    renderDns(data.dns);
    renderPorts(data.ports);
    renderMap(data.geo || {}, data.scanned_at);
    text($("#rawBox"), JSON.stringify(data, null, 2));
    $("#copyReportBtn").disabled = false;
    $("#exportJsonBtn").disabled = false;
    saveTarget(target.host || target.input || input.value.trim());

    if (data.partial && Array.isArray(data.partial_errors) && data.partial_errors.length) {
      showError("The scan completed with partial results. Unavailable modules: " + data.partial_errors.join(", ") + ".", true);
    }
  }

  async function checkHealth() {
    try {
      const response = await fetch("/api/health", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      const data = await response.json();
      if (!response.ok || data.status !== "ok") throw new Error("API health check failed");
      setApiStatus(true);
    } catch (_error) {
      setApiStatus(false);
    }
  }

  async function runScan(value) {
    const target = String(value || "").trim();
    if (scanInProgress) return;

    if (!target) {
      setStatus("error", "Enter a domain, URL, or public IP address.");
      showError("A target is required before a scan can start.");
      input.focus();
      return;
    }

    if (target.length > 255 || /[\u0000-\u001f\u007f]/.test(target)) {
      setStatus("error", "Target input is not valid.");
      showError("Use a valid domain, HTTP or HTTPS URL, or public IP address.");
      input.focus();
      return;
    }

    clearError();
    scanInProgress = true;
    setStatus("scanning", "Resolving target and running available checks");
    scanButton.disabled = true;
    scanButton.setAttribute("aria-busy", "true");
    scanButtonText.textContent = "Scanning";
    workbench.setAttribute("aria-busy", "true");

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch("/api/recon", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ target: target }),
        signal: controller.signal
      });
      const data = await response.json().catch(() => null);

      if (!data || typeof data !== "object") {
        throw new Error("The API returned an unreadable response. Please try again.");
      }
      if (!response.ok || data.ok === false) {
        setStatus("error", response.status === 429 ? "Rate limit reached" : "The scan could not be completed");
        showError(data.error || "The request failed with status " + response.status + ".");
        return;
      }

      renderScan(data);
      setStatus("completed", data.partial ? "Completed with partial module results" : "Results are ready");
    } catch (error) {
      const message = error && error.name === "AbortError"
        ? "The request timed out. Check the target and try again."
        : (error && error.message ? error.message : "Unable to contact the NetRecon API.");
      setStatus("error", message);
      showError(message);
    } finally {
      window.clearTimeout(timeoutId);
      scanInProgress = false;
      scanButton.disabled = false;
      scanButton.removeAttribute("aria-busy");
      scanButtonText.textContent = "Run scan";
      workbench.setAttribute("aria-busy", "false");
    }
  }

  function activateTab(button, moveFocus) {
    $$(".tab-button").forEach((tab) => {
      const selected = tab === button;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      const panel = document.getElementById("panel-" + tab.dataset.tab);
      if (panel) {
        panel.classList.toggle("is-active", selected);
        panel.hidden = !selected;
      }
    });
    if (moveFocus) button.focus();
  }

  $$(".tab-button").forEach((button) => {
    button.addEventListener("click", () => activateTab(button, false));
    button.addEventListener("keydown", (event) => {
      const tabs = $$(".tab-button");
      const current = tabs.indexOf(button);
      let next = current;
      if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
      else if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault();
      activateTab(tabs[next], true);
    });
  });

  recentTargets.addEventListener("click", (event) => {
    const chip = event.target.closest(".recent-chip");
    if (!chip) return;
    input.value = chip.dataset.host || chip.textContent || "";
    input.focus();
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runScan(input.value);
  });

  $("#copyReportBtn").addEventListener("click", async (event) => {
    if (!latestData) return;
    const data = latestData;
    const ports = data.ports || {};
    const open = Array.isArray(ports.open_ports) ? ports.open_ports : [];
    const lines = [
      "NetRecon scan: " + (data.target && data.target.host ? data.target.host : "unknown target"),
      "Target IP: " + (data.target && data.target.primary_ip ? data.target.primary_ip : "Unavailable"),
      "Location: " + [data.geo && data.geo.city, data.geo && data.geo.country].filter(Boolean).join(", "),
      "Open ports: " + (ports.status === "completed" ? String(ports.open_count || open.length) : ports.status || "Unavailable"),
      "Web posture: " + (data.web && data.web.grade ? data.web.grade : "Unavailable"),
      "Scanned at: " + formatDate(data.scanned_at),
      "Duration: " + (data.elapsed_ms === undefined ? "Unavailable" : String(data.elapsed_ms) + " ms")
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      const button = event.currentTarget;
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = "Copy summary"; }, 1400);
    } catch (_error) {
      showError("Clipboard access is unavailable in this browser. Use Export JSON instead.", true);
    }
  });

  $("#exportJsonBtn").addEventListener("click", () => {
    if (!latestData) return;
    const blob = new Blob([JSON.stringify(latestData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const host = String((latestData.target && latestData.target.host) || "scan").replace(/[^a-z0-9.-]+/gi, "-");
    anchor.href = url;
    anchor.download = "netrecon-" + (host || "scan") + ".json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  initializeMap();
  renderHistory();
  checkHealth();
})();
