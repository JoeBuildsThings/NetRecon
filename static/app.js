(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const form = $("#reconForm");
  const targetInput = $("#targetInput");
  const scanBtn = $("#scanBtn");
  const scanBtnText = $("#scanBtnText");
  const portsToggle = $("#activePortsToggle");
  const errorBox = $("#errorBox");
  const recentBar = $("#recentBar");
  const statusPill = $("#statusPill");
  const statusText = $("#statusText");
  const workbench = $("#workbench");
  const targetContext = $("#targetContext");

  let latestData = null;
  let scanInProgress = false;
  const HISTORY_KEY = "netrecon_recent_v22";
  const MAX_HISTORY = 8;
  const REQUEST_TIMEOUT_MS = 30000;

  function setStatus(state, label) {
    statusPill.classList.remove("is-busy", "is-error", "is-online");
    if (state === "busy") statusPill.classList.add("is-busy");
    else if (state === "error") statusPill.classList.add("is-error");
    else statusPill.classList.add("is-online");
    statusText.textContent = label;
  }

  function showError(message, warning = false) {
    errorBox.textContent = message;
    errorBox.classList.add("is-visible");
    errorBox.classList.toggle("is-warn", Boolean(warning));
  }

  function clearError() {
    errorBox.classList.remove("is-visible", "is-warn");
    errorBox.textContent = "";
  }

  function loadHistory() {
    try {
      const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(value) ? value.filter((item) => typeof item === "string").slice(0, MAX_HISTORY) : [];
    } catch {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
    } catch {
      // Scanning remains available when browser storage is disabled or full.
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[char]);
  }

  function renderHistory() {
    recentBar.innerHTML = loadHistory()
      .map((host) => `<button type="button" class="recent-chip" data-host="${escapeHtml(host)}">${escapeHtml(host)}</button>`)
      .join("");
  }

  function pushHistory(data) {
    const host = data?.target?.host || data?.target?.input;
    if (!host) return;
    const next = [host, ...loadHistory().filter((item) => item !== host)];
    saveHistory(next);
    renderHistory();
  }

  function gradeColor(grade) {
    if (!grade || grade === "N/A") return "var(--ink-muted)";
    const value = String(grade).toUpperCase();
    if (value.startsWith("A")) return "var(--green)";
    if (value.startsWith("B")) return "var(--accent)";
    if (value.startsWith("C")) return "var(--amber)";
    return "var(--red)";
  }

  function renderMetrics(data) {
    const target = data.target || {};
    const geo = data.geo || {};
    const web = data.web || {};
    const ports = data.ports || {};

    $("#metricIp").textContent = target.primary_ip || "N/A";
    $("#metricHost").textContent = target.host || (target.is_ip ? "Direct IP" : "N/A");

    const location = [geo.city, geo.country].filter(Boolean).join(", ") || "Unknown location";
    $("#metricGeo").textContent = geo.asn || "N/A";
    $("#metricOrg").textContent = `${location} · ${geo.org || "Unknown network"}`;

    const grade = web.grade || "N/A";
    $("#metricGrade").textContent = grade;
    $("#metricGrade").style.color = gradeColor(grade);
    const tls = web.tls || {};
    $("#metricTls").textContent = tls.available ? (tls.verified ? "TLS verified" : "TLS present · unverified") : "TLS unavailable";

    const portStatus = ports.status || "unknown";
    if (portStatus === "verification_required") {
      $("#metricPorts").textContent = "Verify TXT";
      $("#metricLatency").textContent = "Ownership required";
    } else if (portStatus === "skipped") {
      $("#metricPorts").textContent = "Skipped";
      $("#metricLatency").textContent = "Passive mode";
    } else if (portStatus === "timeout") {
      $("#metricPorts").textContent = "Timeout";
      $("#metricLatency").textContent = ports.reason || "Module timeout";
    } else {
      const openCount = ports.open_count ?? (ports.open_ports || []).length;
      $("#metricPorts").textContent = `${openCount} open`;
      $("#metricLatency").textContent = ports.scan_ms != null ? `${ports.scan_ms} ms · ${ports.scanned_count || 0} checked` : "N/A";
    }

    $("#sideElapsed").textContent = data.elapsed_ms != null ? `${data.elapsed_ms} ms` : "N/A";
    const partialErrors = Array.isArray(data.partial_errors) ? data.partial_errors : [];
    $("#sidePartial").textContent = partialErrors.length ? partialErrors.join(", ") : (data.partial ? "Partial" : "None");
    const ownership = data.ownership || {};
    $("#sideOwn").textContent = ownership.verified ? "Verified" : (ownership.verified === false ? "Unverified" : "Not checked");
    $("#sideMode").textContent = portsToggle.checked ? "Ports enabled" : "Passive only";
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

    const score = Number(web.score ?? 0);
    const grade = web.grade || "N/A";
    $("#scoreGrade").textContent = grade;
    $("#scoreGrade").style.color = gradeColor(grade);
    $("#scoreFill").style.width = `${Math.min(100, Math.max(0, score))}%`;
    $("#scoreLabel").textContent = `${score}/100`;

    const tls = web.tls || {};
    const tlsItems = [
      ["Reachable", web.reachable ? "Yes" : "No"],
      ["TLS available", tls.available ? "Yes" : "No"],
      ["TLS verified", tls.verified ? "Yes" : "No"],
      ["Verification detail", tls.verify_error || "N/A"],
    ];
    $("#tlsGrid").innerHTML = tlsItems.map(([key, value]) =>
      `<div class="kv-card"><div class="k">${escapeHtml(key)}</div><div class="v">${escapeHtml(String(value))}</div></div>`
    ).join("");

    const headers = Array.isArray(web.headers) ? web.headers : [];
    $("#headerList").innerHTML = headers.length
      ? headers.map((header) => {
          const name = header.name || header.header || "Unnamed header";
          const value = header.value || header.status || JSON.stringify(header);
          return `<li><span class="name">${escapeHtml(name)}</span><span class="val">${escapeHtml(String(value))}</span></li>`;
        }).join("")
      : '<li><span class="name">No header findings returned</span><span class="val">N/A</span></li>';
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
    const summary = [
      ["DNS provider", posture.dns_provider || "N/A"],
      ["Mail provider", posture.mail_provider || "N/A"],
      ["SPF", posture.spf_status || (posture.spf_configured ? "Configured" : "Missing")],
      ["DMARC", posture.dmarc_status || posture.dmarc_policy || "N/A"],
    ];
    $("#dnsSummary").innerHTML = summary.map(([key, value]) =>
      `<div class="kv-card"><div class="k">${escapeHtml(key)}</div><div class="v">${escapeHtml(String(value))}</div></div>`
    ).join("");

    const records = dns.records || {};
    let markup = "";
    if (Array.isArray(dns.ptr) && dns.ptr.length) {
      markup += `<div class="kv-card ptr-card"><div class="k">PTR</div><div class="v">${escapeHtml(dns.ptr.join(", "))}</div></div>`;
    }
    for (const [key, recordValue] of Object.entries(records)) {
      const values = Array.isArray(recordValue) ? recordValue : [recordValue];
      markup += `<div class="dns-record-group"><div class="micro-label">${escapeHtml(key)}</div><ul class="header-list">`;
      for (const value of values) {
        const output = typeof value === "object" && value !== null ? JSON.stringify(value) : String(value);
        markup += `<li><span class="name">${escapeHtml(key)}</span><span class="val">${escapeHtml(output)}</span></li>`;
      }
      markup += "</ul></div>";
    }
    $("#dnsRecords").innerHTML = markup || '<p class="empty-state dns-empty">No DNS records returned.</p>';
  }

  function renderPorts(ports, ownership) {
    const banner = $("#ownBanner");
    const empty = $("#portsEmpty");
    const box = $("#portsBox");
    const status = ports?.status || "";

    if (status === "verification_required") {
      banner.classList.add("is-visible");
      $("#ownReason").textContent = ports.reason || ownership?.reason || "Domain ownership verification is required before active port probing.";
      const host = ports.txt_host || ownership?.txt_host || "";
      const value = ports.txt_value || ownership?.txt_value || "";
      $("#ownTxt").textContent = host && value ? `${host}  TXT  "${value}"` : (value || host || "See ownership challenge response");
      empty.hidden = true;
      box.hidden = true;
      return;
    }

    banner.classList.remove("is-visible");
    if (!ports || status === "skipped") {
      empty.hidden = false;
      empty.querySelector("strong").textContent = status === "skipped" ? "Port probe skipped" : "Port data not available";
      empty.querySelector("span:last-child").textContent = status === "skipped" ? "Passive mode is active or ownership has not been verified." : "Port results appear when an audit completes.";
      box.hidden = true;
      return;
    }
    if (status === "timeout") {
      empty.hidden = false;
      empty.querySelector("strong").textContent = "Port probe timed out";
      empty.querySelector("span:last-child").textContent = ports.reason || "The port module exceeded its time budget.";
      box.hidden = true;
      return;
    }

    const openPorts = Array.isArray(ports.open_ports) ? ports.open_ports : [];
    if (!openPorts.length) {
      empty.hidden = false;
      empty.querySelector("strong").textContent = "No open ports reported";
      empty.querySelector("span:last-child").textContent = "No open ports were returned from the common port set.";
      box.hidden = true;
      return;
    }

    empty.hidden = true;
    box.hidden = false;
    $("#portsBody").innerHTML = openPorts.map((entry) => {
      const port = entry.port ?? entry;
      const service = entry.service || "N/A";
      const latency = entry.latency_ms != null ? `${entry.latency_ms} ms` : "N/A";
      return `<tr><td>${escapeHtml(String(port))}</td><td>${escapeHtml(String(service))}</td><td>${escapeHtml(latency)}</td><td><span class="badge badge-green">Open</span></td></tr>`;
    }).join("");
  }

  function renderScan(data) {
    latestData = data;
    clearError();
    renderMetrics(data);
    renderWeb(data.web);
    renderDns(data.dns);
    renderPorts(data.ports, data.ownership);
    $("#rawBox").textContent = JSON.stringify(data, null, 2);

    const host = data.target?.host || data.target?.input || "Target complete";
    targetContext.innerHTML = `<span class="context-dot"></span> ${escapeHtml(host)}`;
    $("#copyMdBtn").disabled = false;
    $("#exportJsonBtn").disabled = false;
    if (data.partial && Array.isArray(data.partial_errors) && data.partial_errors.length) {
      showError(`Partial result. Modules with errors: ${data.partial_errors.join(", ")}. Available findings are still shown below.`, true);
    }
  }

  async function checkHealth() {
    try {
      const response = await fetch("/api/health", { headers: { Accept: "application/json" }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok || data.status !== "ok") throw new Error("Health check failed");
      if (!scanInProgress) setStatus("online", "API ONLINE");
    } catch {
      if (!scanInProgress) setStatus("error", "API UNAVAILABLE");
    }
  }

  async function runScan(rawTarget) {
    const target = String(rawTarget || "").trim();
    if (!target || scanBtn.disabled) return;

    clearError();
    scanInProgress = true;
    setStatus("busy", "AUDIT RUNNING");
    scanBtn.disabled = true;
    scanBtn.setAttribute("aria-busy", "true");
    scanBtnText.textContent = "Probing target";
    workbench.classList.add("is-scanning");
    workbench.setAttribute("aria-busy", "true");

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch("/api/recon", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ target, include_ports: Boolean(portsToggle.checked) }),
        signal: controller.signal,
      });
      const data = await response.json().catch(() => null);
      if (!data || typeof data !== "object") throw new Error("The API returned an unreadable response. Please try again.");
      if (!response.ok || data.ok === false) {
        setStatus("error", response.status === 429 ? "RATE LIMITED" : "AUDIT FAILED");
        showError(data.error || `Request failed (${response.status}).`);
        return;
      }

      renderScan(data);
      pushHistory(data);
      setStatus("online", data.partial ? "AUDIT PARTIAL" : "AUDIT COMPLETE");
    } catch (error) {
      const message = error?.name === "AbortError"
        ? "The audit request timed out. Check the target and try again."
        : (error?.message || "Network error contacting the NetRecon API.");
      setStatus("error", "CONNECTION ERROR");
      showError(message);
    } finally {
      window.clearTimeout(timeoutId);
      scanInProgress = false;
      scanBtn.disabled = false;
      scanBtn.removeAttribute("aria-busy");
      scanBtnText.textContent = "Start audit";
      workbench.classList.remove("is-scanning");
      workbench.setAttribute("aria-busy", "false");
    }
  }

  function activateTab(button, moveFocus = false) {
    $$(".tab-btn").forEach((tab) => {
      const selected = tab === button;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      const panel = document.getElementById(`panel-${tab.dataset.tab}`);
      if (panel) {
        panel.classList.toggle("active", selected);
        panel.hidden = !selected;
      }
    });
    if (moveFocus) button.focus();
  }

  $$(".tab-btn").forEach((button) => {
    button.addEventListener("click", () => activateTab(button));
    button.addEventListener("keydown", (event) => {
      const tabs = $$(".tab-btn");
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

  $$(".chip-btn").forEach((button) => {
    button.addEventListener("click", () => {
      targetInput.value = button.dataset.preset || "";
      targetInput.focus();
    });
  });

  recentBar.addEventListener("click", (event) => {
    const chip = event.target.closest(".recent-chip");
    if (!chip) return;
    targetInput.value = chip.dataset.host || chip.textContent || "";
    runScan(targetInput.value);
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runScan(targetInput.value);
  });

  portsToggle.addEventListener("change", () => {
    $("#sideMode").textContent = portsToggle.checked ? "Ports enabled" : "Passive only";
  });

  $("#copyMdBtn").addEventListener("click", async (event) => {
    if (!latestData) return;
    const data = latestData;
    const ports = data.ports?.open_ports?.length
      ? data.ports.open_ports.map((item) => `${item.port ?? item}/${item.service || "service"}`).join(", ")
      : (data.ports?.status || "Not reported");
    const lines = [
      `# NetRecon audit: ${data.target?.host || "target"}`,
      "",
      `- Target IP: ${data.target?.primary_ip || "N/A"}`,
      `- ASN: ${data.geo?.asn || "N/A"} (${data.geo?.org || "N/A"})`,
      `- Location: ${[data.geo?.city, data.geo?.country].filter(Boolean).join(", ") || "N/A"}`,
      `- Web grade: ${data.web?.grade || "N/A"} (${data.web?.score ?? 0}/100)`,
      `- Ports: ${ports}`,
      `- Elapsed: ${data.elapsed_ms ?? "N/A"} ms`,
      `- Partial result: ${data.partial ? "Yes" : "No"}`,
    ];
    const button = event.currentTarget;
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = "Copy report"; }, 1400);
    } catch {
      showError("Clipboard access is unavailable in this browser. Use Export JSON instead.", true);
    }
  });

  $("#exportJsonBtn").addEventListener("click", () => {
    if (!latestData) return;
    const blob = new Blob([JSON.stringify(latestData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const host = String(latestData.target?.host || "scan").replace(/[^a-z0-9.-]+/gi, "-");
    anchor.href = url;
    anchor.download = `netrecon-${host || "scan"}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  });


  renderHistory();
  checkHealth();
})();
