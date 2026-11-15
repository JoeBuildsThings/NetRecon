(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const form = $("#reconForm");
  const targetInput = $("#targetInput");
  const scanBtn = $("#scanBtn");
  const scanBtnText = $("#scanBtnText");
  const portsToggle = $("#activePortsToggle");
  const errorBox = $("#errorBox");
  const recentBar = $("#recentBar");
  const statusPill = $("#statusPill");
  const statusText = $("#statusText");
  let latestData = null;
  const HISTORY_KEY = "netrecon_recent_v21";
  const MAX_HISTORY = 8;

  function setStatus(state, text) {
    statusPill.classList.remove("is-busy", "is-error");
    if (state === "busy") statusPill.classList.add("is-busy");
    if (state === "error") statusPill.classList.add("is-error");
    statusText.textContent = text;
  }
  function showError(msg, warn = false) {
    errorBox.textContent = msg;
    errorBox.classList.add("is-visible");
    errorBox.classList.toggle("is-warn", !!warn);
  }
  function clearError() {
    errorBox.classList.remove("is-visible", "is-warn");
    errorBox.textContent = "";
  }
  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  }
  function saveHistory(list) {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_HISTORY)));
  }
  function pushHistory(data) {
    const host = data?.target?.host || data?.target?.input;
    if (!host) return;
    const prev = loadHistory().filter((h) => h !== host);
    prev.unshift(host);
    saveHistory(prev);
    renderHistory();
  }
  function renderHistory() {
    recentBar.innerHTML = loadHistory()
      .map((h) => `<button type="button" class="recent-chip" data-host="${escAttr(h)}">${esc(h)}</button>`)
      .join("");
  }
  function esc(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  function escAttr(s) { return esc(s).replace(/'/g,"&#39;"); }
  function gradeColor(grade) {
    if (!grade || grade === "N/A") return "var(--ink-muted)";
    const g = String(grade).toUpperCase();
    if (g.startsWith("A")) return "var(--green)";
    if (g.startsWith("B")) return "var(--accent)";
    if (g.startsWith("C")) return "var(--amber)";
    return "var(--red)";
  }

  function renderMetrics(data) {
    const t = data.target || {}, geo = data.geo || {}, web = data.web || {}, ports = data.ports || {};
    $("#metricIp").textContent = t.primary_ip || "—";
    $("#metricHost").textContent = t.host || (t.is_ip ? "Direct IP" : "—");
    const loc = [geo.city, geo.country].filter(Boolean).join(", ") || "Unknown";
    $("#metricGeo").textContent = geo.asn || "—";
    $("#metricOrg").textContent = `${loc} · ${geo.org || "—"}`;
    const grade = web.grade || "N/A";
    $("#metricGrade").textContent = grade;
    $("#metricGrade").style.color = gradeColor(grade);
    const tls = web.tls || {};
    $("#metricTls").textContent = tls.available ? (tls.verified ? "TLS verified" : "TLS present") : "TLS unavailable";
    const status = ports.status || "unknown";
    if (status === "verification_required") {
      $("#metricPorts").textContent = "Verify TXT";
      $("#metricLatency").textContent = "Ownership gated";
    } else if (status === "skipped") {
      $("#metricPorts").textContent = "Skipped";
      $("#metricLatency").textContent = "Passive mode";
    } else if (status === "timeout") {
      $("#metricPorts").textContent = "Timeout";
      $("#metricLatency").textContent = ports.reason || "Module timeout";
    } else {
      const open = ports.open_count ?? (ports.open_ports || []).length;
      $("#metricPorts").textContent = `${open} open`;
      $("#metricLatency").textContent = ports.scan_ms != null ? `${ports.scan_ms} ms · ${ports.scanned_count || 0} probed` : "—";
    }
    $("#sideElapsed").textContent = data.elapsed_ms != null ? `${data.elapsed_ms} ms` : "—";
    $("#sidePartial").textContent = data.partial && data.partial_errors?.length ? data.partial_errors.join(", ") : (data.partial ? "yes" : "no");
    const own = data.ownership || {};
    $("#sideOwn").textContent = own.verified ? "verified" : (own.verified === false ? "unverified" : "—");
    $("#sideMode").textContent = portsToggle.checked ? "Active ports on" : "Passive only";
  }

  function renderWeb(web) {
    const empty = $("#webEmpty"), box = $("#webBox");
    if (!web) { empty.hidden = false; box.hidden = true; return; }
    empty.hidden = true; box.hidden = false;
    const score = web.score ?? 0, grade = web.grade || "N/A";
    $("#scoreGrade").textContent = grade;
    $("#scoreGrade").style.color = gradeColor(grade);
    $("#scoreFill").style.width = `${Math.min(100, Math.max(0, score))}%`;
    $("#scoreLabel").textContent = `${score}/100`;
    const tls = web.tls || {};
    const tlsItems = [
      ["Reachable", web.reachable ? "yes" : "no"],
      ["TLS available", tls.available ? "yes" : "no"],
      ["TLS verified", tls.verified ? "yes" : "no"],
      ["Verify error", tls.verify_error || "—"],
    ];
    $("#tlsGrid").innerHTML = tlsItems.map(([k,v]) =>
      `<div class="kv-card"><div class="k">${esc(k)}</div><div class="v">${esc(String(v))}</div></div>`).join("");
    const headers = Array.isArray(web.headers) ? web.headers : [];
    $("#headerList").innerHTML = headers.length
      ? headers.map((h) => {
          const name = h.name || h.header || "—";
          const val = h.value || h.status || JSON.stringify(h);
          return `<li><span class="name">${esc(name)}</span><span class="val">${esc(String(val))}</span></li>`;
        }).join("")
      : `<li><span class="name">No header findings</span><span class="val">—</span></li>`;
  }

  function renderDns(dns) {
    const empty = $("#dnsEmpty"), box = $("#dnsBox");
    if (!dns) { empty.hidden = false; box.hidden = true; return; }
    empty.hidden = true; box.hidden = false;
    const posture = dns.posture || {};
    const summary = [
      ["DNS provider", posture.dns_provider || "—"],
      ["Mail provider", posture.mail_provider || "—"],
      ["SPF", posture.spf_status || (posture.spf_configured ? "configured" : "missing")],
      ["DMARC", posture.dmarc_status || posture.dmarc_policy || "—"],
    ];
    $("#dnsSummary").innerHTML = summary.map(([k,v]) =>
      `<div class="kv-card"><div class="k">${esc(k)}</div><div class="v">${esc(String(v))}</div></div>`).join("");
    const records = dns.records || {};
    const keys = Object.keys(records);
    let html = "";
    if ((dns.ptr || []).length) {
      html += `<div class="kv-card" style="margin-bottom:10px"><div class="k">PTR</div><div class="v">${esc((dns.ptr||[]).join(", "))}</div></div>`;
    }
    for (const key of keys) {
      const list = Array.isArray(records[key]) ? records[key] : [records[key]];
      html += `<div style="margin-bottom:12px"><div class="micro-label" style="margin-bottom:6px">${esc(key)}</div><ul class="header-list">`;
      for (const v of list) {
        html += `<li><span class="name">${esc(key)}</span><span class="val">${esc(typeof v === "object" ? JSON.stringify(v) : String(v))}</span></li>`;
      }
      html += `</ul></div>`;
    }
    $("#dnsRecords").innerHTML = html || `<p class="empty-state" style="padding:12px 0">No DNS records returned.</p>`;
  }

  function renderPorts(ports, ownership) {
    const banner = $("#ownBanner"), empty = $("#portsEmpty"), box = $("#portsBox");
    const status = ports?.status || "";
    if (status === "verification_required") {
      banner.classList.add("is-visible");
      $("#ownReason").textContent = ports.reason || ownership?.reason || "Domain ownership verification required before active port probing.";
      const host = ports.txt_host || ownership?.txt_host || "";
      const val = ports.txt_value || ownership?.txt_value || "";
      $("#ownTxt").textContent = host && val ? `${host}  TXT  "${val}"` : (val || host || "See ownership challenge API");
      empty.hidden = true; box.hidden = true; return;
    }
    banner.classList.remove("is-visible");
    if (!ports || status === "skipped") {
      empty.hidden = false;
      empty.textContent = status === "skipped" ? "Port probing skipped (passive mode or ownership not verified)." : "Port results appear when a scan completes.";
      box.hidden = true; return;
    }
    if (status === "timeout") {
      empty.hidden = false; empty.textContent = ports.reason || "Port scan timed out."; box.hidden = true; return;
    }
    const open = ports.open_ports || [];
    if (!open.length) {
      empty.hidden = false; empty.textContent = "No open ports reported in the common set."; box.hidden = true; return;
    }
    empty.hidden = true; box.hidden = false;
    $("#portsBody").innerHTML = open.map((p) => {
      const port = p.port ?? p, svc = p.service || "—", lat = p.latency_ms != null ? `${p.latency_ms} ms` : "—";
      return `<tr><td>${esc(String(port))}</td><td>${esc(String(svc))}</td><td>${esc(lat)}</td><td><span class="badge badge-green">open</span></td></tr>`;
    }).join("");
  }

  function renderScan(data) {
    latestData = data;
    renderMetrics(data);
    renderWeb(data.web);
    renderDns(data.dns);
    renderPorts(data.ports, data.ownership);
    $("#rawBox").textContent = JSON.stringify(data, null, 2);
    if (data.partial && data.partial_errors?.length) {
      showError(`Partial result — timed out modules: ${data.partial_errors.join(", ")}`, true);
    }
  }

  async function runScan(rawTarget) {
    const target = (rawTarget || "").trim();
    if (!target) return;
    clearError();
    setStatus("busy", "Scanning…");
    scanBtn.disabled = true;
    scanBtnText.textContent = "Scanning…";
    try {
      const res = await fetch("/api/recon", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, include_ports: !!portsToggle.checked }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) {
        setStatus("error", "Failed");
        showError(data.error || `Request failed (${res.status})`);
        return;
      }
      renderScan(data);
      pushHistory(data);
      setStatus("ok", `${data.elapsed_ms ?? "—"} ms`);
    } catch {
      setStatus("error", "Network error");
      showError("Network error contacting /api/recon");
    } finally {
      scanBtn.disabled = false;
      scanBtnText.textContent = "Run Audit";
    }
  }

  $$(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab-btn").forEach((b) => { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
      $$(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const panel = document.getElementById(`panel-${btn.dataset.tab}`);
      if (panel) panel.classList.add("active");
    });
  });
  $$(".chip-btn").forEach((btn) => {
    btn.addEventListener("click", () => { targetInput.value = btn.dataset.preset || ""; targetInput.focus(); });
  });
  recentBar.addEventListener("click", (e) => {
    const chip = e.target.closest(".recent-chip");
    if (!chip) return;
    targetInput.value = chip.dataset.host || chip.textContent;
    runScan(targetInput.value);
  });
  form.addEventListener("submit", (e) => { e.preventDefault(); runScan(targetInput.value); });
  portsToggle.addEventListener("change", () => {
    $("#sideMode").textContent = portsToggle.checked ? "Active ports on" : "Passive only";
  });
  $("#copyMdBtn").addEventListener("click", async () => {
    if (!latestData) return;
    const d = latestData;
    const ports = d.ports?.open_ports?.length
      ? d.ports.open_ports.map((p) => `${p.port}/${p.service || "svc"}`).join(", ")
      : (d.ports?.status || "none");
    const md = [
      `### NetRecon — ${d.target?.host || "target"}`,
      `- **IP:** \`${d.target?.primary_ip || "—"}\`,
      `- **ASN:** \`${d.geo?.asn || "—"}\` (${d.geo?.org || "—"})`,
      `- **Geo:** ${d.geo?.city || "—"}, ${d.geo?.country || "—"}`,
      `- **Ports:** ${ports}`,
      `- **Grade:** \`${d.web?.grade || "N/A"}\` (${d.web?.score ?? 0}/100)`,
      `- **Elapsed:** ${d.elapsed_ms ?? "—"} ms`,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(md);
      const btn = $("#copyMdBtn");
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy Markdown"; }, 1200);
    } catch {}
  });
  $("#exportJsonBtn").addEventListener("click", () => {
    if (!latestData) return;
    const blob = new Blob([JSON.stringify(latestData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `netrecon-${latestData.target?.host || "scan"}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  });
  renderHistory();
  setStatus("ok", "Engine ready");
})();
