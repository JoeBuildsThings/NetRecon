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
  const globeCanvas = $("#geoGlobe");

  const HISTORY_KEY = "netrecon_recent_v4";
  const MAX_HISTORY = 6;
  const DEFAULT_SAMPLES = ["1.1.1.1", "cloudflare.com", "github.com"];

  let latestData = null;
  let scanInProgress = false;
  let globeInstance = null;

  const { setText, makeEl } = window.NetReconRender;

  function setStatus(state, detail) {
    if (!runState) return;
    runState.dataset.state = state;
    const labels = { idle: "Standby", scanning: "Scanning", completed: "Locked", error: "Fault" };
    const codes = { idle: "NR / 00", scanning: "NR / 01", completed: "NR / 02", error: "NR / ERR" };
    setText($("#statusLabel"), labels[state] || "Standby");
    setText($("#statusDetail"), detail || "Ready for target input");
    setText($("#statusCode"), codes[state] || "NR / 00");
  }

  function setApiStatus(online) {
    const indicator = $("#apiIndicator");
    if (!indicator) return;
    indicator.dataset.state = online ? "online" : "offline";
    setText($("#apiStatus"), online ? "ENGINE ONLINE" : "ENGINE OFFLINE");
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

  function loadHistory() {
    try {
      const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(value)
        ? value.filter((item) => typeof item === "string" && item.trim()).slice(0, MAX_HISTORY)
        : [];
    } catch (_error) {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
    } catch (_error) {
      // Optional storage
    }
  }

  function renderHistory() {
    recentTargets.replaceChildren();
    const history = loadHistory();
    const list = history.length ? history : DEFAULT_SAMPLES;
    recentTargets.appendChild(makeEl("span", "recent-label", history.length ? "RECENT" : "QUICK PROBE"));
    list.forEach((host) => {
      const button = makeEl("button", "recent-chip", host);
      button.type = "button";
      button.dataset.host = host;
      recentTargets.appendChild(button);
    });
  }

  function saveTarget(host) {
    if (!host) return;
    const next = [host].concat(loadHistory().filter((item) => item !== host));
    saveHistory(next);
    renderHistory();
  }

  function renderScan(data) {
    latestData = data;
    const target = data.target || {};
    window.NetReconRender.renderSummary(data);
    window.NetReconRender.renderRisks(data);
    window.NetReconRender.renderOverview(data);
    window.NetReconRender.renderWeb(data.web);
    window.NetReconRender.renderDns(data.dns);
    window.NetReconRender.renderPorts(data.ports);
    window.NetReconRender.renderGlobeTelemetry(data.geo || {}, data.scanned_at, globeInstance);

    setText($("#rawBox"), JSON.stringify(data, null, 2));
    $("#copyReportBtn").disabled = false;
    $("#exportJsonBtn").disabled = false;
    saveTarget(target.host || target.input || input.value.trim());

    if (data.partial && Array.isArray(data.partial_errors) && data.partial_errors.length) {
      showError(
        "Scan completed with partial results. Unavailable modules: " + data.partial_errors.join(", ") + ".",
        true
      );
    }
  }

  async function initHealth() {
    try {
      await window.NetReconApi.checkHealth();
      setApiStatus(true);
    } catch (_error) {
      setApiStatus(false);
    }
  }

  async function runScan(value) {
    const target = String(value || "").trim();
    if (scanInProgress) return;

    if (!target) {
      setStatus("error", "Enter a public domain, URL, or IP address.");
      showError("A public domain, URL, or IP address is required.");
      input.focus();
      return;
    }

    if (target.length > 255 || /[\u0000-\u001f\u007f]/.test(target)) {
      setStatus("error", "Target input is invalid.");
      showError("Use a valid domain, HTTP/HTTPS URL, or public IP address.");
      input.focus();
      return;
    }

    clearError();
    scanInProgress = true;
    setStatus("scanning", "Resolving DNS, TLS, headers, and geolocation");
    scanButton.disabled = true;
    scanButton.setAttribute("aria-busy", "true");
    scanButtonText.textContent = "Scanning";
    workbench.setAttribute("aria-busy", "true");

    try {
      const data = await window.NetReconApi.runRecon(target);
      renderScan(data);
      setStatus("completed", data.partial ? "Locked with partial module data" : "Telemetry locked");
    } catch (error) {
      const msg = error && error.message ? error.message : "Unable to contact NetRecon engine.";
      setStatus("error", error && error.status === 429 ? "Rate limit reached" : "Scan failed");
      showError(msg);
    } finally {
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
    runScan(input.value);
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runScan(input.value);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && document.activeElement !== input && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const tag = document.activeElement && document.activeElement.tagName;
      if (tag !== "INPUT" && tag !== "TEXTAREA") {
        event.preventDefault();
        input.focus();
        input.select();
      }
    }
  });

  $("#copyReportBtn").addEventListener("click", async (event) => {
    if (!latestData) return;
    const summary = window.NetReconRender.buildSummaryText(latestData);
    try {
      await navigator.clipboard.writeText(summary);
      const button = event.currentTarget;
      button.textContent = "Copied brief";
      window.setTimeout(() => { button.textContent = "Copy brief"; }, 1500);
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

  if (globeCanvas && window.NetReconGlobe) {
    globeInstance = window.NetReconGlobe.createGlobe(globeCanvas);
    const pauseBtn = $("#globePauseBtn");
    const zoomInBtn = $("#globeZoomInBtn");
    const zoomOutBtn = $("#globeZoomOutBtn");
    const resetBtn = $("#globeResetBtn");

    if (pauseBtn) {
      pauseBtn.textContent = globeInstance.isPaused() ? "Resume" : "Pause";
      pauseBtn.setAttribute("aria-pressed", String(globeInstance.isPaused()));
      pauseBtn.addEventListener("click", () => {
        const paused = globeInstance.togglePause();
        pauseBtn.textContent = paused ? "Resume" : "Pause";
        pauseBtn.setAttribute("aria-pressed", String(paused));
      });
    }
    if (zoomInBtn) zoomInBtn.addEventListener("click", () => globeInstance.zoomIn());
    if (zoomOutBtn) zoomOutBtn.addEventListener("click", () => globeInstance.zoomOut());
    if (resetBtn) resetBtn.addEventListener("click", () => globeInstance.resetView());
  }

  renderHistory();
  initHealth();
})();
