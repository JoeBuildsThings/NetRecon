(() => {
  "use strict";

  const REQUEST_TIMEOUT_MS = 25000;

  async function checkHealth() {
    const response = await fetch("/api/health", {
      headers: { Accept: "application/json" },
      cache: "no-store"
    });
    const data = await response.json().catch(() => null);
    if (!response.ok || !data || data.status !== "ok") {
      throw new Error("API health check failed");
    }
    return data;
  }

  async function runRecon(target) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch("/api/recon", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({ target }),
        signal: controller.signal
      });
      const data = await response.json().catch(() => null);
      if (!data || typeof data !== "object") {
        throw new Error("The API returned an unreadable response. Try again.");
      }
      if (!response.ok || data.ok === false) {
        const err = new Error(data.error || "Request failed with status " + response.status + ".");
        err.status = response.status;
        throw err;
      }
      return data;
    } catch (error) {
      if (error && error.name === "AbortError") {
        const timeoutErr = new Error("The scan timed out before the server responded. Check the target and retry.");
        timeoutErr.status = 408;
        throw timeoutErr;
      }
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  window.NetReconApi = { checkHealth, runRecon };
})();
