var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
const minWaitMs = pageData.min_wait_ms;
const startedAt = Date.now();
const statusEl = document.getElementById("status");

function setStatus(t) {
  if (statusEl) statusEl.textContent = t;
}

async function requestReboot() {
  try {
    const r = await fetch("/api/reboot", {
      method: "POST",
      headers: { "X-CSRF-Token": window.__CSRF || "" },
      cache: "no-store",
      keepalive: true
    });
    try {
      const j = await r.json();
      if (j && j.ok) {
        setStatus("Reboot scheduled. Waiting for restart\u2026");
        return;
      }
    } catch (e) {}
    setStatus("Reboot requested. Waiting for restart\u2026");
  } catch (e) {
    setStatus("Waiting for restart\u2026");
  }
}

async function pollRoot() {
  const elapsed = Date.now() - startedAt;
  if (elapsed < minWaitMs) {
    const s = Math.ceil((minWaitMs - elapsed) / 1000);
    setStatus("Reboot scheduled. Restarting in ~" + s + "s\u2026");
    setTimeout(pollRoot, 700);
    return;
  }

  setStatus("Checking if the app is back\u2026");
  try {
    const r = await fetch("/", { cache: "no-store" });
    if (r && r.ok) {
      window.location.replace("/");
      return;
    }
  } catch (e) {
    // Not up yet
  }
  setTimeout(pollRoot, 1200);
}

requestReboot();
pollRoot();
