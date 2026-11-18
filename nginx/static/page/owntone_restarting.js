var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
const nextPath = pageData.next_path;
async function poll() {
  try {
    const r = await fetch("/api/owntone/ready", { cache: "no-store" });
    const j = await r.json();
    const msg = (j.restart && j.restart.message) ? j.restart.message : "";
    const probe = j.probe ? j.probe : "";
    document.getElementById("status").textContent =
      (j.ok ? "Ready. Redirecting\u2026" : ("Not ready yet. " + (msg || probe || "")));
    if (j.ok) {
      window.location.replace(nextPath);
      return;
    }
  } catch (e) {
    document.getElementById("status").textContent = "Not ready yet. (" + e + ")";
  }
  setTimeout(poll, 800);
}
poll();
