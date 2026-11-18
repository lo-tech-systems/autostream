(function () {
  function setupA2HS() {
    // Detect iOS
    var ua = window.navigator.userAgent || "";
    var isIOS = /iphone|ipad|ipod/i.test(ua);

    // Detect if already running as a Home Screen app / standalone
    var isInStandalone =
      (window.navigator.standalone === true) ||
      (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);

    // Debug log
    try {
      console.log("A2HS check:", {
        ua: ua,
        isIOS: isIOS,
        isInStandalone: isInStandalone
      });
    } catch (e) {}

    // If not iOS, or already installed as an "app", don't show
    if (!isIOS || isInStandalone) {
      return;
    }

    // --- Once-per-day logic ---
    var now = Date.now();
    var lastShown = 0;
    try {
      lastShown = parseInt(localStorage.getItem("a2hs-last-shown") || "0", 10);
    } catch (e) {}

    var ONE_DAY = 24 * 60 * 60 * 1000;

    if (lastShown && (now - lastShown) < ONE_DAY) {
      return; // Already shown within 24 hours
    }

    var prompt = document.getElementById("a2hs-prompt");
    var closeBtn = document.getElementById("a2hs-close");

    if (!prompt || !closeBtn) {
      return;
    }

    prompt.style.display = "block";

    try {
      localStorage.setItem("a2hs-last-shown", String(now));
    } catch (e) {}

    closeBtn.addEventListener("click", function () {
      prompt.style.display = "none";
    });
  }

  // Run after DOM is ready so #a2hs-prompt exists even if script is in <head>
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupA2HS);
  } else {
    setupA2HS();
  }
})();
