document.addEventListener("DOMContentLoaded", () => {
  const banner = document.getElementById("green-banner");
  if (!banner) return;

  const spacer = document.getElementById("green-banner-spacer");

  window.setTimeout(() => {
    // Measure actual rendered height (includes iOS safe-area padding).
    const h = Math.ceil(banner.getBoundingClientRect().height);

    // Tell CSS how far to translate.
    banner.style.setProperty("--flash-rollup-y", h + "px");

    // Trigger animations
    banner.classList.add("flash-rollup");
    if (spacer) spacer.classList.add("flash-spacer-hidden");

    // After animation completes, remove from layout completely.
    window.setTimeout(() => {
      banner.style.display = "none";
      if (spacer) spacer.style.display = "none";
    }, 400);
  }, 5000);
});
