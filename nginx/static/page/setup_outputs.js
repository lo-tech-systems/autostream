        async function refreshOwntoneOutputs() {
          const sel = document.getElementById("owntone_output_select");
          const hint = document.getElementById("owntone_output_hint");
          if (!sel) return;

          // If the user is interacting with the dropdown, don't change it under them.
          if (document.activeElement === sel) return;

          let j = null;
          try {
            const r = await fetch("/api/owntone/outputs", { cache: "no-store" });
            j = await r.json();
          } catch (e) {
            return;
          }
          if (!j || !j.ok) return;

          const outputs = Array.isArray(j.outputs) ? j.outputs : [];
          if (hint) hint.style.display = outputs.length ? "none" : "block";

          // If still empty, keep whatever is currently shown (don't wipe it).
          if (!outputs.length) return;

          const current = sel.value;
          const existing = Array.from(sel.options).map(o => o.value);

          // If the list hasn't changed, do nothing.
          const same =
            existing.length === outputs.length &&
            existing.every((v, i) => v === outputs[i]);
          if (same) return;

          // Rebuild options
          sel.innerHTML = "";
          for (const name of outputs) {
            const opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            sel.appendChild(opt);
          }

          // Preserve user's current selection if possible
          if (outputs.includes(current)) {
            sel.value = current;
          } else if (j.selected && outputs.includes(j.selected)) {
            sel.value = j.selected;
          } else {
            sel.selectedIndex = 0;
          }
          refreshPlaybackCardSub();
        }

        window.addEventListener("DOMContentLoaded", () => {
          // Run once immediately, then every 2 seconds
          refreshOwntoneOutputs();
          setInterval(refreshOwntoneOutputs, 2000);
        });
