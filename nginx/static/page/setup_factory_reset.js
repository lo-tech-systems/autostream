        function showFactoryResetModal() {
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.add('show');
        }
        function hideFactoryResetModal() {
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.remove('show');
        }
        function showRebootModal() {
          const m = document.getElementById('rebootModal');
          if (m) m.classList.add('show');
        }
        function hideRebootModal() {
          const m = document.getElementById('rebootModal');
          if (m) m.classList.remove('show');
        }
        async function confirmReboot() {
          hideRebootModal();
          try {
            fetch("/api/reboot", {
              method: "POST",
              headers: {"X-CSRF-Token": window.__CSRF || ""},
              cache: "no-store",
              keepalive: true
            });
          } catch (e) {}
          window.location.replace("/offline/rebooting");
        }
        async function doFactoryReset() {
          const cont = document.getElementById('factoryResetContinue');
          const canc = document.getElementById('factoryResetCancel');
          const errEl = document.getElementById('factoryResetModalError');
          if (cont) cont.disabled = true;
          if (canc) canc.disabled = true;
          try {
            const r = await fetch('/api/factory-reset', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': window.__CSRF || ''
              },
              body: 'csrf_token=' + encodeURIComponent(window.__CSRF || ''),
              keepalive: true
            });
            let ok = false;
            try { const j = await r.json(); ok = !!(j && j.ok); } catch (e) {}
            if (ok) {
              window.location.replace('/offline/resetting');
            } else {
              if (errEl) { errEl.textContent = 'Reset could not be scheduled. Please try again.'; errEl.style.display = ''; }
              if (cont) cont.disabled = false;
              if (canc) canc.disabled = false;
            }
          } catch (e) {
            // Network error: the service may have already started resetting.
            window.location.replace('/offline/resetting');
          }
        }
