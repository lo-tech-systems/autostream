  function showInfoModal(title, message, isHtml){
    return new Promise((resolve) => {
      const m = document.getElementById('infoModal');
      const titleEl = document.getElementById('infoModalTitle');
      const msgEl = document.getElementById('infoModalMessage');
      const btnOk = document.getElementById('infoModalOk');
      if (!m || !titleEl || !msgEl || !btnOk) {
        // Fallback to native alert if our modal is missing for any reason.
        // HTML messages are not safe/meaningful in a plain alert, so only
        // the title is shown in that case.
        window.alert(isHtml ? title : (title + ': ' + message));
        resolve();
        return;
      }
      titleEl.textContent = title;
      if (isHtml) { msgEl.innerHTML = message; } else { msgEl.textContent = message; }
      m.classList.add('show');

      const cleanup = () => {
        m.classList.remove('show');
        btnOk.onclick = null;
        document.removeEventListener('keydown', onKey);
        resolve();
      };
      const onKey = (ev) => {
        if (ev.key === 'Escape') { ev.preventDefault(); cleanup(); }
      };
      btnOk.onclick = () => cleanup();
      document.addEventListener('keydown', onKey);
    });
  }
