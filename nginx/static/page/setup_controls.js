        const pinChangeState = {
          busy: false,
        };
        function pinModalElements() {
          return {
            modal: document.getElementById('pinModal'),
            title: document.getElementById('pinModalTitle'),
            body: document.querySelector('#pinModal .bd'),
            message: document.getElementById('pinModalMessage'),
            error: document.getElementById('pinModalError'),
            newInput: document.getElementById('pinModalNew'),
            repeatInput: document.getElementById('pinModalRepeat'),
            cancel: document.getElementById('pinModalCancel'),
            ok: document.getElementById('pinModalOk'),
          };
        }
        function _makePinInput(id, placeholder) {
          const input = document.createElement('input');
          input.id = id;
          input.name = 'v';
          input.type = 'text';
          input.className = 'pin-entry';
          input.setAttribute('readonly', 'readonly');
          input.setAttribute('inputmode', 'text');
          input.setAttribute('autocapitalize', 'off');
          input.setAttribute('autocomplete', 'off');
          input.setAttribute('autocorrect', 'off');
          input.setAttribute('spellcheck', 'false');
          input.setAttribute('data-form-type', 'other');
          input.setAttribute('placeholder', placeholder);
          return input;
        }
        function _armPinInput(input) {
          input.value = '';
          input.setAttribute('readonly', 'readonly');
          const enable = () => input.removeAttribute('readonly');
          input.addEventListener('pointerdown', enable, { once: true });
          input.addEventListener('focus', enable, { once: true });
        }
        function ensurePinModalInputs() {
          const els = pinModalElements();
          if (!els.body) return;
          if (!els.newInput) {
            const newInput = _makePinInput('pinModalNew', 'New PIN');
            newInput.addEventListener('keydown', (ev) => {
              if (ev.key === 'Enter') {
                ev.preventDefault();
                const rep = document.getElementById('pinModalRepeat');
                if (rep) rep.focus();
              }
            });
            const err = els.error;
            if (err && err.parentNode === els.body) {
              els.body.insertBefore(newInput, err.nextSibling);
            } else {
              els.body.appendChild(newInput);
            }
          }
          if (!els.repeatInput) {
            const repeatInput = _makePinInput('pinModalRepeat', 'Repeat PIN');
            repeatInput.style.marginTop = '0.5rem';
            repeatInput.addEventListener('keydown', (ev) => {
              if (ev.key === 'Enter') { ev.preventDefault(); handlePinModalOk(); }
            });
            const newInput = document.getElementById('pinModalNew');
            if (newInput) newInput.after(repeatInput);
            else els.body.appendChild(repeatInput);
          }
        }
        function setPinModalBusy(busy) {
          pinChangeState.busy = !!busy;
          const els = pinModalElements();
          if (els.cancel) els.cancel.disabled = !!busy;
          if (els.ok) els.ok.disabled = !!busy;
          if (els.newInput) els.newInput.disabled = !!busy;
          if (els.repeatInput) els.repeatInput.disabled = !!busy;
        }
        function showPinModalError(message) {
          const els = pinModalElements();
          if (!els.error) return;
          if (message) {
            els.error.style.display = '';
            els.error.textContent = message;
          } else {
            els.error.style.display = 'none';
            els.error.textContent = '';
          }
        }
        function closePinModal() {
          const els = pinModalElements();
          if (!els.modal) return;
          els.modal.classList.remove('show');
          if (els.newInput) { els.newInput.value = ''; els.newInput.remove(); }
          if (els.repeatInput) { els.repeatInput.value = ''; els.repeatInput.remove(); }
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          pinChangeState.busy = false;
        }
        function openChangePinModal() {
          pinChangeState.busy = false;
          const els = pinModalElements();
          if (!els.modal) return;
          ensurePinModalInputs();
          const inputs = pinModalElements();
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          if (inputs.newInput) _armPinInput(inputs.newInput);
          if (inputs.repeatInput) _armPinInput(inputs.repeatInput);
          setPinModalBusy(false);
          els.modal.classList.add('show');
        }
        // Parse a fetch Response into a discriminated result object.
        // Does NOT catch a rejected fetch() promise -- network failures propagate.
        // Returns: {ok, transportStatus, body, error}
        async function _parseDialResponse(response) {
          var transportStatus = response.status;
          var ct = response.headers.get('Content-Type') || '';
          if (ct.toLowerCase().indexOf('application/json') === -1) {
            try { await response.text(); } catch(e) {}
            return {ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'};
          }
          var body;
          try { body = await response.json(); } catch(e) {
            return {ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'};
          }
          if (!body || typeof body !== 'object' || Array.isArray(body)) {
            return {ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'};
          }
          if (body.ok === false) {
            return {ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'unknown_error')};
          }
          if (transportStatus < 200 || transportStatus > 299) {
            return {ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'http_error')};
          }
          return {ok: true, transportStatus: transportStatus, body: body, error: null};
        }

        async function submitPinChange(newPin, newPinCheck) {
          const resp = await fetch('/api/pin/change', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': window.__CSRF || ''
            },
            body: JSON.stringify({ new_pin: newPin, new_pin_check: newPinCheck })
          });
          return _parseDialResponse(resp);
        }
        function friendlyPinChangeError(message) {
          const text = String(message || '').trim();
          if (!text) return 'Unable to change PIN.';
          if (text === 'PIN must be 4-20 characters using letters, numbers, or hyphens') return text;
          if (text === 'Values did not match') return 'The two PIN entries did not match.';
          if (text === 'Missing fields') return 'Enter your new PIN twice.';
          return text;
        }
        async function handlePinModalOk() {
          if (pinChangeState.busy) return;
          const els = pinModalElements();
          const newVal = ((els.newInput && els.newInput.value) || '').trim();
          const repeatVal = ((els.repeatInput && els.repeatInput.value) || '').trim();
          if (!newVal) {
            showPinModalError('Enter a new PIN.');
            if (els.newInput) els.newInput.focus();
            return;
          }
          if (!repeatVal) {
            showPinModalError('Repeat the new PIN.');
            if (els.repeatInput) els.repeatInput.focus();
            return;
          }
          if (newVal !== repeatVal) {
            showPinModalError('The two PINs did not match. Please try again.');
            if (els.newInput) { _armPinInput(els.newInput); els.newInput.focus(); }
            if (els.repeatInput) _armPinInput(els.repeatInput);
            return;
          }
          setPinModalBusy(true);
          try {
            const result = await submitPinChange(newVal, repeatVal);
            if (result.ok) {
              if (els.newInput) { els.newInput.value = ''; els.newInput.style.display = 'none'; }
              if (els.repeatInput) { els.repeatInput.value = ''; els.repeatInput.style.display = 'none'; }
              showPinModalError(null);
              els.message.textContent = 'PIN changed successfully. Returning to the home screen\u2026';
              els.ok.style.display = 'none';
              els.cancel.textContent = 'Continue';
              setPinModalBusy(false);
              window.setTimeout(() => { window.location.href = '/'; }, 900);
              return;
            }
            showPinModalError(friendlyPinChangeError(result.error || 'Unable to change PIN.'));
          } catch (e) {
            showPinModalError('Unable to change PIN.');
          } finally {
            setPinModalBusy(false);
          }
        }
        function handlePinModalCancel() {
          closePinModal();
        }
        const hostnameChangeState = {
          busy: false,
        };
        function hostnameModalElements() {
          return {
            modal: document.getElementById('hostnameModal'),
            input: document.getElementById('hostnameModalInput'),
            error: document.getElementById('hostnameModalError'),
            cancel: document.getElementById('hostnameModalCancel'),
            ok: document.getElementById('hostnameModalOk'),
          };
        }
        function currentDisplayedHostname() {
          const el = document.getElementById('systemHostnameValue');
          return ((el && el.textContent) || 'autostream').trim() || 'autostream';
        }
        function setHostnameModalBusy(busy) {
          hostnameChangeState.busy = !!busy;
          const els = hostnameModalElements();
          if (els.cancel) els.cancel.disabled = !!busy;
          if (els.ok) els.ok.disabled = !!busy;
          if (els.input) els.input.disabled = !!busy;
        }
        function showHostnameModalError(message) {
          const els = hostnameModalElements();
          if (!els.error) return;
          if (message) {
            els.error.style.display = '';
            els.error.textContent = message;
          } else {
            els.error.style.display = 'none';
            els.error.textContent = '';
          }
        }
        function openChangeHostnameModal() {
          const els = hostnameModalElements();
          if (!els.modal) return;
          showHostnameModalError(null);
          if (els.input) {
            els.input.value = currentDisplayedHostname();
            els.input.disabled = false;
          }
          setHostnameModalBusy(false);
          els.modal.classList.add('show');
          setTimeout(function() {
            if (els.input) {
              els.input.focus();
              els.input.select();
            }
          }, 50);
        }
        function closeHostnameModal() {
          const els = hostnameModalElements();
          if (els.modal) els.modal.classList.remove('show');
          showHostnameModalError(null);
          setHostnameModalBusy(false);
        }
        function friendlyHostnameChangeError(message) {
          const text = String(message || '').trim();
          if (!text) return 'Unable to change hostname.';
          if (text === 'Invalid hostname') return 'Enter a valid hostname using letters, numbers, and hyphens.';
          return text;
        }
        function handleHostnameModalOk() {
          if (hostnameChangeState.busy) return;
          const els = hostnameModalElements();
          const value = ((els.input && els.input.value) || '').trim();
          if (!value) {
            showHostnameModalError('Enter a hostname.');
            if (els.input) els.input.focus();
            return;
          }
          setHostnameModalBusy(true);
          settingsTransact('/api/settings/hostname', {value: value}, {
            onSuccess: function(data) {
              const display = document.getElementById('systemHostnameValue');
              if (display) display.textContent = value;
              refreshSystemCardSub();
              closeHostnameModal();
            },
            onError: function(data) {
              showHostnameModalError(friendlyHostnameChangeError(data && data.error));
              setHostnameModalBusy(false);
              if (els.input) els.input.focus();
            }
          });
        }
        const liveEnabled = true;
        function onInputEnableToggle(inputIndex, checked){
          syncInputUi(inputIndex);
          if (liveEnabled) settingsSaveField('audio' + inputIndex + '.enabled', checked);
        }
        function syncVol(v){
          document.getElementById('owntone_volume_percent').value=v;
          document.getElementById('vol_val').textContent=v+'%';
          refreshPlaybackCardSub();
          if (liveEnabled) settingsSaveFieldDebounced('owntone.volume_percent', parseInt(v, 10), 300);
        }
        // Take one speaker out of the Auto-Start set. The last one stays:
        // the appliance needs a speaker to start on.
        function removeAutoStart(btn){
          const buttons = Array.from(document.querySelectorAll('#autostart_members .autostart-remove'));
          const kept = buttons.filter(function(b){ return b !== btn; });
          if (!kept.length) return;
          btn.closest('.autostart-row').remove();
          kept.forEach(function(b){ b.disabled = kept.length === 1; });
          document.getElementById('autostart_last').textContent = kept.length === 1 ? ' At least one speaker is needed.' : '';
          refreshPlaybackCardSub();
          if (liveEnabled) settingsSaveField('owntone.default_outputs', kept.map(function(b){
            return {id: b.dataset.id, name: b.dataset.name, volume: parseInt(b.dataset.volume, 10)};
          }));
        }
        function syncInputUi(inputIndex){
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const enabledName = prefix + '_enabled';
          const enabled = !!document.querySelector('input[name="' + enabledName + '"]')?.checked;
          const settings = document.getElementById(prefix + '_settings');
          const preampCard = document.getElementById(prefix + '_preamp_card');
          if (settings) settings.style.display = enabled ? 'block' : 'none';
          if (preampCard) preampCard.style.display = enabled ? 'block' : 'none';
        }
        function inputTypePreset(inputIndex, type){
          const sel = document.getElementById('audio' + inputIndex + '_input_type');
          if (!sel) return NaN;
          let presets = {};
          try { presets = JSON.parse(sel.dataset.presets || '{}'); } catch (e) { presets = {}; }
          return Number(presets[type]);
        }
        function _showSilenceThreshold(inputIndex, value){
          const valueEl = document.getElementById('audio' + inputIndex + '_silence_threshold_val');
          if (valueEl) valueEl.textContent = String(value) + ' dB';
          _applyInputLevelMark(inputIndex);
        }
        function onInputTypeChange(inputIndex, type){
          const sel = document.getElementById('audio' + inputIndex + '_input_type');
          const prev = sel ? sel.dataset.currentType : '';
          const preset = inputTypePreset(inputIndex, type);
          // The server moves the threshold to the new preset only when the
          // preset changes; mirror that so the slider agrees with the file.
          if (Number.isFinite(preset) && preset !== inputTypePreset(inputIndex, prev)) {
            const slider = document.getElementById(inputIndex === 1 ? 'audio_silence_threshold' : 'audio2_silence_threshold');
            if (slider) slider.value = String(preset);
            _showSilenceThreshold(inputIndex, preset);
          }
          if (sel) sel.dataset.currentType = type;
          // A CD input starts on its first sound, so it has no Start after.
          const startAfter = document.getElementById('audio' + inputIndex + '_start_after_wrap');
          if (startAfter) startAfter.hidden = (type === 'cd');
          if (liveEnabled) settingsSaveField('audio' + inputIndex + '.input_type', type);
          refreshInputCardSubs();
        }
        function syncSilenceThreshold(inputIndex, value){
          _showSilenceThreshold(inputIndex, value);
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.silence_threshold', Number(value), 300);
        }
        // Start after: a step stops at the end of the range, so a button is
        // disabled only once the value is there.
        var START_AFTER_MIN_MS = 30;
        var START_AFTER_MAX_MS = 250;
        var START_AFTER_DEFAULT_MS = 60;
        function _startAfterSync(inputIndex, ms){
          const valueEl = document.getElementById('audio' + inputIndex + '_start_after_val');
          if (valueEl) {
            valueEl.dataset.ms = String(ms);
            valueEl.textContent = String(ms);
          }
          const stepper = document.getElementById('audio' + inputIndex + '_start_after_stepper');
          if (!stepper) return;
          stepper.querySelectorAll('button[data-step]').forEach(function(b){
            const step = Number(b.dataset.step);
            b.disabled = step < 0 ? ms <= START_AFTER_MIN_MS : ms >= START_AFTER_MAX_MS;
          });
        }
        function _startAfterSave(inputIndex, ms){
          _startAfterSync(inputIndex, ms);
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.start_after_ms', ms, 300);
        }
        function startAfterStep(inputIndex, step){
          const valueEl = document.getElementById('audio' + inputIndex + '_start_after_val');
          const current = valueEl ? Number(valueEl.dataset.ms) : START_AFTER_DEFAULT_MS;
          const next = Math.max(START_AFTER_MIN_MS, Math.min(START_AFTER_MAX_MS, current + step));
          _startAfterSave(inputIndex, next);
        }
        function startAfterReset(inputIndex){
          _startAfterSave(inputIndex, START_AFTER_DEFAULT_MS);
        }
        function eqPrefix(inputIndex){ return inputIndex===1 ? 'audio1' : 'audio2'; }
        function syncGain(inputIndex, value){
          const prefix = eqPrefix(inputIndex);
          const inputEl = document.getElementById(prefix + '_gain_db');
          const valueEl = document.getElementById(prefix + '_gain_db_val');
          if (inputEl) inputEl.value = value;
          if (valueEl) valueEl.textContent = value + ' dB';
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.gain_db', Number(value), 120);
        }
        function syncEq(inputIndex, band, value){
          const prefix = eqPrefix(inputIndex);
          const valueEl = document.getElementById(prefix + '_eq_' + band + '_db_val');
          if (valueEl) valueEl.textContent = value + ' dB';
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.eq_' + band + '_db', Number(value), 120);
        }
        function silSecondsFromPos(pos){
          // Mirrors _silence_pos_to_seconds() in autostream_webui_page_setup.py --
          // exponential position->seconds curve, snapped to coarser steps as
          // the value grows.
          var minS = 5, maxS = 300;
          pos = Math.max(0, Math.min(100, Number(pos)));
          var s = minS * Math.pow(maxS / minS, pos / 100);
          if (s < 30) s = Math.round(s);
          else if (s < 120) s = Math.round(s / 5) * 5;
          else s = Math.round(s / 10) * 10;
          return Math.max(minS, Math.min(maxS, s));
        }
        function syncSil(v){
          var s = silSecondsFromPos(v);
          document.getElementById('sil_val').textContent=s+'s';
          document.getElementById('silence_seconds').value=s;
          if (liveEnabled) settingsSaveFieldDebounced('general.silence_seconds', s, 500);
        }
        let mdnsGraceTimer = null;
        function syncMdnsGracePeriod(v){
          clearTimeout(mdnsGraceTimer);
          mdnsGraceTimer = setTimeout(function(){
            settingsTransact('/api/settings/mdns-grace-period', {value: parseInt(v, 10)});
          }, 500);
        }
        function syncTiLeadIn(v){
          document.getElementById('ti_lead_in_val').textContent=v+' s';
          document.getElementById('ti_analysis_lead_in_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.analysis_lead_in_seconds', Number(v), 500);
        }
        function syncTiRefresh(v){
          document.getElementById('ti_refresh_val').textContent=Math.round(v/60)+' min';
          document.getElementById('ti_refresh_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.refresh_seconds', Number(v), 500);
        }
        function syncTiSilence(v){
          document.getElementById('ti_silence_val').textContent=parseFloat(v).toFixed(2)+' s';
          document.getElementById('ti_track_change_silence_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.track_change_silence_seconds', Number(v), 500);
        }
        function onTiToggle(checked){
          var body=document.getElementById('ti-controls');
          if(!body)return;
          body.style.opacity=checked?'':'0.4';
          body.style.pointerEvents=checked?'':'none';
          body.querySelectorAll('input[type="range"]').forEach(function(el){el.disabled=!checked;});
          refreshTrackIdCardSub();
        }
        // System card's button/modal wiring: the System panel's body
        // -- including #btnChangePin/#btnChangeHostname -- is fetched
        // lazily on first open rather than present at DOMContentLoaded, so
        // this binding is a named
        // function invoked once by openPanel() the first time the System
        // panel opens (see _setupInitPanel()). The two modals themselves
        // (#pinModal/#hostnameModal) are always in the DOM (global,
        // rendered in _body_prefix), so binding their buttons here -- not
        // at DOMContentLoaded -- is still correct, just later.
        function _initSystemCard() {
          const changePinBtn = document.getElementById('btnChangePin');
          const pinModalCancel = document.getElementById('pinModalCancel');
          const pinModalOk = document.getElementById('pinModalOk');
          const changeHostnameBtn = document.getElementById('btnChangeHostname');
          const hostnameModalCancel = document.getElementById('hostnameModalCancel');
          const hostnameModalOk = document.getElementById('hostnameModalOk');
          const hostnameModalInput = document.getElementById('hostnameModalInput');
          if (changePinBtn) changePinBtn.addEventListener('click', openChangePinModal);
          if (pinModalCancel) pinModalCancel.addEventListener('click', handlePinModalCancel);
          if (pinModalOk) pinModalOk.addEventListener('click', handlePinModalOk);
          if (changeHostnameBtn) changeHostnameBtn.addEventListener('click', openChangeHostnameModal);
          if (hostnameModalCancel) hostnameModalCancel.addEventListener('click', closeHostnameModal);
          if (hostnameModalOk) hostnameModalOk.addEventListener('click', handleHostnameModalOk);
          if (hostnameModalInput) hostnameModalInput.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); handleHostnameModalOk(); }
          });
          _initUpdatesCard();
        }
        // Personalisation card: enforce hostname-dependent state once its
        // #webui_show_hostname_on_home checkbox exists (same lazy-load
        // pattern as _initSystemCard() above).
        function _initCustomiseCard() {
          const cbHost = document.getElementById('webui_show_hostname_on_home');
          if (cbHost) onHostnameToggle(cbHost.checked);
        }
        async function requestReboot(){
          if (liveEnabled) {
            try {
              const saveR = await fetch('/api/settings/save', {method:'POST', headers:{'X-CSRF-Token':window.__CSRF||''}});
              const saveJ = await saveR.json().catch(()=>({ok:false}));
              if (!saveJ.ok) {
                alert('Settings could not be saved before rebooting: ' + (saveJ.error || 'unknown error'));
                return;
              }
            } catch(e) {
              // Network error -- fall through; reboot will reload config from disk
            }
          }
          showRebootModal();
        }
        // Updates card (part of the System panel, lazy-loaded): was an
        // IIFE that ran unconditionally at page load, assuming
        // #updMsg/#btnCheck/#btnInst already existed -- now a named
        // function invoked once by _initSystemCard() the first time the
        // System panel opens.
        function _initUpdatesCard(){
          const msg = (t) => { document.getElementById("updMsg").textContent = t; };
          const bCheck = document.getElementById("btnCheck"), bInst = document.getElementById("btnInst");
          let cand = null;
          // Info mode: a check found an update, so the button now opens the
          // release-notes modal instead of re-checking. Cleared back to the
          // default checking behaviour whenever a check finds no update.
          let infoMode = false;
          let notesHtml = "";
          let notesText = "";
          // Shared reset: also invoked from outside this IIFE (channel
          // toggle) since switching channels invalidates any candidate
          // found under the previous channel.
          function resetUpdateCheckState(){
            infoMode = false;
            notesHtml = ""; notesText = "";
            cand = null;
            bCheck.textContent = "Check";
            bInst.disabled = true;
            msg("");
          }
          window.resetUpdateCheckState = resetUpdateCheckState;
          // On page load, check persisted update status so any recent result is visible.
          async function checkPersistedStatus(){
            try {
              const r = await fetch("/api/update/status"); const j = await r.json();
              if(j.ok && j.status === "in_progress"){
                if(j.stale){
                  if(j.hung){
                    msg("An update is still running but has been unresponsive for 30+ minutes. Power-cycle the device to recover \u2014 do not retry until after rebooting.");
                  } else {
                    msg("A previous update appears to have stalled. Power-cycle the device to trigger automatic recovery, or use Check for Updates to retry.");
                  }
                } else {
                  // An update is already running -- send the user to the progress page.
                  window.location.replace("/offline/updating");
                }
                return;
              }
              if(j.ok && j.status === "success"){ msg("Last update: installed successfully."); }
              else if(j.ok && (j.status === "failure" || j.status === "error")){
                msg("Last update failed: " + (j.message || "unknown error"));
              }
            } catch(e) { /* ignore -- no persisted status yet */ }
          }
          bCheck.onclick = async () => {
            if (infoMode) {
              var infoMsg = notesHtml || notesText || "No release notes provided.";
              showInfoModal("Release Notes", infoMsg, !!notesHtml);
              return;
            }
            msg("Checking..."); bInst.disabled=true;
            try {
              const r = await fetch("/api/update/check"); const j = await r.json();
              if(j.ok && j.update_available){
                cand=j.candidate;
                msg("Update available: " + j.candidate);
                notesHtml = j.release_notes_html || "";
                notesText = j.release_notes || "";
                infoMode = true;
                bCheck.textContent = "Info";
                bInst.disabled=false;
              } else {
                resetUpdateCheckState();
                msg(j.ok?"No updates available.":"Check failed.");
              }
            } catch(e) {
              resetUpdateCheckState();
              msg("Check failed.");
            }
          };
          bInst.onclick = async () => {
            if(!cand) return;
            msg("Saving settings..."); bCheck.disabled=true; bInst.disabled=true;
            try {
              const saveR = await fetch("/api/settings/save",{method:"POST",headers:{"X-CSRF-Token":window.__CSRF||""}});
              const saveJ = await saveR.json().catch(()=>({ok:false}));
              if(!saveJ.ok){
                msg("Could not save settings before update: " + (saveJ.error || "unknown error"));
                bCheck.disabled=false; bInst.disabled=false;
                return;
              }
            } catch(e) {
              msg("Could not save settings before update");
              bCheck.disabled=false; bInst.disabled=false;
              return;
            }
            msg("Starting update...");
            try {
              const r = await fetch("/api/update/apply",{method:"POST",headers:{"X-CSRF-Token":window.__CSRF||""}});
              const j = await r.json().catch(()=>({ok:false}));
              if(j.accepted){
                window.location.replace("/offline/updating");
              } else {
                msg("Failed to start update: " + (j.error || "unknown error"));
                bCheck.disabled=false;
              }
            } catch(e) {
              // Network error: service may have already started the update.
              window.location.replace("/offline/updating");
            }
          };
          checkPersistedStatus();
        }
