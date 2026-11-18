var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
        function _inputCardSub(captureSelName, typeSelName, gainId) {
          var sel = document.querySelector('select[name="' + captureSelName + '"]');
          var opt = sel ? sel.options[sel.selectedIndex] : null;
          var dev = (opt && opt.dataset.card) ? opt.dataset.card : (sel && sel.value ? sel.value : 'Not configured');
          var typeSel = document.querySelector('select[name="' + typeSelName + '"]');
          var typeOpt = typeSel ? typeSel.options[typeSel.selectedIndex] : null;
          var mode = typeOpt ? typeOpt.text : 'Line';
          if (opt && opt.dataset.bt === '1') {
            // Bluetooth input: show the connected device name (or connection
            // state) instead of the ALSA card name and input type. The
            // string itself comes verbatim from the status poll's server-
            // computed ui.bt_input_text -- never re-derived from link/paired
            // here, so it can't drift from the card summary's own state.
            dev = 'Bluetooth';
            mode = window._btUiText || 'Not Connected';
          }
          var gainEl = document.getElementById(gainId);
          var gain = gainEl ? parseInt(gainEl.value, 10) : 0;
          var gainStr = gain > 0 ? '+' + gain + ' dB' : (gain < 0 ? gain + ' dB' : '0 dB');
          return dev + ' \u00b7 ' + mode + ' \u00b7 ' + gainStr;
        }
        function refreshInputCardSubs() {
          var s1 = document.getElementById('input1-card-sub');
          if (s1 && _setupPanelIsLoaded('input1')) {
            var en1 = document.querySelector('input[name="audio1_enabled"]');
            if (en1 && !en1.checked) {
              s1.textContent = 'Not configured';
            } else {
              s1.textContent = _inputCardSub('audio_capture_device', 'audio1_input_type', 'audio1_gain_db');
            }
          }
          var s2 = document.getElementById('input2-card-sub');
          if (s2 && _setupPanelIsLoaded('input2')) {
            var en = document.querySelector('input[name="audio2_enabled"]');
            if (en && !en.checked) {
              s2.textContent = 'Disabled';
            } else {
              s2.textContent = _inputCardSub('audio2_capture_device', 'audio2_input_type', 'audio2_gain_db');
            }
          }
        }
        // Lazy per-card detail fetch: a panel's body starts empty
        // (an id="panel-body-<key>" placeholder -- see _setup_panel_shell_html())
        // and is fetched from GET /api/setup/card/<key> the first time its
        // panel opens, then cached in the DOM (never re-fetched on later
        // opens in the same page load).
        var _setupPanelLoaded = {};
        // Every card summary below (refreshInputCardSubs, refreshPlaybackCardSub,
        // ...) is DERIVED from that card's detail-panel controls -- which now
        // only exist once the panel has been lazily fetched. Refreshing a card
        // whose panel was never opened would read every control as absent and
        // overwrite its correct server-rendered summary with the all-defaults
        // text ('Off', 'No speaker selected . 0%', 'Not configured', ...), so
        // each refresher gates on this. Callers are the Back button
        // (refreshSetupCardSubs) and the Bluetooth status poll, both of which
        // can fire while other panels are still unfetched.
        function _setupPanelIsLoaded(id) {
          return !!_setupPanelLoaded[id];
        }
        async function _setupFetchPanelBody(id) {
          var bodyEl = document.getElementById('panel-body-' + id);
          if (!bodyEl) return;
          try {
            var res = await fetch('/api/setup/card/' + encodeURIComponent(id), {
              cache: 'no-store',
              headers: {'X-CSRF-Token': window.__CSRF || ''}
            });
            var body = await res.json();
            if (body && body.ok && typeof body.html === 'string') {
              bodyEl.innerHTML = body.html;
            } else {
              bodyEl.innerHTML = '<p style="color:var(--color-status-danger);">Could not load this section. Please reload the page.</p>';
            }
          } catch (e) {
            bodyEl.innerHTML = '<p style="color:var(--color-status-danger);">Could not load this section. Please reload the page.</p>';
          }
        }
        // One-time, post-injection wiring for panels whose fields the
        // page-load scripts used to bind at DOMContentLoaded -- now
        // deferred to first open since the elements don't exist in the DOM
        // until the lazy fetch above has injected them.
        function _setupInitPanel(id) {
          if (id === 'input1') { syncInputUi(1); refreshExclusivityOptions(); }
          if (id === 'input2') { syncInputUi(2); refreshExclusivityOptions(); }
          if (id === 'system' && typeof _initSystemCard === 'function') _initSystemCard();
          if (id === 'customise' && typeof _initCustomiseCard === 'function') _initCustomiseCard();
          if (id === 'dials' && typeof _initDialsCard === 'function') _initDialsCard();
        }
        async function openPanel(id) {
          document.querySelectorAll('.setup-detail-panel').forEach(function(p) { p.classList.remove('active'); });
          var panel = document.getElementById('panel-' + id);
          if (panel) panel.classList.add('active');
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.add('panel-open');
          window.scrollTo(0, 0);
          if (!_setupPanelLoaded[id]) {
            _setupPanelLoaded[id] = true;
            await _setupFetchPanelBody(id);
            _setupInitPanel(id);
          }
          if (id === 'system') refreshNetworkAdapterInfo();
          if (id === 'playback') refreshRepeatSetupNote();
          // The Bluetooth/System ambient status polls only run while
          // their own panel is open (activeOnly Pollers -- see
          // _bt_card_js/refreshNetworkAdapterInfo's Poller construction).
          if (id === 'bluetooth' && typeof _btStatusPoller !== 'undefined') _btStatusPoller.start();
          if ((id === 'input1' || id === 'input2') && typeof _inputLevelPoller !== 'undefined') _inputLevelPoller.start();
          if (id === 'system' && typeof _networkAdapterInfoPoller !== 'undefined') _networkAdapterInfoPoller.start();
        }
        // Deep links from the Home page's warning cards (dial update, sample rate).
        window.addEventListener('DOMContentLoaded', function() {
          if (location.hash === '#dials') openPanel('dials');
          if (location.hash === '#input1') openPanel('input1');
          if (location.hash === '#input2') openPanel('input2');
        });
        function _repeatCodecLabel(codec) {
          if (!codec) return '';
          var m = /^mp2_(\d+)$/.exec(String(codec));
          if (m) return m[1] + 'Kbps MP2';
          if (codec === 'pcm' || codec === 'pcm_s16') return '16-bit PCM';
          return String(codec);
        }
        async function refreshRepeatSetupNote(expectedRequestedMins) {
          var noteEl = document.getElementById('repeat-max-time-note');
          var unavailEl = document.getElementById('repeat-unavailable-note');
          var populated = false;
          try {
            var r = await fetch('/api/v1/state?parts=repeat', { cache: 'no-store' });
            var d = await r.json();
            var repeat = (d && d.parts && d.parts.repeat && d.parts.repeat.block) || null;
            if (!repeat) return false;  // absent on old monitor binaries -- feature unsupported
            // Freshness gate for the just-changed-a-setting poll: the status
            // cache lags the change by a second or two, so the first
            // snapshot after a target change is usually the OLD arena's
            // figure -- accepting it would freeze the note on stale text
            // (and once the rebuild starts, capacity reads 0 until the new
            // arena finalizes). Only accept a snapshot whose
            // requested_minutes matches what was just set; monitor builds
            // too old to report requested_minutes can't signal freshness at
            // all, so they are accepted as-is rather than rejected forever.
            if (expectedRequestedMins !== undefined
                && repeat.requested_minutes !== undefined
                && Number(repeat.requested_minutes) !== expectedRequestedMins)
              return false;
            var maxSecs = Number(repeat.max_recording_seconds);
            if (noteEl && Number.isFinite(maxSecs) && maxSecs > 0) {
              // effective_codec: the tier the estimate assumes (monitor
              // status, e.g. "mp2_256" or "pcm"); absent/empty on older
              // monitor builds -> omit the parenthetical.
              var codecLabel = _repeatCodecLabel(repeat.effective_codec);
              var deliveredMins = Math.round(maxSecs / 60);
              // requested_minutes (honesty surface): what was asked for,
              // vs. deliveredMins, what the arena actually fit. Below the
              // codec ladder's floor, duration degrades instead of quality
              // -- when that has visibly happened (whole-minute
              // comparison), say so plainly rather than reporting the
              // smaller figure as if it were the ask, and name the ACTUAL
              // bitrate the arena records at (the ladder picked it; the
              // user configured a duration, not a quality). Older monitor
              // builds omit requested_minutes entirely, so this falls back
              // to the single-figure wording.
              var requestedMins = Number(repeat.requested_minutes);
              if (Number.isFinite(requestedMins) && requestedMins > 0 && deliveredMins < requestedMins) {
                noteEl.textContent = requestedMins + ' minutes requested; ' + deliveredMins
                                     + ' minutes' + (codecLabel ? ' at ' + codecLabel : '')
                                     + ' fit in memory';
              } else {
                noteEl.textContent = 'Buffer: ' + deliveredMins + ' mins'
                                     + (codecLabel ? ' (' + codecLabel + ')' : '');
              }
              populated = true;
            }
            var reason = repeat.recording && repeat.recording.unavailable_reason;
            if (unavailEl) {
              if (reason) {
                unavailEl.textContent = 'Repeat unavailable: insufficient free memory';
                unavailEl.style.display = '';
              } else {
                unavailEl.style.display = 'none';
                unavailEl.textContent = '';
              }
            }
          } catch (e) { return false; }
          return populated;
        }
        var _repeatToggleToken = 0;
        // After a target/enable change the daemon tears the arena down and
        // rebuilds it (typically well under a second), but the status cache
        // backing the state refreshes on its own ~1-2s poll -- so the note
        // switches to "Calculating..." immediately and polls until a FRESH
        // figure (requested_minutes matching the new target, capacity
        // recomputed) is back, rather than either freezing on the stale
        // pre-change text or flashing the old figure as if it were the
        // answer. If nothing fresh arrives within the window (e.g. an old
        // monitor build that never reports requested_minutes alongside a
        // rejected match), a final unconditional refresh shows whatever the
        // daemon does report instead of leaving "Calculating..." stuck.
        function pollRepeatNote(expectedRequestedMins) {
          var myToken = ++_repeatToggleToken;
          var attempts = 0;
          var maxAttempts = 12;
          var noteEl = document.getElementById('repeat-max-time-note');
          if (noteEl) noteEl.textContent = 'Calculating\u2026';
          (function poll() {
            if (myToken !== _repeatToggleToken) return;  // superseded by a later change
            attempts++;
            refreshRepeatSetupNote(expectedRequestedMins).then(function(ok) {
              if (ok || myToken !== _repeatToggleToken) return;
              if (attempts >= maxAttempts) {
                refreshRepeatSetupNote();  // last resort: accept any figure
                return;
              }
              setTimeout(poll, 700);
            });
          })();
        }
        function onRepeatEnabledToggle(checked) {
          settingsSaveField('repeat.enabled', checked);
          var targetSelect = document.getElementById('repeat_target_minutes');
          var targetRow = document.getElementById('repeat-target-row');
          if (targetSelect) targetSelect.disabled = !checked;
          if (targetRow) targetRow.style.opacity = checked ? '' : '0.4';
          if (!checked) {
            _repeatToggleToken++;  // cancel any in-flight poll
            var noteEl = document.getElementById('repeat-max-time-note');
            var unavailEl = document.getElementById('repeat-unavailable-note');
            if (noteEl) noteEl.textContent = '';
            if (unavailEl) {
              unavailEl.textContent = '';
              unavailEl.style.display = 'none';
            }
            return;
          }
          var targetVal = targetSelect ? parseInt(targetSelect.value, 10) : undefined;
          pollRepeatNote(Number.isFinite(targetVal) ? targetVal : undefined);
        }
        function onRepeatTargetChange(value) {
          var target = parseInt(value, 10);
          settingsSaveField('repeat.target_minutes', target);
          pollRepeatNote(Number.isFinite(target) ? target : undefined);
        }
        function onHostnameToggle(checked) {
          var cb = document.getElementById('webui_control_other_appliances');
          var row = document.getElementById('ctrl-other-row');
          if (cb) {
            if (!checked) {
              cb.checked = false;
              cb.disabled = true;
            } else {
              cb.disabled = false;
            }
          }
          if (row) { row.style.opacity = checked ? '' : '0.4'; }
          refreshCustomiseCardSub();
        }
        function refreshCustomiseCardSub() {
          var sub = document.getElementById('customise-card-sub');
          if (!sub || !_setupPanelIsLoaded('customise')) return;
          var cb = document.getElementById('webui_show_master_volume');
          var cbDet = document.getElementById('webui_show_input_detail');
          var cbDark = document.getElementById('webui_dark_mode');
          var cbHost = document.getElementById('webui_show_hostname_on_home');
          var cbCtrl = document.getElementById('webui_control_other_appliances');
          var cbAdv = document.getElementById('webui_advertise_appliance');
          var mv = (cb && cb.checked) ? 'Master volume: On' : 'Master volume: Off';
          var det = (cbDet && cbDet.checked) ? 'Input detail: On' : 'Input detail: Off';
          var dark = (cbDark && cbDark.checked) ? 'Dark mode: On' : 'Dark mode: Off';
          var host = (cbHost && cbHost.checked) ? 'Hostname: On' : 'Hostname: Off';
          var ctrl = (cbCtrl && cbCtrl.checked) ? 'Control others: On' : 'Control others: Off';
          var adv = (cbAdv && cbAdv.checked) ? 'Peer control: On' : 'Peer control: Off';
          sub.textContent = mv + ' \u00b7 ' + det + ' \u00b7 ' + dark + ' \u00b7 ' + host + ' \u00b7 ' + ctrl + ' \u00b7 ' + adv;
        }
        function refreshPlaybackCardSub() {
          var sub = document.getElementById('playback-card-sub');
          if (!sub || !_setupPanelIsLoaded('playback')) return;
          var names = Array.from(document.querySelectorAll('#autostart_members .autostart-remove'))
            .map(function(b){ return b.dataset.name; });
          var speaker = names.length ? names.join(', ') : 'No speaker selected';
          var volEl = document.getElementById('owntone_volume_percent');
          var vol = volEl ? volEl.value : '0';
          sub.textContent = speaker + ' \u00b7 ' + vol + '%';
        }
        function refreshTrackIdCardSub() {
          var sub = document.getElementById('track-id-card-sub');
          if (!sub || !_setupPanelIsLoaded('track-id')) return;
          var cb = document.getElementById('track_identification_enabled');
          sub.textContent = (cb && cb.checked) ? 'On' : 'Off';
        }
        function applyDarkMode(enabled) {
          document.documentElement.setAttribute('data-theme', enabled ? 'dark' : 'light');
        }
        function refreshSystemCardSub() {
          var sub = document.getElementById('system-card-sub');
          if (!sub || !_setupPanelIsLoaded('system')) return;
          var hn = document.getElementById('systemHostnameValue');
          var hostname = hn ? (hn.textContent.trim() || 'autostream') : 'autostream';
          var cbAu = document.getElementById('updates_auto_update');
          var cbPre = document.getElementById('updates_prerelease_channel');
          var auState = (cbAu && cbAu.checked) ? 'Auto-update: On' : 'Auto-update: Off';
          if (cbPre && cbPre.checked) auState += ' - Pre-release channel';
          sub.textContent = hostname + ' \u00b7 v' + pageData.app_version + ' \u00b7 ' + auState;
        }
        function refreshSetupCardSubs() {
          refreshInputCardSubs();
          refreshPlaybackCardSub();
          refreshTrackIdCardSub();
          refreshCustomiseCardSub();
          refreshSystemCardSub();
          refreshDialsCardSub();
        }
        function closePanel() {
          refreshSetupCardSubs();
          // Pause the activeOnly ambient-status Pollers when their
          // panel closes (mirrors openPanel()'s .start() calls above).
          var activePanel = document.querySelector('.setup-detail-panel.active');
          var activeId = activePanel ? activePanel.id.replace(/^panel-/, '') : null;
          if (activeId === 'bluetooth' && typeof _btStatusPoller !== 'undefined') _btStatusPoller.stop();
          if ((activeId === 'input1' || activeId === 'input2') && typeof _inputLevelPoller !== 'undefined') _inputLevelPoller.stop();
          if (activeId === 'system' && typeof _networkAdapterInfoPoller !== 'undefined') _networkAdapterInfoPoller.stop();
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.remove('panel-open');
          window.scrollTo(0, 0);
        }
