var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
        // -- Dial management ------------------------------------------------
        var _dialPinRecoveryTimer = null;
        var _dialPinRecoverySeenActive = false;
        var _dialPinModalCard = null;
        var _dialPinModalMode = null; // 'change' | 'unlock'
        var _dialPinRecoveryModalCard = null;
        var _dialPinRecoveryStep = null; // 'confirm' | 'wait' | 'set'
        var _dialNameModalCard = null;
        var _dialUnlockedPins = new WeakMap(); // card -> '' (no PIN) | 'XXXX' (PIN stored) | absent (locked)
        var _ICON_PADLOCK_LOCKED = pageData.icons.padlock_locked;
        var _ICON_PADLOCK_UNLOCKED = pageData.icons.padlock_unlocked;

        function _dialSetRecoveryBadge(card, active) {
          // Keeps the server-rendered "Recovery Active" badge honest for a
          // card while its PIN-recovery modal is open: the modal already
          // polls /api/dial/pin_recovery/status/<uuid> every 2s, so this
          // reuses that response instead of opening a new polling loop.
          var group = card.querySelector('.dial-badge');
          if (!group || !group.parentElement) return;
          var wrap = group.parentElement;
          var badge = wrap.querySelector('.dial-badge-recovery');
          if (active) {
            if (!badge) {
              badge = document.createElement('span');
              badge.className = 'dial-badge dial-badge-recovery';
              badge.textContent = 'Recovery Active';
              wrap.appendChild(badge);
            }
          } else if (badge) {
            badge.remove();
          }
        }

        // Single source of truth for the tri-state (+ Configuring) status
        // badge, so setDialAuthorized() and the restart-in-progress flow
        // can't drift by hardcoding the class/text mapping twice.
        function _dialSetStatusBadge(card, state) {
          var badge = card.querySelector('.dial-badge');
          if (!badge) return;
          var map = {
            online: ['dial-badge-online', 'Online'],
            offline: ['dial-badge-offline', 'Offline'],
            new: ['dial-badge-new', 'New'],
            configuring: ['dial-badge-configuring', 'Configuring'],
          };
          var entry = map[state] || map.offline;
          badge.className = 'dial-badge ' + entry[0];
          badge.textContent = entry[1];
        }

        function setDialAuthorized(card, authorized) {
          card.dataset.authorized = authorized ? 'true' : 'false';
          if (authorized) { delete card.dataset.new; } else { card.dataset.new = 'true'; }
          var allow = card.querySelector('.dial-allow');
          if (allow) allow.checked = authorized;
          var config = card.querySelector('.dial-config');
          if (config) config.style.display = authorized ? '' : 'none';
          var online = card.dataset.online === 'true';
          _dialSetStatusBadge(card, authorized ? (online ? 'online' : 'offline') : 'new');
          if (authorized) {
            var titleEl = card.querySelector('.dial-card-title');
            var nameInput = card.querySelector('.dial-name');
            if (nameInput && nameInput.value.trim()) {
              if (titleEl) titleEl.textContent = nameInput.value.trim();
              var nameDisplayEl = card.querySelector('.dial-current-name');
              if (nameDisplayEl) nameDisplayEl.textContent = nameInput.value.trim();
            }
          }
        }
        function syncDialStep(input) {
          var card = input.closest('.dial-card');
          if (!card) return;
          var valEl = card.querySelector('.dial-step-val');
          if (valEl) valEl.textContent = input.value + '% per click';
        }

        function dialSyncScreenControlsEnabled(card) {
          var fittedEl = card.querySelector('.dial-screen-fitted');
          var rotateEl = card.querySelector('.dial-screen-rotate');
          var bgrEl = card.querySelector('.dial-screen-bgr');
          var typeEl = card.querySelector('.dial-screen-type');
          var sizeEl = card.querySelector('.dial-screen-size');
          var layoutEl = card.querySelector('.dial-screen-layout');
          var touchEl = card.querySelector('.dial-screen-touch');
          if (!fittedEl || !rotateEl) return;
          var off = fittedEl.disabled || !fittedEl.checked;
          rotateEl.disabled = off;
          var brightEl = card.querySelector('.dial-screen-brightness');
          var sleepEl = card.querySelector('.dial-screen-sleep');
          if (brightEl) brightEl.disabled = off;
          if (sleepEl) sleepEl.disabled = off;
          // The panel power setting only applies to an HD dial's HDMI panel.
          var panelOffEl = card.querySelector('.dial-screen-panel-off');
          var panelOffRow = card.querySelector('.dial-screen-panel-off-row');
          var panelOffOff = off || card.dataset.surface !== 'kiosk';
          if (panelOffEl) panelOffEl.disabled = panelOffOff;
          if (panelOffRow) panelOffRow.classList.toggle('is-disabled', panelOffOff);
          if (bgrEl) bgrEl.disabled = off;
          if (typeEl) typeEl.disabled = off;
          if (sizeEl) sizeEl.disabled = off;
          if (layoutEl) layoutEl.disabled = off;
          if (touchEl) touchEl.disabled = off;
          // Dim the rows too -- a disabled input still renders its label text
          // at full contrast, which reads as available when it is not.
          card.querySelectorAll('.dial-screen-ctl-row').forEach(function(row) {
            row.classList.toggle('is-disabled', off);
          });
          // "Always show controls" additionally requires a real touch
          // controller -- a persistent overlay with dead minus/plus buttons
          // on a screen-only dial is misleading. The dial itself does not
          // check touch at runtime; this is purely a UI courtesy.
          var ctlEl = card.querySelector('.dial-screen-always-controls');
          var ctlRow = card.querySelector('.dial-screen-controls-row');
          var noTouch = !touchEl || touchEl.value === '' || touchEl.value === 'none';
          if (ctlEl) ctlEl.disabled = off || noTouch;
          if (ctlRow) ctlRow.classList.toggle('is-disabled', off || noTouch);
          // Volume/mute scope: without a screen the dial cannot pick an
          // appliance, so both actions reach every playing appliance. Show
          // that (forced to All Appliances, disabled) while the screen is
          // off; the dial enforces the same rule itself, and the stored
          // choice (dataset.stored) is kept for when the screen comes back.
          ['dial-volume-scope', 'dial-mute-scope'].forEach(function(cls) {
            var el = card.querySelector('.' + cls);
            if (!el) return;
            el.disabled = off;
            el.value = off ? 'all' : (el.dataset.stored || 'current');
          });
        }

        // Freezes every control on one card for an in-flight operation
        // (the dial restarting itself to apply a new touch controller).
        //
        // Queried generically rather than from a hand-listed set of
        // selectors: an enumeration silently misses whatever is added to
        // the card later, and each miss looks like a control that stayed
        // live over a device that is not listening.
        //
        // Un-busy RESTORES each control's prior disabled state rather than
        // enabling everything. Several controls are legitimately disabled
        // before the operation starts -- the whole settings section is
        // disabled while it is locked, and the screen sub-controls follow
        // "Has Screen Fitted" -- so blanket enabling would silently unlock
        // a locked card.
        function dialSetCardBusy(card, busy) {
          card.querySelectorAll('input, select, button, textarea').forEach(function(el) {
            if (busy) {
              if (el.dataset.busyPrevDisabled === undefined) {
                el.dataset.busyPrevDisabled = el.disabled ? '1' : '0';
              }
              el.disabled = true;
            } else if (el.dataset.busyPrevDisabled !== undefined) {
              el.disabled = (el.dataset.busyPrevDisabled === '1');
              delete el.dataset.busyPrevDisabled;
            }
            // Switch-style toggles render from a hidden checkbox, so
            // disabling the input alone leaves the switch and its label
            // looking fully available. Dim the row that holds them, the
            // same treatment the screen control rows already get.
            var toggle = el.closest ? el.closest('label.output-toggle') : null;
            var row = toggle ? toggle.parentElement : null;
            if (row) row.classList.toggle('is-disabled', busy);
          });
          card.querySelectorAll('.dial-screen-ctl-row').forEach(function(row) {
            row.classList.toggle('is-disabled', busy);
          });
          if (!busy) {
            dialSyncScreenControlsEnabled(card);
          }
        }

        function _dialLockSection(card) {
          _dialUnlockedPins.delete(card);
          var section = card.querySelector('.dial-locked-section');
          if (!section) return;
          section.classList.add('dial-section-locked');
          var btn = section.querySelector('.dial-lock-btn');
          if (btn) { btn.innerHTML = _ICON_PADLOCK_LOCKED; btn.setAttribute('aria-label', 'Unlock settings'); }
          section.querySelectorAll('input, select').forEach(function(el) { el.disabled = true; });
          dialSyncScreenControlsEnabled(card);
        }

        function _dialUnlockSection(card, pin) {
          _dialUnlockedPins.set(card, pin);
          var section = card.querySelector('.dial-locked-section');
          if (!section) return;
          section.classList.remove('dial-section-locked');
          var btn = section.querySelector('.dial-lock-btn');
          if (btn) {
            if (card.dataset.pinSet === 'true') {
              btn.innerHTML = _ICON_PADLOCK_UNLOCKED;
              btn.setAttribute('aria-label', 'Lock settings');
              btn.style.display = '';
            } else {
              btn.style.display = 'none';
            }
          }
          section.querySelectorAll('input, select').forEach(function(el) { el.disabled = false; });
          dialSyncScreenControlsEnabled(card);
        }

        function _updateDialLockVisibility(card) {
          if (card.dataset.pinSet !== 'true') {
            _dialUnlockSection(card, '');
          } else if (!_dialUnlockedPins.has(card)) {
            _dialLockSection(card);
          }
          var hasPin = card.dataset.pinSet === 'true';
          var canConfirm = card.dataset.canConfirm !== 'false'; // default true when unknown
          var pinBtn = card.querySelector('[data-dial-action="change-pin"]');
          var recoverBtn = card.querySelector('[data-dial-action="recover-pin"]');
          var noConfirmMsg = card.querySelector('.dial-pin-no-confirm-msg');
          if (pinBtn) pinBtn.textContent = hasPin ? 'Change Dial PIN' : 'Set Dial PIN';
          // A dial that can never confirm presence can never complete recovery,
          // so it must not be offered a lock it has no key for: block setting a
          // PIN in the first place. If a PIN was already set before this became
          // true (an already-impossible situation), don't strand the user by
          // hiding everything -- keep the reset button visible and explain.
          if (!canConfirm && !hasPin) {
            if (pinBtn) pinBtn.style.display = 'none';
            if (recoverBtn) recoverBtn.style.display = 'none';
          } else {
            if (pinBtn) pinBtn.style.display = '';
            if (recoverBtn) {
              recoverBtn.style.display = '';
              recoverBtn.disabled = !hasPin;
            }
          }
          if (noConfirmMsg) noConfirmMsg.style.display = canConfirm ? 'none' : '';
        }

        function refreshDialsCardSub() {
          var sub = document.getElementById('dials-card-sub');
          if (!sub || !_setupPanelIsLoaded('dials')) return;
          var all = document.querySelectorAll('.dial-card');
          var nAuth = 0, nOnline = 0, nNew = 0, nUpdate = 0;
          all.forEach(function(c) {
            if (c.dataset.needsUpdate === 'true') nUpdate++;
            if (c.dataset.authorized === 'true') {
              nAuth++;
              if (c.dataset.online === 'true') nOnline++;
            } else { nNew++; }
          });
          var text;
          if (nAuth === 0 && nNew === 0) { text = 'No dials'; }
          else if (nAuth === 0) { text = nNew + ' new'; }
          else if (nNew > 0) { text = nAuth + ' authorized \u00b7 ' + nNew + ' new'; }
          else { text = nAuth + ' authorized' + (nOnline ? ' \u00b7 ' + nOnline + ' online' : ''); }
          if (nUpdate > 0) text += ' \u00b7 ' + nUpdate + ' need update';
          sub.textContent = text;
        }

        function dialUUID(card) {
          return card ? (card.dataset.dialUuid || '') : '';
        }

        function dialMsg(card, msg, ok) {
          var el = card ? card.querySelector('.dial-card-msg') : null;
          if (!el) return;
          el.textContent = msg;
          el.style.color = ok ? 'var(--color-status-success)' : 'var(--color-status-danger)';
          el.style.display = msg ? '' : 'none';
        }

        function _dialErrorMessage(error) {
          var map = {
            'dial_offline': 'Dial is offline',
            'dial_unreachable': 'Dial could not be reached',
            'dial_bad_response': 'Dial returned an invalid response',
            'dial_unavailable': 'Dial is temporarily unavailable',
            'dial_timeout': 'Dial did not respond in time',
            'invalid_response': 'Appliance returned an unexpected response',
            'wrong_pin': 'Incorrect PIN',
            'too_many_attempts': 'Too many attempts; try again later',
            'screen_apply_failed': 'Screen settings could not be applied',
            'no_frame': 'The dial is not showing anything right now',
            'probe_running': 'The dial is already checking its card',
            'tool_missing': 'The SD card health tool is not installed on the dial',
            'invalid_method': 'Unknown probe method',
          };
          return map[String(error || '')] || String(error || 'Unknown error');
        }

        async function _dialFetch(path, opts) {
          var headers = Object.assign({'X-CSRF-Token': window.__CSRF || ''}, (opts.headers || {}));
          var r = await fetch(path, Object.assign({}, opts, {headers: headers}));
          return _parseDialResponse(r);
        }

        async function _dialPost(path, body) {
          return _dialFetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
          });
        }

        async function _dialGet(path) {
          return _dialFetch(path, {cache: 'no-store'});
        }

        // Polls checkFn at intervalMs until it resolves truthy (done) or
        // deadlineMs elapses, then calls onTimeout. Returns a cancel()
        // function. Guards against a checkFn() promise resolving after the
        // poll was stopped/superseded -- the same generation-token shape as
        // pollRepeatNote(), scoped per call so unrelated dial cards polling
        // concurrently can't cancel each other.
        function dialPollUntil(intervalMs, deadlineMs, checkFn, onTimeout) {
          var token = {};
          var active = token;
          var deadlineAt = Date.now() + deadlineMs;
          var timerId = setInterval(function() {
            if (active !== token) { clearInterval(timerId); return; }
            if (Date.now() >= deadlineAt) {
              clearInterval(timerId);
              active = null;
              onTimeout();
              return;
            }
            Promise.resolve(checkFn()).then(function(done) {
              if (active !== token) return;  // cancelled/superseded while awaiting
              if (done) { clearInterval(timerId); active = null; }
            }).catch(function() {
              // Keep polling to the deadline. A check that throws is the
              // normal case while the target is restarting; swallowing it
              // here keeps that from surfacing as an unhandled rejection
              // and from ending the poll early.
            });
          }, intervalMs);
          return function cancel() {
            active = null;
            clearInterval(timerId);
          };
        }

        // -- Dial self-restart after a touch-controller change --------------
        // The dial persists the new touch_type and THEN restarts, so
        // screen.touch_type (built from persisted config) reports the new
        // value instantly from the old, not-yet-restarted process -- polling
        // it would report success immediately and verify nothing.
        // runtime.touch_type is the one field that reflects what is
        // actually running, so that -- and only that -- is what gets polled.
        var _dialTouchPollCancel = new WeakMap(); // card -> cancel() of an in-flight restart poll

        function _dialCancelTouchRestartPoll(card) {
          var cancel = _dialTouchPollCancel.get(card);
          if (cancel) {
            cancel();
            _dialTouchPollCancel.delete(card);
          }
        }

        // Single-OK result modal, reusing the dial PIN modals' markup and
        // classes. A restart outcome arrives up to a minute after the
        // change, by which time an inline one-liner under the buttons is
        // easily missed -- especially the failures, which matter most.
        function _dialShowResultModal(title, message) {
          var modal = document.getElementById('dialResultModal');
          if (!modal) return;
          var titleEl = document.getElementById('dialResultModalTitle');
          var msgEl = document.getElementById('dialResultModalMsg');
          if (titleEl) titleEl.textContent = title;
          if (msgEl) msgEl.textContent = message;
          modal.classList.add('show');
        }

        // Cancel/Continue confirmation for switching the panel off, in the
        // same modal markup as the other dial dialogs. *onContinue* or
        // *onCancel* runs once, whichever button (or Escape) closes it.
        var _dialPanelOffChoice = null;
        function dialConfirmPanelOff(onContinue, onCancel) {
          var modal = document.getElementById('dialPanelOffModal');
          if (!modal) { onCancel(); return; }
          _dialPanelOffChoice = {ok: onContinue, cancel: onCancel};
          modal.classList.add('show');
        }

        function _dialClosePanelOff(confirmed) {
          var modal = document.getElementById('dialPanelOffModal');
          if (modal) modal.classList.remove('show');
          var choice = _dialPanelOffChoice;
          _dialPanelOffChoice = null;
          if (choice) (confirmed ? choice.ok : choice.cancel)();
        }

        function _dialCloseResultModal() {
          var modal = document.getElementById('dialResultModal');
          if (modal) modal.classList.remove('show');
        }

        // One-shot "Show dial screen" modal: fetches the current panel
        // image through the appliance's binary proxy and shows it, or a
        // message when there is nothing to show. Refresh re-runs the same
        // fetch; the object URL behind the <img> is revoked on every state
        // change and on close so repeated use cannot leak blobs.
        var _dialScreenModalUuid = '';
        var _dialScreenObjectUrl = null;

        function _dialScreenSetState(msg, imgUrl) {
          var msgEl = document.getElementById('dialScreenModalMsg');
          var imgEl = document.getElementById('dialScreenModalImg');
          if (msgEl) { msgEl.textContent = msg || ''; msgEl.style.display = msg ? '' : 'none'; }
          if (imgEl) {
            if (_dialScreenObjectUrl) { URL.revokeObjectURL(_dialScreenObjectUrl); _dialScreenObjectUrl = null; }
            if (imgUrl) { _dialScreenObjectUrl = imgUrl; imgEl.src = imgUrl; imgEl.style.display = ''; }
            else { imgEl.removeAttribute('src'); imgEl.style.display = 'none'; }
          }
        }

        async function _dialScreenFetch() {
          if (!_dialScreenModalUuid) return;
          _dialScreenSetState('Loading\u2026', null);
          try {
            var r = await fetch('/api/dial/screen/image/' + encodeURIComponent(_dialScreenModalUuid),
                                {cache: 'no-store', headers: {'X-CSRF-Token': window.__CSRF || ''}});
            var ct = (r.headers.get('Content-Type') || '').toLowerCase();
            if (r.ok && ct.indexOf('image/png') === 0) {
              var blob = await r.blob();
              _dialScreenSetState('', URL.createObjectURL(blob));
              return;
            }
            var parsed = await _parseDialResponse(r);
            _dialScreenSetState(_dialErrorMessage(parsed.error), null);
          } catch (e) {
            _dialScreenSetState('Network error', null);
          }
        }

        function dialShowScreen(card) {
          _dialScreenModalUuid = dialUUID(card);
          var modal = document.getElementById('dialScreenModal');
          if (!modal || !_dialScreenModalUuid) return;
          modal.classList.add('show');
          _dialScreenFetch();
        }

        function _dialCloseScreenModal() {
          var modal = document.getElementById('dialScreenModal');
          if (modal) modal.classList.remove('show');
          _dialScreenSetState('', null);
          _dialScreenModalUuid = '';
        }

        function _dialFinishTouchRestartPoll(card, badgeState, message, ok) {
          _dialTouchPollCancel.delete(card);
          dialSetCardBusy(card, false);
          _dialSetStatusBadge(card, badgeState);
          _dialShowResultModal(_DIAL_CFG_TITLE, message);
        }

        // Outcome text for the result modal. Which message applies depends
        // on BOTH the outcome and whether touch was being switched on or
        // off -- "disabled" is a success, not a lesser one, and a panel
        // that will not open is a wiring/type problem the user can act on.
        var _DIAL_CFG_TITLE = 'Dial Configuration';
        var _DIAL_CFG_OK_ENABLED  = 'Touch panel configured successfully.';
        var _DIAL_CFG_OK_DISABLED = 'Touch panel disabled.';
        var _DIAL_CFG_CANNOT_OPEN = 'Touch panel could not be opened. Please check touch panel type and wiring.';
        var _DIAL_CFG_GENERIC_ERR = 'An error was encountered applying the configuration.';

        function dialBeginTouchRestartPoll(card, requestedTouchType) {
          // A second save on the same card must supersede, not race, a poll
          // already in flight for that card.
          _dialCancelTouchRestartPoll(card);
          var uuid = dialUUID(card);
          dialSetCardBusy(card, true);
          _dialSetStatusBadge(card, 'configuring');
          // A restart clears the dial's in-memory recovery window, so a
          // stale "Recovery Active" badge left showing would be a lie.
          _dialSetRecoveryBadge(card, false);
          var cancel = dialPollUntil(1000, 60000, async function() {
            var pollResult = await _dialGet('/api/dial/screen/settings/' + encodeURIComponent(uuid));
            // The dial is unreachable for most of this window; the proxy
            // reports that as ok:false (dial_unreachable/dial_offline).
            // Expected -- keep polling silently, it is not an error.
            if (!pollResult.ok) return false;
            var runtime = pollResult.body && pollResult.body.runtime;
            var runtimeTouchType = runtime ? runtime.touch_type : null;
            if (runtimeTouchType === 'failed') {
              // The dial came back and reported its touch stack failed to
              // open -- a real outcome, not a timeout. Stop waiting now.
              _dialFinishTouchRestartPoll(card, 'online',
                requestedTouchType === 'none' ? _DIAL_CFG_GENERIC_ERR : _DIAL_CFG_CANNOT_OPEN,
                false);
              return true;
            }
            if (runtimeTouchType === requestedTouchType) {
              _dialFinishTouchRestartPoll(card, 'online',
                requestedTouchType === 'none' ? _DIAL_CFG_OK_DISABLED : _DIAL_CFG_OK_ENABLED,
                true);
              return true;
            }
            return false;
          }, function onTimeout() {
            _dialFinishTouchRestartPoll(card, 'offline', _DIAL_CFG_GENERIC_ERR, false);
          });
          _dialTouchPollCancel.set(card, cancel);
        }

        async function dialToggleAllow(card, checked) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (checked) {
            var nameEl = card.querySelector('.dial-name');
            var name = ((nameEl ? nameEl.value : '') || uuid.slice(0, 8)).trim();
            try {
              var result = await _dialPost('/api/dial/authorize', {uuid: uuid, name: name});
              if (result.ok) {
                setDialAuthorized(card, true);
                dialLoadConfig(card);
                dialLoadScreenSettings(card);
                refreshDialsCardSub();
                dialMsg(card, 'Authorized', true);
                setTimeout(function() { dialMsg(card, '', true); }, 2000);
              } else {
                dialMsg(card, _dialErrorMessage(result.error), false);
                var cb = card.querySelector('.dial-allow');
                if (cb) cb.checked = false;
              }
            } catch(e) {
              dialMsg(card, 'Network error', false);
              var cb2 = card.querySelector('.dial-allow');
              if (cb2) cb2.checked = false;
            }
          } else {
            if (confirm('Remove authorization for this dial?')) {
              await dialRevoke(card);
            } else {
              var cb3 = card.querySelector('.dial-allow');
              if (cb3) cb3.checked = true;
            }
          }
        }

        async function dialRevoke(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {
            var result = await _dialPost('/api/dial/revoke', {uuid: uuid});
            if (result.ok) {
              setDialAuthorized(card, false);
              refreshDialsCardSub();
              dialMsg(card, 'Revoked', true);
              setTimeout(function() { dialMsg(card, '', true); }, 2000);
            } else {
              dialMsg(card, _dialErrorMessage(result.error), false);
              var cb = card.querySelector('.dial-allow');
              if (cb) cb.checked = true;
            }
          } catch(e) {
            dialMsg(card, 'Network error', false);
            var cb = card.querySelector('.dial-allow');
            if (cb) cb.checked = true;
          }
        }

        async function dialSaveConfig(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          var nameEl = card.querySelector('.dial-name');
          var stepEl = card.querySelector('.dial-step');
          var autoEl = card.querySelector('.dial-autoupdate');
          var chanEl = card.querySelector('.dial-channel');
          var muteAllEl = card.querySelector('.dial-mute-all');
          var body = {uuid: uuid};
          if (nameEl) body.name = nameEl.value.trim();
          if (stepEl) {
            var step = parseInt(stepEl.value, 10);
            if (!Number.isInteger(step) || step < 1 || step > 10) {
              dialMsg(card, 'Step must be between 1 and 10', false);
              return;
            }
            body.step_percent = step;
          }
          if (autoEl) body.auto_update = autoEl.checked;
          if (chanEl) body.update_channel = chanEl.checked ? 'dev' : 'stable';
          if (muteAllEl && card.dataset.muteAllCaps === '1') body.mute_all_playing = muteAllEl.checked;
          if (card.dataset.pinSet === 'true') {
            var unlockedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (!unlockedPin) { dialMsg(card, 'Unlock settings first', false); return; }
            body.current_pin = unlockedPin;
          }
          try {
            var result = await _dialPost('/api/dial/configure', body);
            if (result.ok) { dialMsg(card, 'Saved', true); setTimeout(function(){ dialMsg(card, '', true); }, 2000); }
            else { dialMsg(card, _dialErrorMessage(result.error), false); }
          } catch(e) {
            dialMsg(card, 'Network error', false);
          }
        }

        async function dialLoadConfig(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {
            var loadResult = await _dialGet('/api/dial/configure/' + encodeURIComponent(uuid));
            if (!loadResult.ok) return;
            var j = loadResult.body;
            var stepEl = card.querySelector('.dial-step');
            var autoEl = card.querySelector('.dial-autoupdate');
            var chanEl = card.querySelector('.dial-channel');
            if (stepEl && j.step_percent != null) {
              stepEl.value = j.step_percent;
              var stepValEl = card.querySelector('.dial-step-val');
              if (stepValEl) stepValEl.textContent = j.step_percent + '% per click';
            }
            if (autoEl && j.auto_update != null) autoEl.checked = !!j.auto_update;
            if (chanEl && j.update_channel != null) chanEl.checked = (j.update_channel === 'dev');
            var muteAllEl = card.querySelector('.dial-mute-all');
            var muteAllRow = card.querySelector('.dial-mute-all-row');
            if (j.mute_all_playing !== undefined) {
              card.dataset.muteAllCaps = '1';
              if (muteAllEl) muteAllEl.checked = !!j.mute_all_playing;
              if (muteAllRow) muteAllRow.style.display = 'flex';
            } else {
              delete card.dataset.muteAllCaps;
              if (muteAllRow) muteAllRow.style.display = 'none';
            }
            card.dataset.pinSet = j.pin_set ? 'true' : 'false';
            card.dataset.canConfirm = j.can_confirm_presence === false ? 'false' : 'true';
            _updateDialLockVisibility(card);
          } catch(e) {}
        }

        async function dialLoadScreenSettings(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {
            var loadResult = await _dialGet('/api/dial/screen/settings/' + encodeURIComponent(uuid));
            if (!loadResult.ok) return;
            var j = loadResult.body;
            var fittedEl = card.querySelector('.dial-screen-fitted');
            var rotateEl = card.querySelector('.dial-screen-rotate');
            var bgrEl = card.querySelector('.dial-screen-bgr');
            var typeEl = card.querySelector('.dial-screen-type');
            var sizeEl = card.querySelector('.dial-screen-size');
            var touchEl = card.querySelector('.dial-screen-touch');
            var bgrRow = card.querySelector('.dial-screen-bgr-row');
            var typeRow = card.querySelector('.dial-screen-type-row');
            var sizeRow = card.querySelector('.dial-screen-size-row');
            var touchRow = card.querySelector('.dial-screen-touch-row');
            if (fittedEl && j.screen && j.screen.fitted != null) {
              fittedEl.checked = !!j.screen.fitted;
            }
            if (rotateEl && j.screen) {
              rotateEl.checked = !!(j.screen || {}).rotate;
            }
            // `supported` is the capability gate: older dials that don't
            // publish it must never receive screen_type/bgr in the save
            // body, so the two new controls stay hidden and disabled.
            var supported = Array.isArray(j.supported) ? j.supported : [];
            if (supported.length > 0) {
              card.dataset.screenCaps = '1';
              if (typeEl) {
                typeEl.innerHTML = '';
                supported.slice().sort(function(a, b) {
                  return String(a.text).localeCompare(String(b.text));
                }).forEach(function(opt) {
                  var o = document.createElement('option');
                  o.value = opt.key;
                  o.textContent = opt.text;
                  o.dataset.defaultInches = opt.default_inches;
                  typeEl.appendChild(o);
                });
                if (j.screen && j.screen.screen_type != null) typeEl.value = j.screen.screen_type;
                // Tracks the currently-selected option's own default, so a
                // later type change (see the save-screen dispatch) can tell
                // whether the size input still holds "the old default" (and
                // should move to the new one) or a genuine user override.
                var loadedTypeOpt = typeEl.selectedOptions[0];
                if (loadedTypeOpt) typeEl.dataset.prevDefault = loadedTypeOpt.dataset.defaultInches;
              }
              if (bgrEl && j.screen) bgrEl.checked = !!j.screen.bgr;
              if (bgrRow) bgrRow.style.display = 'flex';
              if (typeRow) typeRow.style.display = 'flex';
            } else {
              delete card.dataset.screenCaps;
              if (bgrRow) bgrRow.style.display = 'none';
              if (typeRow) typeRow.style.display = 'none';
            }
            // `supported_touch` is a SEPARATE capability array from
            // `supported` -- a dial can publish screen profiles but no touch
            // capability at all, and must never receive touch_type in the
            // save body or its strict whitelist rejects the whole save.
            var supportedTouch = Array.isArray(j.supported_touch) ? j.supported_touch : [];
            if (supportedTouch.length > 0) {
              card.dataset.touchCaps = '1';
              if (touchEl) {
                touchEl.innerHTML = '';
                supportedTouch.slice().sort(function(a, b) {
                  return String(a.text).localeCompare(String(b.text));
                }).forEach(function(opt) {
                  var o = document.createElement('option');
                  o.value = opt.key;
                  o.textContent = opt.text;
                  touchEl.appendChild(o);
                });
                if (j.screen && j.screen.touch_type != null) touchEl.value = j.screen.touch_type;
              }
              if (touchRow) touchRow.style.display = 'flex';
            } else {
              delete card.dataset.touchCaps;
              if (touchRow) touchRow.style.display = 'none';
            }
            // `always_show_controls` is a THIRD, independent capability gate
            // -- a dial can support screen profiles and touch but still be
            // on a release that predates this setting, and must never
            // receive the field in the save body until its own GET has
            // advertised it (see the cross-version compatibility notes).
            var ctlEl = card.querySelector('.dial-screen-always-controls');
            var ctlRow = card.querySelector('.dial-screen-controls-row');
            if (j.screen && j.screen.always_show_controls !== undefined) {
              card.dataset.controlsCaps = '1';
              if (ctlEl) ctlEl.checked = !!j.screen.always_show_controls;
              if (ctlRow) ctlRow.style.display = 'flex';
            } else {
              delete card.dataset.controlsCaps;
              if (ctlRow) ctlRow.style.display = 'none';
            }
            // `screen_size_inches` is a FOURTH, independent capability gate
            // -- same reasoning as always_show_controls above: a dial can
            // support screen profiles, touch and the controls toggle while
            // still predating this field, and must never receive it in the
            // save body until its own GET has advertised it. Pre-filled
            // from the override when the dial has one, else the selected
            // type's own built-in default (set on each <option> above).
            if (j.screen && j.screen.screen_size_inches !== undefined) {
              card.dataset.sizeCaps = '1';
              if (sizeEl) {
                var sizeTypeOpt = typeEl ? typeEl.selectedOptions[0] : null;
                if (typeof j.screen.screen_size_inches === 'number') {
                  sizeEl.value = j.screen.screen_size_inches;
                } else if (sizeTypeOpt) {
                  sizeEl.value = sizeTypeOpt.dataset.defaultInches;
                }
              }
              if (sizeRow) sizeRow.style.display = 'flex';
            } else {
              delete card.dataset.sizeCaps;
              if (sizeRow) sizeRow.style.display = 'none';
            }
            // `layout_sizes` is a FIFTH, independent capability gate -- same
            // reasoning as sizeCaps above: a dial can support everything else
            // above while still predating this field, and must never receive
            // it in the save body until its own GET has advertised it. The
            // fixed first option (value "", text "Native") represents the
            // panel's own resolution -- the client sends that as JSON null.
            var layoutRow = card.querySelector('.dial-screen-layout-row');
            if (Array.isArray(j.layout_sizes)) {
              card.dataset.layoutCaps = '1';
              dialFillLayoutSizes(card, j.layout_sizes, j.screen ? j.screen.layout_size : null);
              if (layoutRow) layoutRow.style.display = 'flex';
            } else {
              delete card.dataset.layoutCaps;
              if (layoutRow) layoutRow.style.display = 'none';
            }
            // Live setup-card notes: what the screen settings above resolve
            // to, from the dial's own report. Hidden entirely on an older
            // dial that publishes no `layout`.
            dialRenderLayoutNotes(card, j.layout);
            // `volume_scope`/`mute_scope` are a SIXTH, independent
            // capability gate -- same reasoning as layoutCaps above: a dial
            // can support everything else while still predating broadcast
            // scope, and must never receive either field in the save body
            // until its own GET has advertised BOTH. dataset.stored is what
            // dialSaveScreenSettings posts even while the row below forces
            // the select to "all" -- see dialSyncScreenControlsEnabled.
            var scopeRows = card.querySelectorAll('.dial-screen-scope-row');
            if (j.screen && j.screen.volume_scope !== undefined && j.screen.mute_scope !== undefined) {
              card.dataset.scopeCaps = '1';
              [['dial-volume-scope', j.screen.volume_scope], ['dial-mute-scope', j.screen.mute_scope]].forEach(function(p) {
                var el = card.querySelector('.' + p[0]);
                if (el) { el.dataset.stored = p[1]; el.value = p[1]; }
              });
              scopeRows.forEach(function(r) { r.style.display = 'flex'; });
            } else {
              delete card.dataset.scopeCaps;
              scopeRows.forEach(function(r) { r.style.display = 'none'; });
            }
            dialApplySurface(card, j);
            // Only now is it safe to save: the controls hold the dial's real
            // values, so a whole-object POST cannot reset an unread field.
            card.dataset.screenLoaded = '1';
            dialSyncScreenControlsEnabled(card);
          } catch(e) {}
        }

        // Shows the rows that fit the dial's screen. A kiosk (HD) dial has
        // no panel wiring to configure and no frame to show, so the SPI-only
        // rows and the "Show dial screen" button are hidden and brightness
        // and sleep appear instead, each only when the dial's own GET
        // carried the field (an older dial never gets it back). A dial that
        // sends no `surface` is an SPI dial. Runs after the per-row gates in
        // dialLoadScreenSettings so it has the last word on visibility.
        function dialApplySurface(card, j) {
          var screen = (j && j.screen) || {};
          var kiosk = screen.surface === 'kiosk';
          card.dataset.surface = kiosk ? 'kiosk' : 'spi';
          var spiOnly = ['dial-screen-rotate-row', 'dial-screen-bgr-row', 'dial-screen-size-row',
            'dial-screen-layout-row', 'dial-screen-touch-row', 'dial-screen-controls-row', 'dial-screen-layout-note',
            'dial-screen-touch-warning'];
          if (kiosk) {
            spiOnly.forEach(function(cls) {
              var el = card.querySelector('.' + cls);
              if (el) el.style.display = 'none';
            });
          } else {
            var rotateRow = card.querySelector('.dial-screen-rotate-row');
            if (rotateRow) rotateRow.style.display = 'flex';
          }
          var showBtn = card.querySelector('[data-dial-action="show-screen"]');
          if (showBtn) showBtn.style.display = kiosk ? 'none' : '';
          var brightEl = card.querySelector('.dial-screen-brightness');
          var brightRow = card.querySelector('.dial-screen-brightness-row');
          if (kiosk && screen.brightness !== undefined) {
            card.dataset.brightnessCaps = '1';
            if (brightEl) brightEl.value = screen.brightness;
            dialSyncBrightnessLabel(card);
            if (brightRow) brightRow.style.display = 'flex';
          } else {
            delete card.dataset.brightnessCaps;
            if (brightRow) brightRow.style.display = 'none';
          }
          var sleepEl = card.querySelector('.dial-screen-sleep');
          var sleepRow = card.querySelector('.dial-screen-sleep-row');
          if (kiosk && screen.sleep_after_s !== undefined) {
            card.dataset.sleepCaps = '1';
            if (sleepEl) sleepEl.value = String(screen.sleep_after_s);
            if (sleepRow) sleepRow.style.display = 'flex';
          } else {
            delete card.dataset.sleepCaps;
            if (sleepRow) sleepRow.style.display = 'none';
          }
          // Shown for every dial so it reads as unavailable on an SPI one;
          // dialSyncScreenControlsEnabled greys it out unless this is a kiosk.
          var panelOffEl = card.querySelector('.dial-screen-panel-off');
          var panelOffRow = card.querySelector('.dial-screen-panel-off-row');
          if (panelOffEl) panelOffEl.checked = kiosk && screen.panel_power_off === true;
          if (panelOffRow) panelOffRow.style.display = 'flex';
          // A kiosk profile chosen while a panel is still active needs the
          // kiosk install on the dial first.
          var noteEl = card.querySelector('.dial-screen-hd-note');
          var runtime = j && j.runtime;
          var panelActive = !!(runtime && runtime.backend && runtime.backend !== 'noop');
          if (noteEl) noteEl.style.display = (screen.screen_type === 'hd_kiosk' && panelActive) ? 'block' : 'none';
        }

        function dialSyncBrightnessLabel(card) {
          var el = card.querySelector('.dial-screen-brightness');
          var val = card.querySelector('.dial-screen-brightness-val');
          if (el && val) val.textContent = el.value + '%';
        }

        // Fill the layout-size <select> with the fixed "Native" option
        // (value "", meaning the panel's own resolution) followed by one
        // option per entry in *list* ({key, text}), and select *selected*
        // (or "" when it is null/undefined). Shared by dialLoadScreenSettings
        // and the POST success path (a screen_type change can change which
        // sizes are offered without a second GET).
        function dialFillLayoutSizes(card, list, selected) {
          var layoutEl = card.querySelector('.dial-screen-layout');
          if (!layoutEl) return;
          layoutEl.innerHTML = '';
          var native = document.createElement('option');
          native.value = '';
          native.textContent = 'Native';
          layoutEl.appendChild(native);
          list.forEach(function(opt) {
            var o = document.createElement('option');
            o.value = opt.key;
            o.textContent = opt.text;
            layoutEl.appendChild(o);
          });
          layoutEl.value = selected || '';
        }

        // Human labels for the dial's content tiers. Fallback to the raw key
        // so a tier this page does not know yet still reads as something.
        var _DIAL_TIER_LABEL = { base: 'compact', rich: 'standard', large: 'large' };

        function dialLayoutNoteText(layout) {
          var tier = _DIAL_TIER_LABEL[layout.content_tier] || String(layout.content_tier);
          var text = 'Renders at ' + layout.logical_width + 'x' + layout.logical_height
            + ' (' + tier + ' layout)';
          if (layout.resampled) {
            var down = layout.logical_width > layout.physical_width
              || layout.logical_height > layout.physical_height;
            text += ', scaled to the ' + layout.physical_width + 'x' + layout.physical_height + ' panel.';
            text += down
              ? ' Preview only: fine detail is lost and touch targets are smaller than a fingertip.'
              : ' Preview only: shown enlarged.';
          } else {
            text += '.';
          }
          return text;
        }

        function dialTouchWarningText(layout) {
          if (!layout.touch_short) return '';
          var text = 'Controls on this screen are shorter than the recommended 6 mm.';
          text += layout.size_chosen
            ? ' The chosen layout size overrides the automatic fallback to the compact layout.'
            : ' The compact layout is used automatically.';
          return text;
        }

        // Renders (or hides) the two setup-card notes below the layout-size
        // select from the screen-settings response's `layout` object -- the
        // dial's own report of what the persisted settings resolve to (see
        // dialLoadScreenSettings/dialSaveScreenSettings call sites below).
        // Called with null/undefined on an older dial that publishes no
        // `layout` at all, which simply hides both.
        function dialRenderLayoutNotes(card, layout) {
          var noteEl = card.querySelector('.dial-screen-layout-note');
          var warnEl = card.querySelector('.dial-screen-touch-warning');
          // A kiosk dial has no panel layout to describe.
          if (card.dataset.surface === 'kiosk') layout = null;
          if (!layout || typeof layout !== 'object') {
            if (noteEl) noteEl.style.display = 'none';
            if (warnEl) warnEl.style.display = 'none';
            return;
          }
          if (noteEl) {
            noteEl.textContent = dialLayoutNoteText(layout);
            noteEl.style.display = 'block';
          }
          if (warnEl) {
            var warning = dialTouchWarningText(layout);
            warnEl.textContent = warning;
            warnEl.style.display = warning ? 'block' : 'none';
          }
        }

        async function dialSaveScreenSettings(card, changedEl) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          var fittedEl = card.querySelector('.dial-screen-fitted');
          var rotateEl = card.querySelector('.dial-screen-rotate');
          var bgrEl = card.querySelector('.dial-screen-bgr');
          var typeEl = card.querySelector('.dial-screen-type');
          var touchEl = card.querySelector('.dial-screen-touch');
          if (!fittedEl || !rotateEl) return;
          // POST /screen/settings replaces the whole object, and any field
          // left out is reset to its default. dialLoadConfig and
          // dialLoadScreenSettings are fired independently on page load, so
          // without this guard a toggle clicked before the screen-settings
          // GET resolves would post {fitted, rotate} alone and silently
          // reset a configured screen_type/BGR back to defaults.
          if (card.dataset.screenLoaded !== '1') {
            dialMsg(card, 'Still loading screen settings \u2014 try again', false);
            return;
          }
          var screen = {fitted: fittedEl.checked, rotate: rotateEl.checked};
          // Capability gate: only include the new fields once the dial has
          // published `supported` -- an older dial 400s the whole save on an
          // unknown field, which would break the existing toggles too.
          if (card.dataset.screenCaps === '1') {
            screen.bgr = bgrEl ? bgrEl.checked : false;
            screen.screen_type = typeEl ? typeEl.value : '';
          }
          // Independent capability gate: a dial can support screen profiles
          // without supporting touch, so touch_type is only ever included
          // once the dial has published `supported_touch` separately.
          if (card.dataset.touchCaps === '1') {
            screen.touch_type = touchEl ? touchEl.value : '';
          }
          // Independent capability gate, same reasoning as touchCaps above:
          // an older dial 400s the whole save on an unknown field.
          if (card.dataset.controlsCaps === '1') {
            var ctlEl = card.querySelector('.dial-screen-always-controls');
            screen.always_show_controls = ctlEl ? ctlEl.checked : false;
          }
          // Independent capability gate, same reasoning as touchCaps/
          // controlsCaps above. Sends null (use the selected type's own
          // default) when the typed value equals that default, an empty
          // input, or is not a number -- otherwise the typed float. This
          // keeps the table authoritative for a dial that never deviated.
          if (card.dataset.sizeCaps === '1') {
            var sizeEl = card.querySelector('.dial-screen-size');
            var selectedTypeOpt = typeEl ? typeEl.selectedOptions[0] : null;
            var defaultInches = selectedTypeOpt ? parseFloat(selectedTypeOpt.dataset.defaultInches) : NaN;
            var rawSize = sizeEl ? sizeEl.value : '';
            var parsedSize = parseFloat(rawSize);
            screen.screen_size_inches = (
              rawSize === '' || isNaN(parsedSize) || parsedSize === defaultInches
            ) ? null : parsedSize;
          }
          // Independent capability gate, same reasoning as touchCaps/
          // controlsCaps/sizeCaps above. The select's "" value (Native) is
          // the panel's own resolution, sent as JSON null.
          if (card.dataset.layoutCaps === '1') {
            var layoutEl = card.querySelector('.dial-screen-layout');
            screen.layout_size = (layoutEl && layoutEl.value !== '') ? layoutEl.value : null;
          }
          // Independent capability gate, same reasoning as the others above.
          // Posts the STORED choice (dataset.stored), never the forced
          // display -- while the screen is off the selects show "All
          // Appliances" and are disabled, but the dial's own value must
          // stay whatever the user last chose, so turning the screen back
          // on restores it rather than silently resetting to "all".
          if (card.dataset.scopeCaps === '1') {
            var volEl = card.querySelector('.dial-volume-scope');
            var muteEl = card.querySelector('.dial-mute-scope');
            screen.volume_scope = (volEl && volEl.dataset.stored) || 'current';
            screen.mute_scope = (muteEl && muteEl.dataset.stored) || 'current';
          }
          // HD fields: only a kiosk dial that published them gets them back.
          if (card.dataset.brightnessCaps === '1') {
            var brightEl = card.querySelector('.dial-screen-brightness');
            if (brightEl && brightEl.value !== '') screen.brightness = parseInt(brightEl.value, 10);
          }
          if (card.dataset.sleepCaps === '1') {
            var sleepEl = card.querySelector('.dial-screen-sleep');
            if (sleepEl && sleepEl.value !== '') screen.sleep_after_s = parseInt(sleepEl.value, 10);
          }
          // Only an HD dial has the setting; an SPI dial would refuse the field.
          if (card.dataset.surface === 'kiosk') {
            var panelOffEl = card.querySelector('.dial-screen-panel-off');
            if (panelOffEl) screen.panel_power_off = panelOffEl.checked;
          }
          var body = {uuid: uuid, screen: screen};
          if (card.dataset.pinSet === 'true') {
            var unlockedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (!unlockedPin) { dialMsg(card, 'Unlock settings first', false); return; }
            body.current_pin = unlockedPin;
          }
          // Snapshot the changed control's previous value before posting --
          // a <select> can't be reverted with a simple !checked flip like
          // the checkboxes, so remember what to restore it to on failure.
          // The change has already happened, so a checkbox's previous value
          // is the opposite of its current one.
          var prevValue = null;
          if (changedEl) {
            prevValue = (changedEl.tagName === 'SELECT' || changedEl.type === 'number' || changedEl.type === 'range')
              ? changedEl.value : !changedEl.checked;
          }
          try {
            var result = await _dialPost('/api/dial/screen/settings', body);
            if (result.ok) {
              if (result.body && result.body.restarting === true) {
                // The dial is restarting itself to apply the new touch
                // controller -- hand off to the bounded poll instead of the
                // ordinary immediate-success path.
                dialBeginTouchRestartPoll(card, screen.touch_type);
              } else {
                if (result.body && Array.isArray(result.body.layout_sizes)) {
                  dialFillLayoutSizes(
                    card, result.body.layout_sizes,
                    result.body.screen ? result.body.screen.layout_size : null
                  );
                }
                var savedSurface = (result.body && result.body.screen && result.body.screen.surface === 'kiosk') ? 'kiosk' : 'spi';
                if (savedSurface !== card.dataset.surface) {
                  // A new screen type can move the dial between SPI and kiosk;
                  // reload so the rows match what it now reports.
                  dialLoadScreenSettings(card);
                }
                dialRenderLayoutNotes(card, result.body ? result.body.layout : null);
                dialMsg(card, 'Saved', true); setTimeout(function(){ dialMsg(card, '', true); }, 2000);
                dialSyncScreenControlsEnabled(card);
              }
            }
            else {
              dialMsg(card, _dialErrorMessage(result.error), false);
              // Revert only the control the user changed -- the others
              // still hold their pre-save values.
              if (changedEl) {
                if (changedEl.tagName === 'SELECT' || changedEl.type === 'number' || changedEl.type === 'range') changedEl.value = prevValue;
                else changedEl.checked = prevValue;
                if (changedEl.classList.contains('dial-volume-scope')
                    || changedEl.classList.contains('dial-mute-scope')) changedEl.dataset.stored = prevValue;
              }
              dialSyncScreenControlsEnabled(card);
            }
          } catch(e) {
            dialMsg(card, 'Network error', false);
            if (changedEl) {
              if (changedEl.tagName === 'SELECT' || changedEl.type === 'number' || changedEl.type === 'range') changedEl.value = prevValue;
              else changedEl.checked = prevValue;
              if (changedEl.classList.contains('dial-volume-scope')
                  || changedEl.classList.contains('dial-mute-scope')) changedEl.dataset.stored = prevValue;
            }
            dialSyncScreenControlsEnabled(card);
          }
        }

        async function dialUpdateFirmware(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (!confirm('Start firmware update? The dial will restart.')) return;
          try {
            var r = await fetch('/api/dial/update/' + encodeURIComponent(uuid), {
              method: 'POST', headers: {'X-CSRF-Token': window.__CSRF || ''}
            });
            var updResult = await _parseDialResponse(r);
            if (updResult.ok) {
              dialMsg(card, 'Update started', true);
              dialWatchUpdate(card, uuid);
            }
            else dialMsg(card, _dialErrorMessage(updResult.error), false);
          } catch(e) { dialMsg(card, 'Network error', false); }
        }

        // -- Dial firmware update: live progress and outcome ----------------
        // An update can take about 40 minutes, so the poll budget is an
        // hour. The dial drops off the network while it reboots; an
        // unanswered poll is expected and simply keeps the poll going.
        var DIAL_UPDATE_POLL_MS = 3000;
        var DIAL_UPDATE_BUDGET_MS = 60 * 60 * 1000;
        var DIAL_UPDATE_STALE_MS = 7 * 24 * 60 * 60 * 1000;
        var DIAL_UPDATE_STARTUP_GRACE_MS = 45000;

        function dialUpdateFailureText(b) {
          var tag = b && b.tag ? String(b.tag) : '';
          var prev = b && b.previous_tag ? String(b.previous_tag) : '';
          var head = tag ? 'Update to ' + tag + ' failed' : 'Update failed';
          if (!prev) return head;
          return head + ' \u2013 ' + (b.rolled_back ? 'restored ' + prev : prev + ' kept');
        }

        function dialUpdateBar(card, pct) {
          var bar = card ? card.querySelector('.dial-update-bar') : null;
          if (!bar) return;
          if (pct === null) { bar.style.display = 'none'; return; }
          var p = Math.max(0, Math.min(100, Number(pct) || 0));
          bar.style.display = '';
          bar.setAttribute('aria-valuenow', String(p));
          var fill = bar.querySelector('.dial-update-bar-fill');
          if (fill) fill.style.width = p + '%';
        }

        // Renders one status body on the card. Returns 'running', 'success'
        // or 'failure' (terminal) so the caller can decide to keep polling.
        function dialRenderUpdateStatus(card, b) {
          var state = b && b.state;
          if (state === 'complete') {
            dialUpdateBar(card, null);
            dialMsg(card, b.tag ? 'Updated to ' + b.tag : 'Updated', true);
            return 'success';
          }
          if (state === 'failed') {
            dialUpdateBar(card, null);
            dialMsg(card, dialUpdateFailureText(b), false);
            return 'failure';
          }
          if (b && b.phase === 'reboot') {
            dialUpdateBar(card, null);
            dialMsg(card, 'Restarting...', true);
            return 'running';
          }
          var pct = Number(b && b.percent) || 0;
          var text = '';
          if (Number(b && b.attempt) > 1) {
            text = 'Retrying update (attempt ' + b.attempt + ' of ' + (b.max_attempts || b.attempt) + ') - ';
          }
          text += 'Updating... ' + pct + '%';
          if (b && b.message) text += ' - ' + b.message;
          dialUpdateBar(card, pct);
          dialMsg(card, text, true);
          return 'running';
        }

        function dialWatchUpdate(card, uuid) {
          var startedAt = Date.now();
          var seenActivity = false;
          card.dataset.updateWatching = '1';
          dialUpdateBar(card, 0);
          function finish() { delete card.dataset.updateWatching; }
          dialPollUntil(DIAL_UPDATE_POLL_MS, DIAL_UPDATE_BUDGET_MS, async function() {
            var r;
            try { r = await _dialGet('/api/dial/update/status/' + encodeURIComponent(uuid)); }
            catch(e) { r = null; }
            if (!r || !r.ok || !r.body) {
              // Offline or unreachable: the dial is restarting.
              seenActivity = true;
              dialUpdateBar(card, null);
              dialMsg(card, 'Restarting...', true);
              return false;
            }
            var b = r.body;
            // The result of the previous run can still be on the dial for a
            // moment after the start request; do not mistake it for this
            // run's outcome until activity has been seen (or a grace has passed).
            var terminal = b.state === 'complete' || b.state === 'failed';
            if (terminal && !seenActivity && (Date.now() - startedAt) < DIAL_UPDATE_STARTUP_GRACE_MS) return false;
            if (!terminal) seenActivity = true;
            var outcome = dialRenderUpdateStatus(card, b);
            if (outcome === 'running') return false;
            finish();
            return true;
          }, function() {
            finish();
            dialUpdateBar(card, null);
            dialMsg(card, 'Update status unknown', false);
          });
        }

        // On opening the Dials panel: show the failure (or rollback) of a
        // recent update that nobody watched, e.g. a scheduled one. Needs the
        // result's own timestamp; without one nothing is shown.
        async function dialShowRecentUpdateFailure(card) {
          var uuid = dialUUID(card);
          if (!uuid || card.dataset.online !== 'true' || card.dataset.updateWatching) return;
          try {
            var r = await _dialGet('/api/dial/update/status/' + encodeURIComponent(uuid));
            if (!r.ok || !r.body || r.body.state !== 'failed') return;
            var when = Date.parse(r.body.last_run_at || '');
            if (isNaN(when) || (Date.now() - when) > DIAL_UPDATE_STALE_MS) return;
            if (card.dataset.updateWatching) return;
            dialMsg(card, dialUpdateFailureText(r.body), false);
          } catch(e) {}
        }

        // -- Dial SD card health monitoring row -----------------------------
        // Present only for a dial advertising dial_sdmon=v1 (rendered
        // server-side). The dial runs its probe on its own thread, so an
        // enable is: POST, then poll GET until probe.running is false.
        function _dialSdHealthLine(j) {
          var s = (j && j.state) || {};
          if (!s.tool_present) return 'Tool not installed on the dial';
          if (!s.timer_enabled) {
            if (j && j.requested) return 'Requested but not running (the last probe may have hung)';
            return 'Not monitored';
          }
          if (s.check === 'passed' && typeof s.health_percent === 'number') {
            return 'Monitored, ' + s.health_percent + ' % endurance remaining' +
              (s.last_sampled_at ? ', last checked ' + s.last_sampled_at : '');
          }
          return 'Monitored, no reading yet';
        }

        function _dialSdHealthRender(card, j) {
          var row = card.querySelector('.dial-sdhealth-row');
          if (!row) return;
          var s = (j && j.state) || {};
          var line = row.querySelector('.dial-sdhealth-status');
          var sel = row.querySelector('.dial-sdhealth-method');
          var btn = row.querySelector('.dial-sdhealth-btn');
          if (line) line.textContent = _dialSdHealthLine(j);
          var running = !!(j && j.probe && j.probe.running);
          if (sel) {
            if (s.method && !s.timer_enabled) sel.value = s.method;
            sel.disabled = running || !!s.timer_enabled || !s.tool_present;
          }
          if (btn) {
            btn.textContent = running ? 'Checking card...' : (s.timer_enabled ? 'Disable' : 'Enable');
            btn.disabled = running || !s.tool_present;
          }
          card.dataset.sdHealthEnabled = s.timer_enabled ? '1' : '0';
        }

        async function dialLoadSdHealth(card) {
          var uuid = dialUUID(card);
          if (!uuid || !card.querySelector('.dial-sdhealth-row')) return;
          try {
            var r = await _dialGet('/api/dial/sdcard-health/' + encodeURIComponent(uuid));
            if (r.ok) _dialSdHealthRender(card, r.body);
          } catch(e) {}
        }

        async function _dialSdHealthPoll(card, uuid, deadlineMs) {
          while (Date.now() < deadlineMs) {
            await new Promise(function(res) { setTimeout(res, 3000); });
            var r;
            try { r = await _dialGet('/api/dial/sdcard-health/' + encodeURIComponent(uuid)); }
            catch(e) { continue; }
            if (!r.ok) continue;
            _dialSdHealthRender(card, r.body);
            var p = r.body && r.body.probe;
            if (p && !p.running) return p;
          }
          return null;
        }

        async function dialSdHealthToggle(card) {
          var uuid = dialUUID(card);
          if (!uuid) return;
          var enabling = card.dataset.sdHealthEnabled !== '1';
          var sel = card.querySelector('.dial-sdhealth-method');
          var method = sel ? sel.value : 'auto';
          if (enabling) {
            if (!window.confirm("Querying the card's health uses a manufacturer command that may cause unsupported cards to become unresponsive. If the card stops responding, the system will restart automatically. Continue?")) return;
          } else {
            if (!window.confirm("Stop monitoring this dial's card health?")) return;
          }
          var body = {uuid: uuid, enabled: enabling, method: method};
          if (card.dataset.pinSet === 'true') {
            var unlockedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (!unlockedPin) { dialMsg(card, 'Unlock settings first', false); return; }
            body.current_pin = unlockedPin;
          }
          try {
            var result = await _dialPost('/api/dial/sdcard-health', body);
            if (!result.ok) { dialMsg(card, _dialErrorMessage(result.error), false); return; }
            _dialSdHealthRender(card, {state: {tool_present: true, timer_enabled: !enabling}, probe: {running: true}});
            var probe = await _dialSdHealthPoll(card, uuid, Date.now() + 150000);
            if (!probe) { dialMsg(card, 'The dial did not report a result in time', false); return; }
            if (probe.outcome === 'passed') {
              dialMsg(card, enabling ? 'Monitoring enabled' : 'Monitoring disabled', true);
              setTimeout(function(){ dialMsg(card, '', true); }, 2000);
            } else {
              var msg = probe.outcome === 'unsupported' ? ('This card is not supported' + (probe.reason ? ': ' + probe.reason : ''))
                : probe.outcome === 'hung' ? 'A query of this card did not complete; the card may not be supported'
                : probe.outcome === 'tool_missing' ? 'The SD card health tool is not installed on the dial'
                : 'The card health check failed' + (probe.reason ? ': ' + probe.reason : '');
              dialMsg(card, msg, false);
            }
          } catch(e) { dialMsg(card, 'Network error', false); }
        }

        function _openDialPinModal(card, mode, title, message) {
          _dialPinModalCard = card;
          _dialPinModalMode = mode;
          var modal = document.getElementById('dialPinModal');
          if (!modal) return;
          document.getElementById('dialPinModalTitle').textContent = title;
          document.getElementById('dialPinModalMsg').textContent = message;
          var errEl = document.getElementById('dialPinModalError');
          errEl.style.display = 'none'; errEl.textContent = '';
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          currentInputEl.value = '';
          // unlock: current PIN is the only field; change: current PIN not shown (stored from unlock)
          currentInputEl.style.display = mode === 'unlock' ? '' : 'none';
          var inputEl = document.getElementById('dialPinModalInput');
          inputEl.value = '';
          inputEl.style.display = mode === 'unlock' ? 'none' : '';
          var confirmInputEl = document.getElementById('dialPinModalConfirmInput');
          confirmInputEl.value = '';
          confirmInputEl.style.display = mode === 'unlock' ? 'none' : '';
          var okBtn = document.getElementById('dialPinModalOk');
          okBtn.textContent = mode === 'unlock' ? 'Unlock' : (card.dataset.pinSet !== 'true' ? 'Set PIN' : 'Change PIN');
          okBtn.disabled = false;
          document.getElementById('dialPinModalCancel').disabled = false;
          modal.classList.add('show');
          setTimeout(function(){
            (mode === 'unlock' ? currentInputEl : inputEl).focus();
          }, 50);
        }

        function _closeDialPinModal() {
          _dialPinModalCard = null; _dialPinModalMode = null;
          var modal = document.getElementById('dialPinModal');
          if (modal) modal.classList.remove('show');
        }

        function dialChangePIN(card) {
          var hasPin = card.dataset.pinSet === 'true';
          _openDialPinModal(card, 'change',
            hasPin ? 'Change Dial PIN' : 'Set Dial PIN',
            hasPin ? 'Enter a new PIN (leave blank to remove):' : 'Enter a new PIN:');
        }

        function openDialNameModal(card) {
          _dialNameModalCard = card;
          var modal = document.getElementById('dialNameModal');
          if (!modal) return;
          var nameInput = card.querySelector('.dial-name');
          var currentName = (nameInput ? nameInput.value : '') || '';
          var inp = document.getElementById('dialNameModalInput');
          var errEl = document.getElementById('dialNameModalError');
          if (inp) { inp.value = currentName; inp.disabled = false; }
          if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
          var ok = document.getElementById('dialNameModalOk');
          var cancel = document.getElementById('dialNameModalCancel');
          if (ok) ok.disabled = false;
          if (cancel) cancel.disabled = false;
          modal.classList.add('show');
          setTimeout(function() { if (inp) { inp.focus(); inp.select(); } }, 50);
        }

        function closeDialNameModal() {
          _dialNameModalCard = null;
          var modal = document.getElementById('dialNameModal');
          if (modal) modal.classList.remove('show');
        }

        async function handleDialNameModalOk() {
          var card = _dialNameModalCard;
          if (!card) return;
          var uuid = dialUUID(card);
          if (!uuid) return;
          var inp = document.getElementById('dialNameModalInput');
          var errEl = document.getElementById('dialNameModalError');
          var ok = document.getElementById('dialNameModalOk');
          var cancel = document.getElementById('dialNameModalCancel');
          var newName = (inp ? inp.value : '').trim();
          if (!newName) {
            if (errEl) { errEl.textContent = 'Enter a name.'; errEl.style.display = ''; }
            if (inp) inp.focus();
            return;
          }
          var body = {uuid: uuid, name: newName};
          if (card.dataset.pinSet === 'true') {
            var storedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (storedPin) body.current_pin = storedPin;
          }
          if (ok) ok.disabled = true;
          if (cancel) cancel.disabled = true;
          if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
          try {
            var result = await _dialPost('/api/dial/configure', body);
            if (result.ok) {
              var nameInput = card.querySelector('.dial-name');
              if (nameInput) nameInput.value = newName;
              var titleEl = card.querySelector('.dial-card-title');
              if (titleEl) titleEl.textContent = newName;
              var nameDisplayEl = card.querySelector('.dial-current-name');
              if (nameDisplayEl) nameDisplayEl.textContent = newName;
              dialMsg(card, 'Name changed', true);
              setTimeout(function() { dialMsg(card, '', true); }, 2000);
              closeDialNameModal();
            } else {
              if (errEl) { errEl.textContent = _dialErrorMessage(result.error); errEl.style.display = ''; }
              if (ok) ok.disabled = false;
              if (cancel) cancel.disabled = false;
            }
          } catch(e) {
            if (errEl) { errEl.textContent = 'Network error'; errEl.style.display = ''; }
            if (ok) ok.disabled = false;
            if (cancel) cancel.disabled = false;
          }
        }

        function _dialFormatRemaining(ms) {
          var totalSec = Math.max(0, Math.floor((Number(ms) || 0) / 1000));
          var m = Math.floor(totalSec / 60);
          var s = totalSec % 60;
          return m + ':' + (s < 10 ? '0' : '') + s + ' remaining';
        }

        function _dialPinRecoveryExpired() {
          if (_dialPinRecoveryTimer) { clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }
          document.getElementById('dialPinRecoveryWaitMsg').textContent =
            'The recovery window closed without confirmation. Power-cycle the Dial to try again.';
          var okBtn = document.getElementById('dialPinRecoveryOk');
          if (okBtn) { okBtn.disabled = true; okBtn.textContent = 'Window closed'; }
        }

        function _dialPinRecoveryCannotConfirm() {
          if (_dialPinRecoveryTimer) { clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }
          document.getElementById('dialPinRecoveryWaitMsg').textContent =
            'This dial has no rotary control, button or touch panel, so it cannot confirm you are there. PIN recovery cannot complete.';
          var okBtn = document.getElementById('dialPinRecoveryOk');
          if (okBtn) { okBtn.disabled = true; okBtn.textContent = 'Cannot confirm presence'; }
        }

        function openDialPinRecoveryModal(card) {
          _dialPinRecoveryModalCard = card;
          var uuid = dialUUID(card);
          var modal = document.getElementById('dialPinRecoveryModal');
          if (!modal || !uuid) return;
          _dialPinRecoveryStep = 'confirm';
          document.getElementById('dialPinRecoveryModalTitle').textContent = 'Reset Dial PIN';
          document.getElementById('dialPinRecoveryConfirmPanel').style.display = '';
          document.getElementById('dialPinRecoveryWaitPanel').style.display = 'none';
          document.getElementById('dialPinRecoverySetPanel').style.display = 'none';
          var newInp = document.getElementById('dialPinRecoveryNewInput');
          var confInp = document.getElementById('dialPinRecoveryConfirmInput');
          var errEl = document.getElementById('dialPinRecoveryError');
          if (newInp) newInp.value = '';
          if (confInp) confInp.value = '';
          if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          if (okBtn) { okBtn.disabled = false; okBtn.textContent = 'Yes'; }
          if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.textContent = 'No'; }
          if (_dialPinRecoveryTimer) { clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }
          modal.classList.add('show');
        }

        // Popup 1 ("This feature can be used to reset a lost PIN. Continue?")
        // asked the admin, not the device. Only on Yes does the appliance
        // proxy an arm request to the dial -- if that fails, there is
        // nothing to wait for, so the flow must not advance to the
        // power-cycle step or the user would wait for an arm that never
        // happened.
        async function handleDialPinRecoveryConfirmYes() {
          var card = _dialPinRecoveryModalCard;
          if (!card) return;
          var uuid = dialUUID(card);
          if (!uuid) return;
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          if (okBtn) okBtn.disabled = true;
          if (cancelBtn) cancelBtn.disabled = true;
          try {
            var result = await _dialPost('/api/dial/recovery/arm', {uuid: uuid});
            if (result.ok) {
              _dialPinRecoveryBeginWait(card, uuid);
            } else {
              dialMsg(card, _dialErrorMessage(result.error), false);
              closeDialPinRecoveryModal();
            }
          } catch(e) {
            dialMsg(card, 'Network error', false);
            closeDialPinRecoveryModal();
          }
        }

        // Popup 2: the existing power-cycle wording and status poll,
        // unchanged, now started only once the arm request has succeeded.
        function _dialPinRecoveryBeginWait(card, uuid) {
          _dialPinRecoveryStep = 'wait';
          document.getElementById('dialPinRecoveryConfirmPanel').style.display = 'none';
          document.getElementById('dialPinRecoveryWaitPanel').style.display = '';
          document.getElementById('dialPinRecoverySetPanel').style.display = 'none';
          document.getElementById('dialPinRecoveryWaitMsg').textContent =
            'To reset the Dial PIN, start by power-cycling the Dial now. Once it restarts, you have 10 minutes to confirm you are at the device.';
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          if (okBtn) { okBtn.disabled = true; okBtn.textContent = 'Waiting for Dial\u2026'; }
          if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.textContent = 'Cancel'; }
          _dialPinRecoverySeenActive = false;
          if (_dialPinRecoveryTimer) { clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }
          _dialPinRecoveryTimer = setInterval(async function() {
            try {
              var pollResult = await _dialGet('/api/dial/pin_recovery/status/' + encodeURIComponent(uuid));
              var body = pollResult.body || {};
              // A boolean `active` is only ever present when the dial itself
              // answered -- on both the in-recovery 200 and the not-in-recovery
              // 404 that the proxy tunnels through HTTP 200. Transport
              // failures carry no `active`, so an unreachable dial leaves the
              // badge as-is rather than falsely clearing it.
              if (typeof body.active === 'boolean') {
                var pollRemainingMs = body.recovery_remaining_ms;
                _dialSetRecoveryBadge(card, body.active === true &&
                  !(typeof pollRemainingMs === 'number' && pollRemainingMs <= 0));
              }
              if (!pollResult.ok) return; // offline, unreachable, or not yet in recovery -- wait silently
              if (body.can_confirm_presence === false) {
                _dialPinRecoveryCannotConfirm();
                return;
              }
              if (body.volume_confirmed === true) {
                clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null;
                _dialPinRecoveryTransitionToSet();
                return;
              }
              var remainingMs = body.recovery_remaining_ms;
              var stillActive = body.active === true &&
                !(typeof remainingMs === 'number' && remainingMs <= 0);
              if (stillActive) {
                _dialPinRecoverySeenActive = true;
                document.getElementById('dialPinRecoveryWaitMsg').textContent =
                  "Touch the dial's screen, twist its rotary control, or press its button to confirm you are there. (" +
                  _dialFormatRemaining(remainingMs) + ')';
                // The dial is back and listening; what the flow is waiting
                // on is no longer the device but the person standing at it.
                // Leaving the button on "Waiting for Dial" reads as though
                // nothing has happened yet, when in fact the only remaining
                // step is theirs.
                if (okBtn) okBtn.textContent = 'Waiting for user\u2026';
              } else if (_dialPinRecoverySeenActive) {
                // Window was active and is no longer -- it expired rather than
                // never having started, so tell the user instead of leaving
                // them on "Waiting for Dial..." forever.
                _dialPinRecoveryExpired();
              }
            } catch(e) {}
          }, 2000);
        }

        function _dialPinRecoveryTransitionToSet() {
          _dialPinRecoveryStep = 'set';
          document.getElementById('dialPinRecoveryModalTitle').textContent = 'Set New Dial PIN';
          document.getElementById('dialPinRecoveryWaitPanel').style.display = 'none';
          document.getElementById('dialPinRecoverySetPanel').style.display = '';
          var okBtn = document.getElementById('dialPinRecoveryOk');
          if (okBtn) { okBtn.disabled = false; okBtn.textContent = 'Set PIN'; }
          setTimeout(function() {
            var newInp = document.getElementById('dialPinRecoveryNewInput');
            if (newInp) newInp.focus();
          }, 50);
        }

        function closeDialPinRecoveryModal() {
          var card = _dialPinRecoveryModalCard;
          var uuid = dialUUID(card);
          _dialPinRecoveryModalCard = null;
          _dialPinRecoveryStep = null;
          if (_dialPinRecoveryTimer) { clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }
          var modal = document.getElementById('dialPinRecoveryModal');
          if (modal) modal.classList.remove('show');
          // Best-effort: bounds a forgotten request without relying on the
          // device clock. A closed browser mid-flow leaves nothing armed.
          if (uuid) {
            _dialPost('/api/dial/recovery/disarm', {uuid: uuid}).catch(function() {});
          }
        }

        async function handleDialPinRecoveryOk() {
          var card = _dialPinRecoveryModalCard;
          if (!card) return;
          var uuid = dialUUID(card);
          if (!uuid) return;
          var newInp = document.getElementById('dialPinRecoveryNewInput');
          var confInp = document.getElementById('dialPinRecoveryConfirmInput');
          var errEl = document.getElementById('dialPinRecoveryError');
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          var newPin = (newInp ? newInp.value : '').trim();
          var confPin = (confInp ? confInp.value : '').trim();
          if (!/^\d{4,8}$/.test(newPin)) {
            if (errEl) { errEl.textContent = 'Enter 4\u20138 digits.'; errEl.style.display = ''; }
            if (newInp) newInp.focus();
            return;
          }
          if (newPin !== confPin) {
            if (errEl) { errEl.textContent = 'The two PIN entries did not match.'; errEl.style.display = ''; }
            if (confInp) confInp.focus();
            return;
          }
          if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
          if (okBtn) okBtn.disabled = true;
          if (cancelBtn) cancelBtn.disabled = true;
          try {
            var result = await _dialPost('/api/dial/pin_recovery/complete', {uuid: uuid, new_pin: newPin, pin_recovery: true});
            if (result.ok) {
              card.dataset.pinSet = 'true';
              _updateDialLockVisibility(card);
              _dialSetRecoveryBadge(card, false);
              dialMsg(card, 'PIN reset', true);
              closeDialPinRecoveryModal();
            } else {
              if (errEl) { errEl.textContent = _dialErrorMessage(result.error); errEl.style.display = ''; }
              if (okBtn) okBtn.disabled = false;
              if (cancelBtn) cancelBtn.disabled = false;
            }
          } catch(e) {
            if (errEl) { errEl.textContent = 'Network error'; errEl.style.display = ''; }
            if (okBtn) okBtn.disabled = false;
            if (cancelBtn) cancelBtn.disabled = false;
          }
        }

        async function _handleDialPinModalOk() {
          var card = _dialPinModalCard;
          var uuid = dialUUID(card);
          var mode = _dialPinModalMode;
          if (!uuid) return;
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          var inputEl = document.getElementById('dialPinModalInput');
          var errEl = document.getElementById('dialPinModalError');
          var okBtn = document.getElementById('dialPinModalOk');
          var currentPin = (currentInputEl ? currentInputEl.value : '').trim();
          var pin = (inputEl ? inputEl.value : '').trim();
          okBtn.disabled = true; errEl.style.display = 'none';
          try {
            var pinResult;
            if (mode === 'unlock') {
              // Verify PIN by saving the current config values -- same payload as dialSaveConfig.
              // The dial validates the PIN against a real request; values are unchanged.
              var verifyBody = {uuid: uuid, current_pin: currentPin};
              var nameEl2 = card.querySelector('.dial-name');
              var stepEl2 = card.querySelector('.dial-step');
              var autoEl2 = card.querySelector('.dial-autoupdate');
              var chanEl2 = card.querySelector('.dial-channel');
              if (nameEl2) verifyBody.name = nameEl2.value.trim();
              if (stepEl2) {
                var step2 = parseInt(stepEl2.value, 10);
                if (Number.isInteger(step2)) verifyBody.step_percent = step2;
              }
              if (autoEl2) verifyBody.auto_update = autoEl2.checked;
              if (chanEl2) verifyBody.update_channel = chanEl2.checked ? 'dev' : 'stable';
              pinResult = await _dialPost('/api/dial/configure', verifyBody);
              if (pinResult.ok) {
                _dialUnlockSection(card, currentPin);
                dialLoadScreenSettings(card);
                _closeDialPinModal();
              } else {
                errEl.textContent = _dialErrorMessage(pinResult.error); errEl.style.display = '';
                okBtn.disabled = false;
              }
            } else {
              var confirmInputEl = document.getElementById('dialPinModalConfirmInput');
              var confirmPin = (confirmInputEl ? confirmInputEl.value : '').trim();
              if (pin !== confirmPin) {
                errEl.textContent = 'The two PIN entries did not match.'; errEl.style.display = '';
                okBtn.disabled = false;
                if (confirmInputEl) confirmInputEl.focus();
                return;
              }
              var body = {uuid: uuid, new_pin: pin};
              if (card.dataset.pinSet === 'true') {
                var storedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
                if (storedPin) body.current_pin = storedPin;
              }
              pinResult = await _dialPost('/api/dial/configure', body);
              if (pinResult.ok) {
                card.dataset.pinSet = pin ? 'true' : 'false';
                dialMsg(card, pin ? 'PIN changed' : 'PIN removed', true);
                _closeDialPinModal();
                _updateDialLockVisibility(card);
              } else {
                errEl.textContent = _dialErrorMessage(pinResult.error); errEl.style.display = '';
                okBtn.disabled = false;
              }
            }
          } catch(e) {
            errEl.textContent = 'Network error'; errEl.style.display = '';
            okBtn.disabled = false;
          }
        }

        document.addEventListener('DOMContentLoaded', function() {
          var ok = document.getElementById('dialPinModalOk');
          var cancel = document.getElementById('dialPinModalCancel');
          var pinConfirmInp = document.getElementById('dialPinModalConfirmInput');
          if (ok) ok.addEventListener('click', _handleDialPinModalOk);
          if (cancel) cancel.addEventListener('click', _closeDialPinModal);
          if (pinConfirmInp) pinConfirmInp.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); _handleDialPinModalOk(); }
          });
          var recoveryOk = document.getElementById('dialPinRecoveryOk');
          var recoveryCancel = document.getElementById('dialPinRecoveryCancel');
          var recoveryConfirmInp = document.getElementById('dialPinRecoveryConfirmInput');
          if (recoveryOk) recoveryOk.addEventListener('click', function() {
            if (_dialPinRecoveryStep === 'confirm') { handleDialPinRecoveryConfirmYes(); return; }
            if (_dialPinRecoveryStep === 'set') { handleDialPinRecoveryOk(); return; }
          });
          if (recoveryCancel) recoveryCancel.addEventListener('click', closeDialPinRecoveryModal);
          if (recoveryConfirmInp) recoveryConfirmInp.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); handleDialPinRecoveryOk(); }
          });
          var resultOk = document.getElementById('dialResultModalOk');
          if (resultOk) resultOk.addEventListener('click', _dialCloseResultModal);
          var panelOffOk = document.getElementById('dialPanelOffOk');
          var panelOffCancel = document.getElementById('dialPanelOffCancel');
          if (panelOffOk) panelOffOk.addEventListener('click', function() { _dialClosePanelOff(true); });
          if (panelOffCancel) panelOffCancel.addEventListener('click', function() { _dialClosePanelOff(false); });
          var dialScreenClose = document.getElementById('dialScreenModalClose');
          var dialScreenRefresh = document.getElementById('dialScreenModalRefresh');
          if (dialScreenClose) dialScreenClose.addEventListener('click', _dialCloseScreenModal);
          if (dialScreenRefresh) dialScreenRefresh.addEventListener('click', _dialScreenFetch);
          var dialNameOk = document.getElementById('dialNameModalOk');
          var dialNameCancel = document.getElementById('dialNameModalCancel');
          var dialNameInput = document.getElementById('dialNameModalInput');
          if (dialNameOk) dialNameOk.addEventListener('click', handleDialNameModalOk);
          if (dialNameCancel) dialNameCancel.addEventListener('click', closeDialNameModal);
          if (dialNameInput) dialNameInput.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); handleDialNameModalOk(); }
          });
          document.addEventListener('keydown', function(ev) {
            var m = document.getElementById('dialPinModal');
            if (ev.key === 'Escape' && m && m.classList.contains('show')) _closeDialPinModal();
            var hm = document.getElementById('hostnameModal');
            if (ev.key === 'Escape' && hm && hm.classList.contains('show')) closeHostnameModal();
            var wm = document.getElementById('wifiHotspotModal');
            if (ev.key === 'Escape' && wm && wm.classList.contains('show')) cancelChangeWifiNetwork();
            var rm = document.getElementById('dialPinRecoveryModal');
            if (ev.key === 'Escape' && rm && rm.classList.contains('show')) closeDialPinRecoveryModal();
            var nm = document.getElementById('dialNameModal');
            if (ev.key === 'Escape' && nm && nm.classList.contains('show')) closeDialNameModal();
            var sm = document.getElementById('dialScreenModal');
            if (ev.key === 'Escape' && sm && sm.classList.contains('show')) _dialCloseScreenModal();
            var pm = document.getElementById('dialPanelOffModal');
            if (ev.key === 'Escape' && pm && pm.classList.contains('show')) _dialClosePanelOff(false);
          });
        });
        // Dials card (lazy-loaded): the .dial-card bindings below used
        // to live in the DOMContentLoaded listener above, but `.dial-card`
        // elements don't exist until the Dials panel's body has been
        // fetched -- moved into a named function invoked once by
        // openPanel() the first time the Dials panel opens (see
        // _setupInitPanel()). The modal-button bindings above stay in
        // DOMContentLoaded since those modals are always in the DOM
        // (global, rendered in _body_prefix).
        function _initDialsCard() {
          document.querySelectorAll('.dial-card').forEach(function(card) {
            card.addEventListener('input', function(ev) {
              if (ev.target.classList.contains('dial-screen-brightness')) dialSyncBrightnessLabel(card);
            });
            card.addEventListener('change', function(ev) {
              var action = ev.target.dataset.dialAction;
              if (action === 'toggle-allow') dialToggleAllow(card, ev.target.checked);
              if (action === 'save-config' && (
                ev.target.classList.contains('dial-autoupdate') ||
                ev.target.classList.contains('dial-channel') ||
                ev.target.classList.contains('dial-mute-all') ||
                ev.target.classList.contains('dial-step')
              )) dialSaveConfig(card);
              if (action === 'save-screen') {
                if (ev.target.classList.contains('dial-screen-fitted')
                    || ev.target.classList.contains('dial-screen-touch')) dialSyncScreenControlsEnabled(card);
                if (ev.target.classList.contains('dial-screen-type')) {
                  // Move the size input to the new type's own default unless
                  // the user already overrode it (its value no longer
                  // matches the PREVIOUS type's default) -- see
                  // dialLoadScreenSettings's prevDefault tracking.
                  var sizeInput = card.querySelector('.dial-screen-size');
                  var newTypeOpt = ev.target.selectedOptions[0];
                  if (card.dataset.sizeCaps === '1' && sizeInput && newTypeOpt) {
                    var prevDefault = parseFloat(ev.target.dataset.prevDefault);
                    var currentSize = parseFloat(sizeInput.value);
                    if (sizeInput.value === '' || currentSize === prevDefault) {
                      sizeInput.value = newTypeOpt.dataset.defaultInches;
                    }
                  }
                  if (newTypeOpt) ev.target.dataset.prevDefault = newTypeOpt.dataset.defaultInches;
                  // Reset the layout-size select to Native before saving --
                  // the new type may not offer whatever size was selected,
                  // and posting one it does not offer would 400 the whole
                  // save. The response repopulates the options for the new
                  // type (see dialSaveScreenSettings's success path).
                  var layoutEl = card.querySelector('.dial-screen-layout');
                  if (card.dataset.layoutCaps === '1' && layoutEl) layoutEl.value = '';
                }
                if (ev.target.classList.contains('dial-volume-scope')
                    || ev.target.classList.contains('dial-mute-scope')) {
                  ev.target.dataset.stored = ev.target.value;
                }
                if (ev.target.classList.contains('dial-screen-panel-off') && ev.target.checked) {
                  // Switching the panel off can harm some panels: ask first,
                  // and send nothing unless the answer is Continue.
                  dialConfirmPanelOff(function() {
                    dialSaveScreenSettings(card, ev.target);
                  }, function() { ev.target.checked = false; });
                  return;
                }
                dialSaveScreenSettings(card, ev.target);
              }
            });
            card.addEventListener('focusout', function(ev) {
              if (ev.target.dataset.dialAction === 'save-config'
                  && !ev.target.classList.contains('dial-autoupdate')
                  && !ev.target.classList.contains('dial-channel')
                  && !ev.target.classList.contains('dial-mute-all')
                  && !ev.target.classList.contains('dial-step')) {
                dialSaveConfig(card);
              }
            });
            var lockedSection = card.querySelector('.dial-locked-section');
            if (lockedSection) {
              lockedSection.addEventListener('focusout', function(ev) {
                setTimeout(function() {
                  if (!lockedSection.contains(document.activeElement)) {
                    if (card.dataset.pinSet === 'true') _dialLockSection(card);
                  }
                }, 0);
              });
            }
            card.addEventListener('click', function(ev) {
              var target = ev.target.closest('[data-dial-action]');
              if (!target || target.tagName === 'INPUT') return;
              var action = target.dataset.dialAction;
              if (action === 'revoke') dialRevoke(card);
              if (action === 'show-screen') dialShowScreen(card);
              if (action === 'sdhealth-toggle') dialSdHealthToggle(card);
              if (action === 'update') dialUpdateFirmware(card);
              if (action === 'change-pin') dialChangePIN(card);
              if (action === 'recover-pin') openDialPinRecoveryModal(card);
              if (action === 'change-name') openDialNameModal(card);
              if (action === 'toggle-lock') {
                if (_dialUnlockedPins.has(card) && card.dataset.pinSet === 'true') {
                  _dialLockSection(card);
                } else if (!_dialUnlockedPins.has(card)) {
                  _openDialPinModal(card, 'unlock', 'Unlock Settings', 'Enter your Dial PIN:');
                }
              }
            });
          });
          // Load current config for each online authorized dial
          document.querySelectorAll('.dial-card[data-authorized="true"]').forEach(function(card) { dialLoadConfig(card); dialLoadScreenSettings(card); dialLoadSdHealth(card); dialShowRecentUpdateFailure(card); });
        }
