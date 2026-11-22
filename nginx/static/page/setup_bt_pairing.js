var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
        // -- Bluetooth pairing window -------------------------------------
        // One screen: while it is open the appliance is discoverable and
        // searching at once, and its poll is the heartbeat that keeps the
        // window open. Nothing pairs for audio until the user taps an entry
        // and confirms it with the button.
        var BT_LOOPBACK_HW = pageData.bt_loopback_hw;
        var btPaired = pageData.bt_paired;
        var _btLinkState = pageData.bt_link_state;
        var _btInputIndex = null;
        var _btSelectEl = null;
        var _btPriorSelectValue = null;
        var _btPairSucceeded = false;
        var _btSelectedMac = null;
        var _btDevices = [];
        var _btWindowState = 'idle';
        var _btStartPending = false;
        var _btFinished = false;

        var _BT_STATE_LABELS = {
          found: 'Found', provisional: 'Wants to connect',
          confirming: 'Pairing\u2026', paired: 'Paired'
        };
        var _BT_TAPPABLE = {found: true, provisional: true};
        var _BT_STOP_REASONS = {
          limit: 'The pairing screen closes after five minutes. Open it again to keep looking.',
          no_heartbeat: 'Pairing stopped. Open it again.',
          adapter_lost: 'The Bluetooth adapter was removed.',
          cancel: 'Pairing was cancelled.',
          forget: 'Pairing stopped because the paired device was forgotten.'
        };

        var _btWindowPoller = Poller({
          url: '/api/bluetooth/pair_window',
          intervalMs: 2000,
          activeOnly: true,
          onData: _btOnWindowPoll,
          onError: _btOnWindowError
        });

        function isBluetoothDevice(value) { return value === BT_LOOPBACK_HW; }

        async function _btFetch(path, opts) {
          opts = opts || {};
          var headers = Object.assign({'X-CSRF-Token': window.__CSRF || ''}, (opts.headers || {}));
          try {
            var r = await fetch(path, Object.assign({cache: 'no-store'}, opts, {headers: headers}));
            var body = null;
            try { body = await r.json(); } catch (e) {}
            return {status: r.status, body: body};
          } catch (e) {
            return {status: 0, body: null};
          }
        }

        // 404 and 503 cross the proxy as 200 with the real status in the body.
        function _btStatus(res) {
          return (res && res.body && res.body.error_status) || (res ? res.status : 0);
        }

        var _BT_UNAVAILABLE = 'Bluetooth is not available: the adapter or the Bluetooth service is missing.';

        function _btPost(path, payload) {
          return _btFetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload || {})
          });
        }

        function _btShowPanel(name) {
          ['Window', 'Result'].forEach(function(p) {
            var el = document.getElementById('bt' + p + 'Panel');
            if (el) el.style.display = (p === name) ? '' : 'none';
          });
        }

        async function btForgetFromCard() {
          if (!window.confirm('Forget the currently paired Bluetooth device?')) return;
          await _btPost('/api/bluetooth/forget', {});
          _btRefreshLinkStatus();
        }

        function _btEntryLabel(d) {
          var label = _BT_STATE_LABELS[d.state] || '';
          if (d.state === 'provisional' && d.passkey !== null && d.passkey !== undefined) {
            label = 'Code ' + String(d.passkey).padStart(6, '0') + ' \u00b7 ' + label;
          }
          return label;
        }

        function _btDeviceName(mac) {
          for (var i = 0; i < _btDevices.length; i++) {
            if (_btDevices[i].mac === mac) return _btDevices[i].name || mac;
          }
          return mac;
        }

        function _btRenderList(devices, adopting) {
          var list = document.getElementById('btWindowDeviceList');
          if (!list) return;
          if (!devices.length) {
            list.innerHTML = '<p class="bt-scan-empty">Searching\u2026</p>';
            return;
          }
          list.innerHTML = '';
          devices.forEach(function(d) {
            var row = document.createElement('div');
            row.className = 'bt-scan-row' + (d.mac === _btSelectedMac ? ' selected' : '');
            row.dataset.mac = d.mac;
            var name = document.createElement('div');
            name.className = 'bt-row-name';
            name.textContent = d.name || d.mac;
            var mac = document.createElement('div');
            mac.className = 'bt-row-mac';
            mac.textContent = d.mac;
            var state = document.createElement('div');
            state.className = 'bt-row-state';
            state.textContent = _btEntryLabel(d);
            row.appendChild(name);
            row.appendChild(mac);
            row.appendChild(state);
            row.addEventListener('click', function() { _btSelectRow(d); });
            list.appendChild(row);
          });
          _btSyncPairButton(adopting);
        }

        function _btSelectRow(d) {
          if (!_BT_TAPPABLE[d.state] || _btWindowState !== 'open') return;
          _btSelectedMac = d.mac;
          _btRenderList(_btDevices, null);
        }

        // Two gestures: a tap selects a row, the button pairs it.
        function _btSyncPairButton(adopting) {
          var okBtn = document.getElementById('btPairingOk');
          if (!okBtn) return;
          var selected = _btDevices.filter(function(d) { return d.mac === _btSelectedMac; })[0];
          var show = !adopting && _btWindowState === 'open' && selected && _BT_TAPPABLE[selected.state];
          okBtn.style.display = show ? '' : 'none';
          okBtn.textContent = 'Pair this device';
          okBtn.onclick = _btPairSelected;
        }

        function _btShowCountdown(remaining) {
          var el = document.getElementById('btWindowCountdown');
          if (!el) return;
          if (remaining === null || remaining === undefined) { el.textContent = ''; return; }
          var s = Math.max(0, remaining);
          el.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') + ' left';
        }

        function _btShowWindowError(message) {
          var el = document.getElementById('btWindowError');
          if (!el) return;
          el.textContent = message || '';
          el.style.display = message ? '' : 'none';
        }

        function _btOnWindowPoll(body) {
          if (!body || _btFinished) return;
          if (body.ok === false) {
            _btOnWindowError({status: body.error_status || 0}, body);
            return;
          }
          _btWindowState = body.state;
          if (body.state === 'open' || body.state === 'adopting') {
            _btDevices = body.devices || [];
            _btShowCountdown(body.remaining_s);
            _btRenderList(_btDevices, body.adopting);
            _btShowWindowError(body.last_error ? 'Pairing failed: ' + body.last_error : '');
            return;
          }
          if (body.state === 'closing') return;
          if (_btStartPending) { _btStartWindow(); return; }
          _btFinish(body);
        }

        function _btOnWindowError(res) {
          if (_btStatus(res) === 503) {
            _btWindowPoller.stop();
            _btShowResult(false, _BT_UNAVAILABLE);
          }
        }

        async function _btStartWindow() {
          _btStartPending = false;
          var res = await _btPost('/api/bluetooth/pair_window', {action: 'start'});
          var status = _btStatus(res);
          if (status === 409) {
            // The last window is still cleaning up; start again once it has.
            _btStartPending = true;
          } else if (status === 503 || status === 0) {
            _btShowResult(false, _BT_UNAVAILABLE);
            return;
          } else if (!res.body || res.body.ok !== true) {
            _btShowResult(false, (res.body && res.body.error) || 'Unable to start pairing.');
            return;
          }
          _btWindowPoller.start();
        }

        async function _btPairSelected() {
          var mac = _btSelectedMac;
          if (!mac) return;
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          var res = await _btPost('/api/bluetooth/pair', {address: mac});
          var status = _btStatus(res);
          if (status === 409) {
            _btShowWindowError('Another device is being paired.');
          } else if (status === 404) {
            _btShowWindowError('That device is no longer in the list.');
          } else if (!res.body || res.body.ok !== true) {
            _btShowWindowError((res.body && res.body.error) || 'Unable to start pairing.');
          }
          _btWindowPoller.refresh();
        }

        function _btFinish(body) {
          _btFinished = true;
          _btWindowPoller.stop();
          var close = body.last_close || {};
          if (close.reason === 'paired') {
            var msg = 'Paired with ' + _btDeviceName(_btSelectedMac) + ' (' + _btSelectedMac + ').';
            var auto = body.input_auto_configure;
            if (auto) {
              var inputLabel = auto.input === 'audio2' ? 'Input 2' : 'Input 1';
              if (auto.action === 'enabled') {
                msg += ' Bluetooth assigned to ' + inputLabel + '.';
              } else if (auto.action === 'device_set_only') {
                msg += ' Bluetooth set as ' + inputLabel + '\'s capture device -- enable it on the Setup page.';
              } else if (auto.action === 'notice' && auto.notice) {
                msg += ' ' + auto.notice;
              }
              if (auto.action === 'enabled' || auto.action === 'device_set_only') {
                _btApplyAutoConfigureToPage(auto);
              }
            }
            _btShowResult(true, msg);
            return;
          }
          var line = _BT_STOP_REASONS[close.reason] || 'Pairing stopped. Open it again.';
          if (close.error) line += ' (' + close.error + ')';
          _btShowResult(false, line);
        }

        function _btApplyAutoConfigureToPage(auto) {
          var inputIndex = auto.input === 'audio2' ? 2 : 1;
          var captureName = inputIndex === 2 ? 'audio2_capture_device' : 'audio_capture_device';
          var enabledName = inputIndex === 2 ? 'audio2_enabled' : 'audio1_enabled';
          var selectEl = document.querySelector('select[name="' + captureName + '"]');
          if (selectEl) {
            var hasLoopbackOption = Array.prototype.some.call(
              selectEl.options || [], function(opt) { return opt.value === BT_LOOPBACK_HW; }
            );
            if (hasLoopbackOption) selectEl.value = BT_LOOPBACK_HW;
          }
          // Relabel the loopback entries immediately with the just-paired
          // name; the periodic status poll re-applies the server's own
          // label afterwards.
          if (_btSelectedMac) {
            var pairedName = _btDeviceName(_btSelectedMac);
            document.querySelectorAll(
              'select[name="audio_capture_device"] option, select[name="audio2_capture_device"] option'
            ).forEach(function(opt) {
              if (opt.value === BT_LOOPBACK_HW) opt.textContent = 'Bluetooth: ' + pairedName;
            });
          }
          if (auto.action === 'enabled') {
            var enabledEl = document.querySelector('input[name="' + enabledName + '"]');
            if (enabledEl) enabledEl.checked = true;
          }
          if (typeof syncInputUi === 'function') syncInputUi(inputIndex);
          if (typeof refreshInputCardSubs === 'function') refreshInputCardSubs();
        }

        function _btShowResult(success, message) {
          _btFinished = true;
          _btShowPanel('Result');
          var titleEl = document.getElementById('btPairingModalTitle');
          var msgEl = document.getElementById('btResultMsg');
          var errEl = document.getElementById('btResultError');
          var okBtn = document.getElementById('btPairingOk');
          if (success) {
            if (titleEl) titleEl.textContent = 'Paired';
            if (msgEl) msgEl.textContent = message;
            if (errEl) errEl.style.display = 'none';
            btPaired = true;
            _btPairSucceeded = true;
            _btLinkState = 'connected';
            if (_btSelectEl && _btInputIndex) {
              _btSelectEl.value = BT_LOOPBACK_HW;
              _btSelectEl.dataset.prev = BT_LOOPBACK_HW;
              if (liveEnabled) {
                settingsSaveField('audio' + _btInputIndex + '.capture_device', BT_LOOPBACK_HW);
              }
              syncInputExclusivity(_btInputIndex, BT_LOOPBACK_HW);
            }
            _btRefreshLinkStatus();
            if (okBtn) { okBtn.style.display = ''; okBtn.textContent = 'Done'; okBtn.onclick = closeBtPairingModal; }
          } else {
            if (titleEl) titleEl.textContent = 'Pairing Stopped';
            if (msgEl) msgEl.textContent = '';
            if (errEl) { errEl.textContent = message; errEl.style.display = ''; }
            if (_btSelectEl && _btPriorSelectValue !== null) {
              _btSelectEl.value = _btPriorSelectValue;
            }
            if (okBtn) {
              okBtn.style.display = '';
              okBtn.textContent = 'Open Again';
              okBtn.onclick = function() { _btOpenWindow(); };
            }
          }
        }

        async function _btForgetCurrent() {
          if (!window.confirm('Forget the currently paired Bluetooth device?')) return;
          await _btPost('/api/bluetooth/forget', {});
          btPaired = false;
          _btLinkState = 'disconnected';
          _btRefreshLinkStatus();
          closeBtPairingModal();
        }

        function _btOpenWindow() {
          _btSelectedMac = null;
          _btDevices = [];
          _btWindowState = 'idle';
          _btFinished = false;
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Pair a device';
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          _btShowCountdown(null);
          _btShowWindowError('');
          _btRenderList([], null);
          _btShowPanel('Window');
          _btStartWindow();
        }

        function openBtPairingModal(inputIndex, selectEl) {
          _btInputIndex = inputIndex;
          _btSelectEl = selectEl || null;
          // Revert target is the last known-committed value (data-prev), not
          // .value -- by the time this fires the onchange event has already
          // set .value to the newly-selected (Bluetooth) option.
          _btPriorSelectValue = selectEl && selectEl.dataset.prev !== undefined ? selectEl.dataset.prev : null;
          _btPairSucceeded = false;
          var modal = document.getElementById('btPairingModal');
          if (!modal) return;
          var forgetBtn = document.getElementById('btPairingForget');
          if (forgetBtn) {
            forgetBtn.style.display = btPaired ? '' : 'none';
            forgetBtn.onclick = _btForgetCurrent;
          }
          modal.classList.add('show');
          _btOpenWindow();
        }

        function closeBtPairingModal() {
          _btWindowPoller.stop();
          _btStartPending = false;
          // Best effort: the window would close anyway once its heartbeat
          // (this screen's poll) stops.
          if (!_btFinished) _btPost('/api/bluetooth/pair_window', {action: 'stop'});
          _btFinished = true;
          // Cancel/dismiss without a successful pairing in this session: undo
          // the onchange event's already-committed selection change.  A no-op
          // when the select's value/data-prev already match (e.g. opening the
          // modal from the card's "Pair a device" button, which has no
          // associated select).
          if (_btSelectEl && !_btPairSucceeded && _btPriorSelectValue !== null) {
            _btSelectEl.value = _btPriorSelectValue;
            _btSelectEl.dataset.prev = _btPriorSelectValue;
          }
          var modal = document.getElementById('btPairingModal');
          if (modal) modal.classList.remove('show');
        }

        document.addEventListener('DOMContentLoaded', function() {
          var cancelBtn = document.getElementById('btPairingCancel');
          if (cancelBtn) cancelBtn.addEventListener('click', closeBtPairingModal);
          document.addEventListener('keydown', function(ev) {
            var m = document.getElementById('btPairingModal');
            if (ev.key === 'Escape' && m && m.classList.contains('show')) closeBtPairingModal();
          });
        });
