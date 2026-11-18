var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
        // -- Bluetooth input pairing --------------------------------------
        var BT_LOOPBACK_HW = pageData.bt_loopback_hw;
        var btPaired = pageData.bt_paired;
        var _btLinkState = pageData.bt_link_state;
        var _btScanTimer = null;
        var _btPairTimer = null;
        var _btInputIndex = null;
        var _btSelectEl = null;
        var _btSelectedMac = null;
        var _btSelectedName = null;
        var _btPriorSelectValue = null;
        var _btPairSucceeded = false;

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

        function _btPost(path, payload) {
          return _btFetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload || {})
          });
        }

        function _btShowPanel(name) {
          ['Scan', 'Confirm', 'Pairing', 'Result'].forEach(function(p) {
            var el = document.getElementById('bt' + p + 'Panel');
            if (el) el.style.display = (p === name) ? '' : 'none';
          });
        }

        async function btForgetFromCard() {
          if (!window.confirm('Forget the currently paired Bluetooth device?')) return;
          await _btPost('/api/bluetooth/forget', {});
          _btRefreshLinkStatus();
        }

        function _btStopScan() {
          if (_btScanTimer) { clearInterval(_btScanTimer); _btScanTimer = null; }
          _btPost('/api/bluetooth/scan', {action: 'stop'});
        }

        function _btRenderScanList(devices) {
          var list = document.getElementById('btScanDeviceList');
          if (!list) return;
          if (!devices || !devices.length) {
            list.innerHTML = '<p class="bt-scan-empty">Scanning\u2026</p>';
            return;
          }
          list.innerHTML = '';
          devices.forEach(function(d) {
            var row = document.createElement('div');
            row.className = 'bt-scan-row';
            var label = (d.name || d.mac || 'Unknown device');
            row.textContent = d.paired ? (label + ' (paired)') : label;
            row.addEventListener('click', function() { _btSelectDevice(d.mac, d.name || d.mac); });
            list.appendChild(row);
          });
        }

        async function _btPollScan() {
          var res = await _btFetch('/api/bluetooth/scan_results', {});
          var body = res.body;
          if (!body || body.ok === false) return;
          _btRenderScanList(body.devices || []);
        }

        async function _btStartScan() {
          _btShowPanel('Scan');
          var list = document.getElementById('btScanDeviceList');
          if (list) list.innerHTML = '<p class="bt-scan-empty">Scanning\u2026</p>';
          await _btPost('/api/bluetooth/scan', {action: 'start'});
          _btPollScan();
          if (_btScanTimer) { clearInterval(_btScanTimer); _btScanTimer = null; }
          _btScanTimer = setInterval(_btPollScan, 2000);
        }

        function _btSelectDevice(mac, name) {
          _btStopScan();
          _btSelectedMac = mac;
          _btSelectedName = name;
          var nameEl = document.getElementById('btConfirmDeviceName');
          if (nameEl) nameEl.textContent = name;
          var warnEl = document.getElementById('btConfirmWarning');
          if (warnEl) {
            if (btPaired) {
              warnEl.textContent = 'The currently paired device will be forgotten.';
              warnEl.style.display = '';
            } else {
              warnEl.style.display = 'none';
            }
          }
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) { okBtn.style.display = ''; okBtn.textContent = 'Pair'; okBtn.onclick = _btConfirmPair; }
          var forgetBtn = document.getElementById('btPairingForget');
          if (forgetBtn) forgetBtn.style.display = 'none';
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Confirm Pairing';
          _btShowPanel('Confirm');
        }

        async function _btConfirmPair() {
          _btShowPanel('Pairing');
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Pairing\u2026';
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          var res = await _btPost('/api/bluetooth/pair', {address: _btSelectedMac});
          if (res.status === 409) {
            _btShowResult(false, 'Pairing already in progress.');
            return;
          }
          if (res.status === 0 || (res.body && res.body.ok === false && res.status >= 400)) {
            _btShowResult(false, (res.body && res.body.error) || 'Unable to start pairing.');
            return;
          }
          if (_btPairTimer) { clearInterval(_btPairTimer); _btPairTimer = null; }
          _btPairTimer = setInterval(_btPollPairStatus, 2000);
        }

        async function _btPollPairStatus() {
          var res = await _btFetch('/api/bluetooth/pair_status', {});
          var body = res.body;
          if (!body || body.ok === false) return;
          if (body.state === 'done') {
            clearInterval(_btPairTimer); _btPairTimer = null;
            var msg = 'Paired with ' + (_btSelectedName || 'device') + '.';
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
          } else if (body.state === 'failed') {
            clearInterval(_btPairTimer); _btPairTimer = null;
            _btShowResult(false, body.error || 'Pairing failed.');
          }
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
          if (_btSelectedName) {
            document.querySelectorAll(
              'select[name="audio_capture_device"] option, select[name="audio2_capture_device"] option'
            ).forEach(function(opt) {
              if (opt.value === BT_LOOPBACK_HW) opt.textContent = 'Bluetooth: ' + _btSelectedName;
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
            if (titleEl) titleEl.textContent = 'Pairing Failed';
            if (msgEl) msgEl.textContent = '';
            if (errEl) { errEl.textContent = message; errEl.style.display = ''; }
            if (_btSelectEl && _btPriorSelectValue !== null) {
              _btSelectEl.value = _btPriorSelectValue;
            }
            if (okBtn) {
              okBtn.style.display = '';
              okBtn.textContent = 'Retry';
              okBtn.onclick = function() { _btStartScan(); };
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

        function openBtPairingModal(inputIndex, selectEl) {
          _btInputIndex = inputIndex;
          _btSelectEl = selectEl || null;
          // Revert target is the last known-committed value (data-prev), not
          // .value -- by the time this fires the onchange event has already
          // set .value to the newly-selected (Bluetooth) option.
          _btPriorSelectValue = selectEl && selectEl.dataset.prev !== undefined ? selectEl.dataset.prev : null;
          _btPairSucceeded = false;
          _btSelectedMac = null;
          _btSelectedName = null;
          var modal = document.getElementById('btPairingModal');
          if (!modal) return;
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Pair Bluetooth Turntable';
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          var forgetBtn = document.getElementById('btPairingForget');
          if (forgetBtn) {
            forgetBtn.style.display = btPaired ? '' : 'none';
            forgetBtn.onclick = _btForgetCurrent;
          }
          modal.classList.add('show');
          _btStartScan();
        }

        function closeBtPairingModal() {
          _btStopScan();
          if (_btPairTimer) { clearInterval(_btPairTimer); _btPairTimer = null; }
          // Cancel/dismiss without a successful pairing in this session: undo
          // the onchange event's already-committed selection change.  A no-op
          // when the select's value/data-prev already match (e.g. opening the
          // modal from the card's "Pair new device..." button, which has no
          // associated select, or after a failed pairing already reverted it
          // below in _btShowResult).
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
