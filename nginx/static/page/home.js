        function getOutputIdKey(outputs) {
          return JSON.stringify(outputs.map(function(o) {
            return String(o.id) + '|' + String(!!o.remote_in_use) + '|' + String(o.remote_owner || '');
          }).sort());
        }
        function onStatusPollData(d) {
          renderNowPlayingCard(d);
          updateRepeatButton(d);
          ['stylus', 'belt', 'bearing', 'dial_update', 'sample_rate'].forEach(function(item) {
            var el = document.getElementById(item.replace('_', '-') + '-warning-banner');
            if (!el) return;
            var key = item === 'stylus' ? 'playback_banner_text' : item + '_banner_text';
            var txt = String((d && d[key]) || '').trim();
            el.style.display = txt ? 'block' : 'none';
            el.textContent = txt;
            if (item === 'sample_rate' && txt) {
              // The link follows the input that is mismatching.
              var idx = 0;
              var lv = (d && Array.isArray(d.input_levels)) ? d.input_levels : [];
              for (var i = 0; i < lv.length; i++) {
                if (lv[i] && Number(lv[i].rate_mismatch_hz) > 0) {
                  var n = Number.isFinite(Number(lv[i].index)) ? Number(lv[i].index) : i + 1;
                  if (idx === 0 || n < idx) idx = n;
                }
              }
              el.href = '/setup#input' + (idx || 1);
            }
          });
        }
        function onOutputsPollData(j) {
          var __list = document.getElementById('outputs-list');
          var __domIds = __list ? Array.from(__list.querySelectorAll('.output-card[data-output-id]')).map(function(c) {
            return c.getAttribute('data-output-id') + '|' + (c.getAttribute('data-remote-in-use') === '1' ? 'true' : 'false') + '|' + (c.getAttribute('data-remote-owner') || '');
          }) : [];
          var domKey = __domIds.length > 0 ? JSON.stringify(__domIds.sort()) : '';
          if (!j || !j.ok) {
            if (domKey === '') { setOutputsPlaceholder('unreachable'); }
            return;
          }
          if (!Array.isArray(j.outputs)) {
            // Outputs unknown (field missing despite an ok reply): leave the
            // DOM untouched and freeze the empty-tolerance timer rather than
            // treating this as a confirmed empty outputs list.
            return;
          }
          if (typeof maybePromptForPin === 'function') {
            try { maybePromptForPin(j.outputs); } catch (e) {}
          }
          try { maybeShowStartFailure(j.start_failure, { storageKey: 'autostream.startFailureSeen', ownRequester: 'webui' }); } catch (e) {}
          var outputs = j.outputs;
          if (outputs.length === 0) {
            if (window.__OUTPUTS_EMPTY_SINCE == null) { window.__OUTPUTS_EMPTY_SINCE = Date.now(); }
            if (domKey !== '' && (Date.now() - window.__OUTPUTS_EMPTY_SINCE) < window.__OUTPUTS_EMPTY_TOLERANCE_MS) {
              return;
            }
          } else {
            window.__OUTPUTS_EMPTY_SINCE = null;
          }
          var targetKey = outputs.length > 0 ? getOutputIdKey(outputs) : '';
          if (targetKey === domKey) {
            if (targetKey === '') {
              setOutputsPlaceholder('empty');
            } else {
              setOutputsPlaceholder('hidden');
              for (const o of outputs) {
                const id = String(o.id);
                if (window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.has(id)) continue;
                const cb = document.getElementById("output_enabled_" + id);
                const sl = document.getElementById("vol_slider_" + id);
                if (cb) cb.checked = !!o.selected;
                updateOutputStateVisual(id, !!o.selected);
                if (sl && !isActiveControl(sl)) {
                  const v = normalizeVolume(o.volume);
                  const vstr = String(v);
                  if (sl.value !== vstr) sl.value = vstr;
                  updateVolumeLabel(id, v);
                }
              }
              reorderOutputCards();
              if (!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
            }
            return;
          }
          var hasPending = window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.size > 0;
          var masterActive = isActiveControl(document.getElementById('master_vol_slider'));
          var pinVisible = !!(document.getElementById('pinModal') && document.getElementById('pinModal').classList.contains('show'));
          var anySliderActive = !!(document.activeElement && document.activeElement.id && document.activeElement.id.startsWith('vol_slider_'));
          if (!hasPending && !masterActive && !pinVisible && !anySliderActive) {
            renderOutputList(outputs);
            return;
          }
          if (domKey !== '') { setOutputsPlaceholder('hidden'); }
          for (const o of outputs) {
            const id = String(o.id);
            if (window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.has(id)) continue;
            const cb = document.getElementById("output_enabled_" + id);
            const sl = document.getElementById("vol_slider_" + id);
            if (cb) cb.checked = !!o.selected;
            updateOutputStateVisual(id, !!o.selected);
            if (sl && !isActiveControl(sl)) {
              const v = normalizeVolume(o.volume);
              const vstr = String(v);
              if (sl.value !== vstr) sl.value = vstr;
              updateVolumeLabel(id, v);
            }
          }
          reorderOutputCards();
          if (!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
        }

        window.addEventListener('DOMContentLoaded',function(){
          window.__PENDING_OUTPUTS = new Set();
          window.__PIN_DISMISSED = new Set();
          window.__PIN_PROMPT_ACTIVE = false;
          window.__MASTER_DRAG_SNAPSHOTS = {};
          window.__MASTER_DRAG_BASE = 0;
          document.querySelectorAll('[data-volume-label-for]').forEach(s=>{
            var i=s.getAttribute('data-volume-label-for'), sl=document.getElementById('vol_slider_'+i);
            if(sl)updateVolumeLabel(i, sl.value);
            var cb=document.getElementById('output_enabled_'+i);
            if(cb) updateOutputStateVisual(String(i), !!cb.checked);
          });
          reorderOutputCards();
          updateMasterVolumeCard();
          window.__OUTPUTS_EMPTY_SINCE = null;
          setInterval(vuRenderTick, VU_BIN_MS);
          initApplianceSelector();
          refreshApplianceSelector();
          setInterval(function(){if(!document.hidden) refreshApplianceSelector();},15000);
          document.addEventListener('visibilitychange',function(){if(!document.hidden) refreshApplianceSelector();});
          Poller({ url: '/api/status', intervalMs: 1500, onData: onStatusPollData });
          Poller({ url: '/api/owntone/outputs_state', intervalMs: 1500, timeoutMs: 5000, onData: onOutputsPollData });
        });
function navigateToRemoteAppliance(hostname){fetch('/api/appliances',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){if(!data||!data.ok||!Array.isArray(data.appliances))return;var appliance=data.appliances.find(function(a){return String(a.hostname||'').toLowerCase()===String(hostname||'').toLowerCase();});if(appliance){window.location.href='/a/'+String(appliance.id)+'/';}}).catch(function(){});}document.addEventListener('DOMContentLoaded',function(){var list=document.getElementById('outputs-list');if(!list)return;list.addEventListener('click',function(e){if(!window.__CONTROL_OTHER_APPLIANCES)return;var card=e.target.closest('.output-card[data-remote-in-use="1"]');if(!card)return;if(e.target.closest('.output-toggle')||e.target.closest('.output-slider-wrap'))return;var owner=card.getAttribute('data-remote-owner');if(owner)navigateToRemoteAppliance(owner);});});
