function buildOutputCardElement(o) {
  var id = String(o.id || '');
  var name = String(o.name || ('Output ' + id));
  var selected = !!o.selected;
  var volume = normalizeVolume(o.volume);
  var isDefault = !!o.is_default;
  var remoteInUse = !!o.remote_in_use;
  var remoteOwner = String(o.remote_owner || '');

  var card = document.createElement('div');
  card.className = 'output-card ' + (remoteInUse ? 'output-card-in-use' : (selected ? 'output-card-on' : 'output-card-off'));
  card.id = 'output_card_' + id;
  card.setAttribute('data-output-id', id);
  card.setAttribute('data-is-default', isDefault ? '1' : '0');
  card.setAttribute('data-remote-in-use', remoteInUse ? '1' : '0');
  card.setAttribute('data-remote-owner', remoteOwner);

  var head = document.createElement('div');
  head.className = 'output-card-head';

  var meta = document.createElement('div');
  meta.className = 'output-card-meta';
  var nameDiv = document.createElement('div');
  nameDiv.className = 'output-card-name';
  nameDiv.textContent = name;
  meta.appendChild(nameDiv);
  if (isDefault) {
    var badge = document.createElement('span');
    badge.className = 'output-card-default';
    badge.textContent = 'Default';
    meta.appendChild(badge);
  }
  var chip = document.createElement('span');
  chip.className = 'output-state-chip ' + (remoteInUse ? 'in-use' : (selected ? 'on' : 'off'));
  chip.id = 'output_state_' + id;
  chip.textContent = remoteInUse ? ('In Use by ' + (remoteOwner || 'another appliance')) : (selected ? 'On' : 'Off');
  meta.appendChild(chip);
  head.appendChild(meta);

  var toggle = document.createElement('label');
  toggle.className = 'output-toggle';
  toggle.addEventListener('click', function(e) { e.stopPropagation(); });
  var cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.id = 'output_enabled_' + id;
  cb.checked = selected;
  if (remoteInUse) cb.disabled = true;
  cb.addEventListener('change', function() { onToggleOutput(id); });
  toggle.appendChild(cb);
  var sw = document.createElement('span');
  sw.className = 'switch';
  sw.setAttribute('aria-hidden', 'true');
  toggle.appendChild(sw);
  head.appendChild(toggle);
  card.appendChild(head);

  var wrap = document.createElement('div');
  wrap.className = 'output-slider-wrap';
  wrap.id = 'output_slider_wrap_' + id;
  wrap.addEventListener('click', function(e) { e.stopPropagation(); });
  if (!selected) wrap.hidden = true;
  var sliderHdr = document.createElement('div');
  sliderHdr.className = 'slider-header';
  var volText = document.createElement('span');
  volText.textContent = 'Volume:';
  sliderHdr.appendChild(volText);
  var volLbl = document.createElement('span');
  volLbl.id = 'vol_label_' + id;
  volLbl.setAttribute('data-volume-label-for', id);
  sliderHdr.appendChild(volLbl);
  wrap.appendChild(sliderHdr);
  var sl = document.createElement('input');
  sl.type = 'range';
  sl.id = 'vol_slider_' + id;
  sl.min = 0; sl.max = 100; sl.step = 1; sl.value = volume;
  sl.addEventListener('input', function() { updateVolumeLabel(id, this.value); });
  sl.addEventListener('change', function() { onVolumeChange(id, this.value); });
  wrap.appendChild(sl);
  card.appendChild(wrap);

  return card;
}

function setOutputsPlaceholder(state) {
  var el = document.getElementById('outputs-placeholder');
  if (!el) return;
  if (state === 'hidden') {
    el.hidden = true;
    el.textContent = '';
  } else if (state === 'unreachable') {
    el.hidden = false;
    el.textContent = 'Waiting for owntone';
  } else {
    el.hidden = false;
    el.textContent = 'Waiting for device discovery';
  }
}

function renderOutputList(outputs) {
  var list = document.getElementById('outputs-list');
  if (!list) return;
  while (list.firstChild) list.removeChild(list.firstChild);
  for (var i = 0; i < outputs.length; i++) { list.appendChild(buildOutputCardElement(outputs[i])); }
  list.querySelectorAll('[data-volume-label-for]').forEach(function(s) {
    var id = s.getAttribute('data-volume-label-for');
    var sl = document.getElementById('vol_slider_' + id);
    if (sl) updateVolumeLabel(id, sl.value);
    var cb = document.getElementById('output_enabled_' + id);
    if (cb) updateOutputStateVisual(String(id), !!cb.checked);
  });
  reorderOutputCards();
  updateMasterVolumeCard();
  setOutputsPlaceholder(outputs.length > 0 ? 'hidden' : 'empty');
}
