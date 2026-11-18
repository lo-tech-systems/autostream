// "Could not start <speaker>" for one appliance's speaker list. Each
// (boot, seq) is shown once per tab and appliance, across that tab's
// reloads; a failure already old on the first reading after loading is
// not news. No queue: while another dialog is open the notice waits for the
// next reading, which still has the same failure.
//
// maybeShowStartFailure(f, opts), with f the reply's start_failure object
// (or nothing) and opts:
//   storageKey    sessionStorage key for this appliance's last seen (boot, seq)
//   ownRequester  the requester whose PIN request opens this page's PIN
//                 dialog ('webui' on an appliance's own page), or null on a
//                 page with no PIN dialog, where both PIN reasons are silent
var START_FAILURE_MAX_AGE_S = 30;
var START_FAILURE_HANDLED_MS = 15000;
var __startFailureFirst = {};
var __startFailureSeenMem = {};

function startFailureText(reason) {
  if (reason === 'refused') return 'The speaker turned down the request to play. Check that it is switched on and not in use by another app, then try again.';
  if (reason === 'failed') return 'The speaker did not start. autostream keeps trying while the music plays.';
  if (reason === 'timed_out') return 'The speaker did not answer in time. Check that it is switched on and connected to the network.';
  if (reason === 'encoder_capacity') return 'The appliance cannot encode another stream at the chosen quality. Turn another speaker off or choose a lighter audio mode.';
  return 'The speaker did not start.';
}

function startFailureSeen(f, key) {
  var m = __startFailureSeenMem[key];
  if (m && m.boot === f.boot && f.seq <= m.seq) return true;
  try {
    var s = JSON.parse(sessionStorage.getItem(key));
    if (s && s.boot === f.boot && f.seq <= s.seq) return true;
  } catch (e) {}
  return false;
}

function markStartFailureSeen(f, key) {
  __startFailureSeenMem[key] = { boot: f.boot, seq: f.seq };
  try { sessionStorage.setItem(key, JSON.stringify(__startFailureSeenMem[key])); } catch (e) {}
}

function startFailureDialogShown() {
  return ['infoModal', 'pinModal'].some(function(id) {
    var el = document.getElementById(id);
    return !!(el && el.classList.contains('show'));
  });
}

function maybeShowStartFailure(f, opts) {
  var key = opts.storageKey;
  var first = __startFailureFirst[key] !== false;
  __startFailureFirst[key] = false;
  if (!f || startFailureSeen(f, key)) return;
  if (first && f.age_s > START_FAILURE_MAX_AGE_S) { markStartFailureSeen(f, key); return; }
  // A wrong PIN: the PIN dialog of the tab that asked asks again by itself.
  if (f.reason === 'pin_invalid') { markStartFailureSeen(f, key); return; }
  // A PIN request for a start this page asked for opens the PIN dialog
  // (its own guards apply); one from a dial or a peer is theirs to answer.
  if (f.reason === 'pin_required') {
    markStartFailureSeen(f, key);
    if (opts.ownRequester && f.requester === opts.ownRequester && typeof maybePromptForPin === 'function') {
      try { maybePromptForPin([{ id: f.unit_id, name: f.name, pin_pending: true, pin_claim: opts.ownRequester }]); } catch (e) {}
    }
    return;
  }
  // The switch's own reply has already told the user about the CPU limit.
  var handled = window.__HANDLED_FAILURE && window.__HANDLED_FAILURE[String(f.unit_id)];
  if (f.reason === 'encoder_capacity' && handled && (Date.now() - handled) < START_FAILURE_HANDLED_MS) {
    markStartFailureSeen(f, key);
    return;
  }
  if (startFailureDialogShown()) return;
  markStartFailureSeen(f, key);
  showInfoModal('Could not start ' + f.name, startFailureText(f.reason));
}
