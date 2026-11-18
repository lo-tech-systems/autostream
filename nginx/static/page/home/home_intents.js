// Everything Home asks the appliance to do goes through submit().
let reloading = false;
let base = '/api/v1';

// The path the intents go to: this appliance's, or the relay's for another.
export const setBase = (b) => { base = b; };

// POST <base>/intents/<name> with { args }; resolves with the reply
// ({ ok, error, version, result, ... }). A rejected session reloads the page
// once, so the sign-in or the new token takes effect.
export async function submit(name, args = {}) {
  const r = await fetch(base + '/intents/' + name, {
    method: 'POST',
    credentials: 'same-origin',
    signal: AbortSignal.timeout(5000),
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.__CSRF || '' },
    body: JSON.stringify({ args }),
  });
  if ((r.status === 401 || r.status === 403) && !reloading) {
    reloading = true;
    window.location.reload();
  }
  try { return await r.json(); } catch (e) { return { ok: false, error: 'bad_reply', version: null, result: {} }; }
}
