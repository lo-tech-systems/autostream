// SHA-256 helper.
// Prefer WebCrypto when available, but fall back to a small JS implementation
// because many browsers (notably iOS Safari / standalone mode) do not expose
// crypto.subtle on plain HTTP origins.
function _rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function _toHex32(x) { return (x >>> 0).toString(16).padStart(8, '0'); }

function sha256HexFallback(msg) {
// Minimal SHA-256 implementation (Uint8Array in, hex out).
const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

// Encode as UTF-8 bytes
const bytes = new TextEncoder().encode(msg);
const bitLenHi = Math.floor((bytes.length * 8) / 0x100000000);
const bitLenLo = (bytes.length * 8) >>> 0;

// Padding: 0x80, then zeros, then 64-bit length
const withOne = bytes.length + 1;
const padLen = (withOne % 64 <= 56) ? (56 - (withOne % 64)) : (56 + (64 - (withOne % 64)));
const totalLen = bytes.length + 1 + padLen + 8;
const buf = new Uint8Array(totalLen);
buf.set(bytes, 0);
buf[bytes.length] = 0x80;
// length (big-endian)
const dv = new DataView(buf.buffer);
dv.setUint32(totalLen - 8, bitLenHi);
dv.setUint32(totalLen - 4, bitLenLo);

// Initial hash values
let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
let h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

const W = new Uint32Array(64);
for (let i = 0; i < buf.length; i += 64) {
    for (let t = 0; t < 16; t++) {
    W[t] = dv.getUint32(i + t*4);
    }
    for (let t = 16; t < 64; t++) {
    const s0 = (_rotr(W[t-15],7) ^ _rotr(W[t-15],18) ^ (W[t-15] >>> 3)) >>> 0;
    const s1 = (_rotr(W[t-2],17) ^ _rotr(W[t-2],19) ^ (W[t-2] >>> 10)) >>> 0;
    W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }

    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let t = 0; t < 64; t++) {
    const S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
    const S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const temp2 = (S0 + maj) >>> 0;
    h=g; g=f; f=e; e=(d + temp1) >>> 0;
    d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
}

return _toHex32(h0)+_toHex32(h1)+_toHex32(h2)+_toHex32(h3)+_toHex32(h4)+_toHex32(h5)+_toHex32(h6)+_toHex32(h7);
}

async function sha256Hex(s) {
// WebCrypto path (fast) when available
if (window.crypto && crypto.subtle && window.isSecureContext) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', enc.encode(s));
    const arr = Array.from(new Uint8Array(buf));
    return arr.map(b => b.toString(16).padStart(2,'0')).join('');
}
// Fallback path (works on HTTP)
return sha256HexFallback(s);
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
e.preventDefault();

const pin = (document.getElementById('pin').value || '').trim();
const nextPath = decodeURIComponent(document.getElementById('next').value || '%2F');
const nonce = document.getElementById('nonce').value || '';

// Client-side input validation to match server rules.
const re = /^[A-Za-z0-9-]{4,20}$/;
if (!re.test(pin)) {
    // Mirror server error banner style by reloading with err=1.
    window.location.href = '/auth?next=' + encodeURIComponent(nextPath) + '&err=1';
    return;
}

const proof = await sha256Hex(nonce + pin);

const res = await fetch('/api/auth/verify', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({nonce: nonce, proof: proof, next: nextPath})
});

if (res.ok) {
    const j = await res.json();
    window.location.href = (j && j.next) ? j.next : nextPath;
    return;
}

// Incorrect PIN (or any auth failure): reload with error banner.
window.location.href = '/auth?next=' + encodeURIComponent(nextPath) + '&err=1';
});
