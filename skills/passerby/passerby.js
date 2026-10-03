/**
 * passerby — what can a website you merely visited do to your local services?
 *
 * Runs under Electron so the verdict comes from a REAL Chromium, not from
 * reading headers and reasoning about them. Reading headers is how the bug this
 * exists to catch survived: `allowedOrigin()` in a local daemon reflected
 * the literal Origin `null` as trusted "local or native", and every review of
 * that code agreed with its comment instead of asking what a browser actually
 * sends. A sandboxed iframe on ANY site has an opaque origin that serializes to
 * exactly `null`.
 *
 * THE THREAT MODEL: not an attacker who broke in. A page the user merely
 * walked past, in a tab, with no install and no click.
 *
 * VERDICTS (three outcomes, because a broken probe must not read as good news):
 *   PASS  the passerby was blocked, AND the control proved the harness works
 *   FAIL  the passerby read or wrote the service
 *   VOID  we did not actually measure anything (no control, no Electron, dead
 *         target). VOID is the point: a blocked fetch and a broken probe look
 *         identical, and the broken one silently reads as good news.
 *
 * Usage (via the /passerby skill, or directly):
 *   env -u ELECTRON_RUN_AS_NODE <electron> <this-dir> --targets 3000,8080
 *
 * ELECTRON_RUN_AS_NODE is inherited from the VS Code host here and turns the
 * Electron binary into bare node — no window, no error, exit 0. Always strip it.
 */
'use strict';

const { app, BrowserWindow } = require('electron');
const http = require('node:http');

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  if (hit) return hit.split('=').slice(1).join('=');
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

const TARGETS = String(argOf('targets', '')).split(',').map((s) => s.trim()).filter(Boolean);
const CONTROL_PORT = parseInt(argOf('control-port', '8788'), 10);
const SITE_PORT = parseInt(argOf('site-port', '8789'), 10);
const WAIT_MS = parseInt(argOf('wait', '9000'), 10);

if (!TARGETS.length) {
  console.error('passerby: no --targets given (comma-separated ports or host:port)');
  app.exit(2);
}

const norm = (t) => (t.includes(':') ? t : /^\d+$/.test(t) ? `127.0.0.1:${t}` : `${t}:`);  // a bare name has no port: caught below

// Scope guard: this tool probes loopback services on the machine it runs on. A target on another host
// is refused unless the user says so, so a typo cannot aim it at a network it was not meant for.
const LOOPBACK_HOST = /^(127\.0\.0\.1|localhost|\[::1\])$/i;
const remote = TARGETS.filter((t) => !LOOPBACK_HOST.test(norm(t).replace(/:\d+$/, '')));
const portless = TARGETS.filter((t) => /:$/.test(norm(t)));
if (portless.length) {
  console.error(`passerby: a target needs a port: ${portless.join(', ')} (use a port number or host:port)`);
  app.exit(2);
}
if (remote.length && !argv.includes('--allow-remote')) {
  console.error(`passerby: refusing non-loopback target(s): ${remote.join(', ')}. Pass --allow-remote to probe a host you control.`);
  app.exit(2);
}
const lines = [];

// ── the control ────────────────────────────────────────────────────────────
// Deliberately permissive: reflects whatever Origin it is handed, including the
// opaque `null`. If the passerby cannot read THIS, the harness is broken and
// every "blocked" result in the same run is meaningless.
// It also ECHOES the Origin it saw on the wire. `location.origin` inside a
// sandboxed frame is not trustworthy for this — Chromium reports the
// URL-derived origin there while still sending `Origin: null` on the wire, so
// reading it would say "not opaque" about a frame that demonstrably is. The
// only reliable witness is a server saying what it received.
const control = http.createServer((req, res) => {
  res.writeHead(200, {
    'access-control-allow-origin': req.headers.origin || '*',
    'access-control-allow-headers': 'content-type, x-passerby',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-private-network': 'true',
    'content-type': 'application/json',
  });
  res.end(JSON.stringify({
    control: 'ok',
    observedOrigin: req.headers.origin === undefined ? '<ABSENT>' : req.headers.origin,
  }));
});

// ── the "website" ──────────────────────────────────────────────────────────
// A page with a sandboxed iframe. sandbox="allow-scripts" WITHOUT
// allow-same-origin is what makes the frame's origin opaque — the whole trick.
const PAGE = `<!doctype html><meta charset="utf-8"><title>passerby</title>
<iframe sandbox="allow-scripts" src="/frame.html" style="display:none"></iframe>`;

const frameHtml = () => `<!doctype html><meta charset="utf-8"><script>
const say = (m) => console.log('[PASSERBY] ' + m);
const TARGETS = ${JSON.stringify(TARGETS.map(norm))};
const CONTROL = 'http://127.0.0.1:${CONTROL_PORT}/control';

async function probe(label, url, init) {
  try {
    const r = await fetch(url, init);
    const body = await r.text();
    let observed = null;
    try { observed = JSON.parse(body).observedOrigin; } catch {}
    say(JSON.stringify({ label, url, outcome: 'READ', status: r.status, bytes: body.length, observed }));
  } catch (e) {
    say(JSON.stringify({ label, url, outcome: 'BLOCKED', error: String(e.message || e) }));
  }
}

(async () => {
  // Reported for completeness only — NOT used for the verdict. A sandboxed
  // frame can report a non-opaque location.origin while sending Origin: null.
  say(JSON.stringify({ label: 'origin', value: location.origin }));
  // the control FIRST — if this does not read, nothing below means anything
  await probe('control', CONTROL);
  for (const t of TARGETS) {
    const base = 'http://' + t;
    await probe('read:' + t, base + '/');
    await probe('preflight-read:' + t, base + '/', { headers: { 'x-passerby': '1' } });
    await probe('write:' + t, base + '/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passerby: true }),
    });
  }
  say('DONE');
})();
</script>`;

const site = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(req.url === '/frame.html' ? frameHtml() : PAGE);
});

// ── verdict ────────────────────────────────────────────────────────────────
function verdict() {
  const events = lines
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const controlEv = events.find((e) => e.label === 'control');
  const originEv = events.find((e) => e.label === 'origin');
  const controlRead = controlEv && controlEv.outcome === 'READ';

  // The wire origin, witnessed by the control server. If the passerby is not
  // presenting the opaque `null`, it is not simulating a passing website and
  // every "blocked" below is about some other request than the one we mean.
  const wireOrigin = controlEv ? controlEv.observed : undefined;
  const trulyOpaque = wireOrigin === 'null';

  const findings = [];
  for (const t of TARGETS.map(norm)) {
    const mine = events.filter((e) => e.label && e.label.endsWith(':' + t));
    if (!mine.length) {
      findings.push({ target: t, verdict: 'VOID', why: 'no probe results — target never answered' });
      continue;
    }
    const readable = mine.filter((e) => e.outcome === 'READ');
    if (!controlRead) {
      findings.push({ target: t, verdict: 'VOID', why: 'the control was not readable — harness cannot discriminate' });
    } else if (!trulyOpaque) {
      findings.push({
        target: t,
        verdict: 'VOID',
        why: `the probe presented Origin ${JSON.stringify(wireOrigin)}, not the opaque "null" — it is not acting as a passerby, so a block proves nothing`,
      });
    } else if (readable.length) {
      findings.push({
        target: t,
        verdict: 'FAIL',
        why: 'a passerby read or wrote this service',
        exposed: readable.map((e) => ({ probe: e.label.split(':')[0], status: e.status, bytes: e.bytes })),
      });
    } else {
      findings.push({ target: t, verdict: 'PASS', why: 'every passerby probe was blocked, control readable' });
    }
  }

  return {
    frameOrigin: originEv ? originEv.value : null,   // what the frame THINKS (unreliable)
    wireOrigin: wireOrigin === undefined ? null : wireOrigin, // what the server SAW (authoritative)
    opaque: trulyOpaque,
    controlReadable: !!controlRead,
    findings,
  };
}

app.on('window-all-closed', () => {});

app.whenReady().then(() => {
  control.listen(CONTROL_PORT, '127.0.0.1', () => {
    site.listen(SITE_PORT, '127.0.0.1', () => {
      const win = new BrowserWindow({ show: false, webPreferences: { contextIsolation: true, nodeIntegration: false } });
      let done = false;
      win.webContents.on('console-message', (_e, _lvl, message) => {
        if (!message.startsWith('[PASSERBY] ')) return;
        const payload = message.slice('[PASSERBY] '.length);
        if (payload === 'DONE') { done = true; finish(); return; }
        lines.push(payload);
      });
      win.loadURL(`http://127.0.0.1:${SITE_PORT}/`);
      const timer = setTimeout(() => { if (!done) finish(); }, WAIT_MS);
      function finish() {
        clearTimeout(timer);
        const out = verdict();
        console.log('===PASSERBY_JSON===');
        console.log(JSON.stringify(out, null, 2));
        console.log('===END===');
        const worst = out.findings.some((f) => f.verdict === 'FAIL') ? 1
          : out.findings.some((f) => f.verdict === 'VOID') ? 2 : 0;
        app.exit(worst); // 0 PASS · 1 FAIL · 2 VOID
      }
    });
  });
});
