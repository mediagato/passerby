/**
 * passerby selftest — prove the harness can tell the two cases apart.
 *
 * A security probe that cannot detect the bug it exists to find is worse than
 * no probe, because it reports PASS. So this stands up two fixtures and
 * requires passerby to disagree about them:
 *
 *   VULNERABLE  reflects the opaque Origin `null` back as ACAO — the
 *               reflect-any-non-http-origin pattern                  -> want FAIL
 *   SAFE        default-deny, ACAO only for loopback http origins     -> want PASS
 *
 * If both come back PASS the harness is blind. If both come back FAIL it is
 * crying wolf. Either way the selftest fails and the skill must not be trusted.
 *
 * Run:  node selftest.js            (plain node; it spawns Electron itself)
 */
'use strict';

const http = require('node:http');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const VULN_PORT = 8791;
const SAFE_PORT = 8792;

function findElectron() {
  const candidates = [
    path.join(__dirname, 'node_modules', 'electron'),
  ];
  for (const c of candidates) {
    try {
      const p = require(c);
      if (typeof p === 'string' && fs.existsSync(p)) return p;
    } catch {}
  }
  return null;
}

// The vulnerable pattern: any non-http origin reflected as-is.
const vulnerable = http.createServer((req, res) => {
  const o = req.headers.origin;
  const h = { 'content-type': 'application/json' };
  if (!o) h['access-control-allow-origin'] = '*';
  else if (/^https?:\/\//i.test(o)) {
    if (/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(o)) h['access-control-allow-origin'] = o;
  } else h['access-control-allow-origin'] = o;   // <-- the hole: `null` lands here
  h['access-control-allow-headers'] = 'content-type, x-passerby';
  h['access-control-allow-methods'] = 'GET, POST, OPTIONS';
  res.writeHead(req.method === 'OPTIONS' ? 204 : 200, h);
  res.end(req.method === 'OPTIONS' ? '' : JSON.stringify({ secret: 'CANARY-the-whole-store' }));
});

// The fixed behavior: default-deny.
const safe = http.createServer((req, res) => {
  const o = req.headers.origin;
  const h = { 'content-type': 'application/json' };
  if (!o) h['access-control-allow-origin'] = '*';
  else if (/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(o)) h['access-control-allow-origin'] = o;
  // everything else — `null`, file://, unknown schemes — gets no ACAO
  h['access-control-allow-headers'] = 'content-type, x-passerby';
  h['access-control-allow-methods'] = 'GET, POST, OPTIONS';
  res.writeHead(req.method === 'OPTIONS' ? 204 : 200, h);
  res.end(req.method === 'OPTIONS' ? '' : JSON.stringify({ secret: 'CANARY-the-whole-store' }));
});

// MUST be async. spawnSync blocks this process's event loop, and the two
// fixture servers live in THIS process — so a synchronous spawn means the
// fixtures cannot accept a single connection while Electron is running, and
// every target comes back "never answered". That is precisely the false VOID
// this skill exists to make impossible; the selftest caught it on first run.
function runPasserby(elec, targets) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.ELECTRON_RUN_AS_NODE; // or Electron degrades to bare node, silently
    const child = spawn(elec, [__dirname, '--targets', targets, '--wait', '9000'], { env });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const kill = setTimeout(() => { try { child.kill(); } catch {} }, 90000);
    child.on('close', () => {
      clearTimeout(kill);
      const m = out.match(/===PASSERBY_JSON===\s*([\s\S]*?)\s*===END===/);
      if (!m) return resolve({ error: 'no JSON block', raw: out.slice(-800) });
      try { resolve(JSON.parse(m[1])); } catch (e) { resolve({ error: 'bad JSON: ' + e.message }); }
    });
  });
}

(async () => {
  const elec = findElectron();
  if (!elec) { console.log('VOID: no Electron binary found — cannot self-test'); process.exit(2); }

  await new Promise((r) => vulnerable.listen(VULN_PORT, '127.0.0.1', r));
  await new Promise((r) => safe.listen(SAFE_PORT, '127.0.0.1', r));

  const res = await runPasserby(elec, `${VULN_PORT},${SAFE_PORT}`);
  vulnerable.close(); safe.close();

  if (res.error) { console.log('VOID:', res.error, res.raw || ''); process.exit(2); }

  const vf = (res.findings || []).find((f) => f.target.endsWith(':' + VULN_PORT));
  const sf = (res.findings || []).find((f) => f.target.endsWith(':' + SAFE_PORT));
  console.log('frame origin :', JSON.stringify(res.frameOrigin), '(opaque:', res.opaque + ')');
  console.log('control read :', res.controlReadable);
  console.log('vulnerable   :', vf && vf.verdict, '(want FAIL)');
  console.log('safe         :', sf && sf.verdict, '(want PASS)');

  const ok = vf && sf && vf.verdict === 'FAIL' && sf.verdict === 'PASS';
  if (!ok) {
    console.log('\nSELFTEST FAILED — the harness cannot tell a vulnerable service from a safe one.');
    console.log(JSON.stringify(res, null, 2));
    process.exit(1);
  }
  console.log('\nSELFTEST PASSED — passerby detects the hole and clears the fix.');
  process.exit(0);
})();
