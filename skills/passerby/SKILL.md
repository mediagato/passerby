---
name: passerby
description: >-
  Finds out what a website the user merely VISITED can do to a local service — read it, write it,
  export it — by driving a real Chromium from an opaque (sandboxed-iframe) origin, with a mandatory
  positive control so a blocked fetch can never be confused with a broken probe. Verdicts are PASS /
  FAIL / VOID. Use when: shipping or reviewing anything that listens on loopback, auditing a daemon's
  CORS/origin policy, after touching an allowedOrigin/ACAO/Access-Control code path, or when asked
  "can a website reach this port", "is this localhost service exposed", "check the CORS on X", "run
  passerby". Not a general port scanner and not a pentest — it answers exactly one question, the one
  that leaves a local store readable by any website when its origin policy trusts "null".
---

# /passerby — what can a website you merely walked past do to this port?

A user visits a page. They install nothing, click nothing, grant nothing.
That page runs JavaScript, and that JavaScript can reach `127.0.0.1`. The only
thing standing between it and every local service is the service's own origin
policy — and the failure mode is silent, because a service with a broken policy
looks exactly like a service with a good one until someone actually asks a
browser.

This skill asks a browser.

## Why it exists

One local daemon's `allowedOrigin()` reflected the literal origin string `null` back as `Access-Control-Allow-Origin`, on the reasoning — written in a comment, reviewed, tested, shipped — that non-http schemes could only come from local or native surfaces, never a hostile remote page.

That is wrong about `null`. A sandboxed iframe (`<iframe sandbox="allow-scripts">`),
a `data:` document, or any CSP-sandboxed page has an **opaque origin**, which
serializes to exactly `null`. Any website can make one. So any website the user visited could read every record, export the whole store in one request, or write entries indistinguishable from the user's own.

Three independent checks all agreed it was fine:

- The **anti-DNS-rebinding Host gate** was sound — and irrelevant. The request
  carries a genuine loopback `Host`; it is not a rebinding attack.
- The **content-type CSRF gate** and a custom-header gate on a write endpoint were sound — and both fall the moment the preflight is granted.
- The **test suite pinned the vulnerable behavior as correct**
  (a unit test asserted that `file://` was reflected as trusted).

Reading headers and reasoning about them is what produced all three. Only
driving a real browser settles it.

## What it does

Spawns Electron (a real Chromium), serves a page containing a sandboxed iframe,
and from that opaque origin attempts against each target port:

| probe | what it answers |
|---|---|
| `read` | can a passerby read a response body at all? |
| `preflight-read` | is a preflight granted (which defeats content-type/custom-header CSRF gates)? |
| `write` | can a passerby POST into the service? |

**Any readable response is a FAIL**, including a 404 — a readable 404 means the
origin was trusted, and the same trust applies to every other route, including any export route.

## The three verdicts

A probe has three outcomes, not two, because a blocked fetch and a broken
probe look identical:

- **PASS** — every probe blocked, *and* the control proved the harness works.
- **FAIL** — a passerby read or wrote the service.
- **VOID** — nothing was actually measured. Exit code 2, distinct from FAIL's 1.

Two things force VOID rather than a false PASS:

1. **The control.** A deliberately permissive server runs inside the same
   harness and is probed first. If the passerby cannot read *that*, then every
   "blocked" in the run is meaningless and the whole thing is VOID.
2. **The wire origin.** The control server echoes back the `Origin` header it
   actually received. If it is not `null`, the probe is not acting as a
   passerby, and a block proves nothing about passersby. VOID.

That second guard exists because **`location.origin` lies**: inside a sandboxed
frame Chromium reports the URL-derived origin (`http://127.0.0.1:8789`) while
sending `Origin: null` on the wire. Trusting the frame's self-report would have
declared a genuinely opaque probe "not opaque". Only a server saying what it
received is authoritative.

## Procedure

1. **Find the targets.** Either take the ports the user names, or enumerate listeners:
   `netstat -ano | grep LISTENING` (Windows), `ss -ltn` (Linux) or
   `lsof -nP -iTCP -sTCP:LISTEN` (macOS). Probe only loopback services on machines
   the user controls. The tool refuses a non-loopback target unless `--allow-remote`
   is passed.
2. **Self-test first if the harness has been touched.**
   `cd skills/passerby && npm install --no-save electron@32.3.3 && node selftest.js`
   It stands up a deliberately vulnerable fixture and a safe one and requires
   passerby to return FAIL and PASS respectively. A probe that cannot detect
   the bug it exists to find is worse than none, because it reports PASS.
3. **Run it.**
   ```bash
   cd skills/passerby
   ELEC=$(node -p "require('electron')")
   env -u ELECTRON_RUN_AS_NODE "$ELEC" . --targets 3000,8080
   ```
   Flags: `--targets` (comma-separated ports or `host:port`), `--wait` (ms,
   default 9000), `--control-port`, `--site-port`, `--allow-remote` (permit a
   non-loopback host that you control).
4. **Report per target**, and for a FAIL say plainly what a visited page can do
   — read / write / export — not just "CORS misconfigured". The user-facing
   consequence is the finding.

## Traps

- **`ELECTRON_RUN_AS_NODE` can be inherited from the VS Code host.** It turns
  the Electron binary into bare node: no window, no error, exit 0, empty
  output. Always `env -u ELECTRON_RUN_AS_NODE`. Shell state does not persist
  between tool calls, so strip it in the same invocation every time.
- **Never run the fixtures and `spawnSync` in one process.** `spawnSync` blocks
  the event loop, so in-process fixture servers cannot accept a connection
  while Electron runs and every target reports "never answered" — a false VOID.
  The selftest caught exactly this on its first run; it uses async `spawn`.
- **A readable 404 is a FAIL.** Do not dismiss it because the path did not
  exist. The disclosure is that ACAO was granted.
- **Extension origins are not the same class as `null`.** A page cannot forge
  `chrome-extension://<id>` — the browser sets it — so trusting that scheme is
  a real (if loose) boundary. `null` is forgeable by anyone. Do not "fix" a
  FAIL by also banning extension origins unless no legitimate extension needs
  access; a product that ships a companion extension would break without the hole closing.

## Related

- The rule behind the three verdicts: no negative result without a positive
  control that proves the harness can find the thing it reports absent.
- A sandboxed iframe (`<iframe sandbox="allow-scripts">`) sends `Origin: null`;
  any site can create one.
