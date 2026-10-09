---
name: passerby
type: tool
status: experimental
license: MIT
version: 0.1.2
summary: A Claude skill that finds out what a website you merely visited can do to a service on localhost, using a real Chromium and a control that proves the probe can see a hole.
updated: 2026-10-08
verified: 2026-10-08
---

# passerby

You visit a web page. You install nothing, click nothing, grant nothing. That page runs JavaScript, and that JavaScript can reach `127.0.0.1`. The only thing between it and every local service on your machine is each service's own origin policy.

A service with a broken policy looks exactly like a service with a good one until someone asks a browser. `passerby` asks a browser.

## What it does

It starts Electron (a real Chromium), serves a page containing a sandboxed iframe, and from that iframe's opaque origin tries three things against each port you name:

| Probe | Question |
|---|---|
| `read` | Can a passerby read a response body at all? |
| `preflight-read` | Is a CORS preflight granted? (That defeats content-type and custom-header CSRF gates.) |
| `write` | Can a passerby POST into the service? |

Any readable response is a **FAIL**, including a 404. A readable 404 means the origin was trusted, and the same trust covers every other path.

## Three verdicts, not two

| Verdict | Exit code | Meaning |
|---|---|---|
| PASS | 0 | Every probe was blocked, and the control proved the harness works. |
| FAIL | 1 | A passerby read or wrote the service. |
| VOID | 2 | Nothing was measured. |

A blocked fetch and a broken probe look identical, and the broken one reads as good news. Two things force VOID instead of a false PASS:

1. **The control.** A deliberately permissive server runs in the same harness and is probed first. If the passerby cannot read that, every "blocked" in the run is meaningless.
2. **The wire origin.** The control server echoes the `Origin` header it actually received. If it is not `null`, the probe was not acting as a passerby. Chromium reports the frame's URL-derived origin from `location.origin` while sending `Origin: null` on the wire, so only the server's report counts.

## Why `null` matters

A sandboxed iframe (`<iframe sandbox="allow-scripts">`), a `data:` document or any CSP-sandboxed page has an opaque origin that serializes to exactly `null`. Any website can make one. A server that treats `null` as "local or native" and reflects it in `Access-Control-Allow-Origin` hands its data to every site you visit. The usual reviews miss this: the Host check is sound, the content-type gate is sound, and a test suite can pin the vulnerable behavior as correct. Only a browser settles it.

## Prove the probe works first

```bash
cd skills/passerby
npm install --no-save electron@32.3.3
node selftest.js
```

The self-test starts one deliberately vulnerable fixture and one safe one, and requires `passerby` to return FAIL for the first and PASS for the second. Output from a real run:

```text
frame origin : "http://127.0.0.1:8789" (opaque: true)
control read : true
vulnerable   : FAIL (want FAIL)
safe         : PASS (want PASS)

SELFTEST PASSED — passerby detects the hole and clears the fix.
```

If both come back PASS the harness is blind. If both come back FAIL it is crying wolf. Either way, do not trust it.

## Use

```bash
cd skills/passerby
ELEC=$(node -p "require('electron')")
env -u ELECTRON_RUN_AS_NODE "$ELEC" . --targets 3000,8080
```

`--targets` takes comma-separated ports or `host:port`. `--wait` sets how long the whole run waits for results, in milliseconds (default 9000). A target on any host other than `127.0.0.1`, `localhost` or `[::1]` is refused unless you add `--allow-remote`. Inside Claude, ask: "can a website reach this port?" or "check the CORS on my local server".

`ELECTRON_RUN_AS_NODE` can be set by some hosts (VS Code's terminal is one). It turns the Electron binary into plain Node: no window, no error, exit 0, no output. Strip it in the same command, as above.

## What it runs, sends and fetches

- **Runs:** Electron with a hidden window (`show: false`, context isolation on, Node integration off), and two small HTTP servers bound to `127.0.0.1` only: a control server on port 8788 and a page server on port 8789 (both can be changed with `--control-port` and `--site-port`).
- **Sends:** requests only to the control server and to the ports you name. Chromium sends a CORS preflight (`OPTIONS`) before the header and `POST` probes, so each target sees up to five requests in a run. The only write is a `POST` with the body `{"passerby":true}`.
- **Fetches:** nothing at run time. Electron itself is downloaded by `npm install`, at your command, from the public npm registry and GitHub releases; the skill never installs it for you.
- **Reads no credentials, sends none.** Nothing in this repository reads an environment variable, a credential, a token or a file of yours, and nothing it sends carries one: the requests are a bare `GET`, a header probe and the one `POST` with the body `{"passerby":true}`. The self-test (`selftest.js`) never touches the environment either: the one variable that matters, `ELECTRON_RUN_AS_NODE`, is cleared by the shell that starts Electron (`env -u` on macOS and Linux, `set VAR=` through `cmd` on Windows), and the run itself proves it worked, because an Electron that came up as plain Node prints no result and the self-test says VOID.
- **Stores and transmits:** nothing leaves the machine and nothing is saved by the tool.

## Scope and safety

- It probes only loopback services on the machine you run it on. It is a defensive check of your own software, not a port scanner and not a penetration-testing tool.
- It makes cross-origin reads and POSTs against the ports you name, from a page it serves itself. Point it only at services you own.
- `passerby.js` opens no files and starts no other processes; Electron creates its usual user-data folder. The POST probes can still change state in a service that accepts them, which is the finding.

## Install

Copy `skills/passerby` into `~/.claude/skills/` (or a project's `.claude/skills/`). A plugin manifest is included in `.claude-plugin/plugin.json`.

Installed as a plugin the skill is namespaced, for example `/passerby:passerby`; copied into `skills/` it is `/passerby`. Claude also picks it up from the description, so you do not need to type the command.

## Status

Experimental. Run on Windows only; it has not been run on macOS or Linux. Needs Node and an Electron install.

## License

MIT. See [LICENSE](LICENSE).

Made at [MEDiAGATO](https://github.com/mediagato).
