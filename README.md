# Covenant

> Every agent grant today is permanent, coarse, and unaudited. Covenant makes agent permissions task-scoped, self-expiring, and provable to a third party.

Covenant is an MCP proxy that sits between an agent client (Claude Desktop, Gemini CLI) and an MCP tool server. Every `tools/call` is checked against a signed, human-approved **capability** — task-scoped, TTL-bound, quota-limited — before it reaches the real tool. Denials come with a human-readable reason. Every grant, use, and denial is recorded in an append-only, hash-chained, Merkle-provable audit log.

```
Claude Desktop / Gemini CLI
        | MCP over stdio
        v
  Covenant Proxy  ──────► Broker.authorize() ──────► Audit log (hash-chained + Merkle)
        | MCP over stdio        (sig, TTL, audience, scope, quota)
        v
  Target MCP Server (demo/synthetic_mcp_server.py: read_thread, draft_reply, send_reply)
```

## What's real vs. simulated

This is a hackathon prototype. Being explicit about the boundary matters more than pretending it doesn't exist:

**Real, and independently testable (`pytest`):**
- Ed25519 signing and signature verification of capability tokens (`src/covenant/capability.py`)
- TTL, audience, scope, and quota enforcement (`src/covenant/broker.py`) — wall-clock real, not simulated (see the `@pytest.mark.slow` real-sleep test in `tests/test_expiry.py`)
- Attenuation that can only narrow a parent grant, never widen it
- A hash-chained append-only audit log, and a Merkle tree over it with signed tree heads and inclusion proofs
- The MCP proxy itself: it launches the target server as a real subprocess and relays real JSON-RPC traffic over stdio, intercepting only `tools/call`

**Simulated, by design, and stated as such:**
- The target MCP server's data (`demo/synthetic_mcp_server.py`) is synthetic — an in-memory fake thread, no real email is ever read or sent
- The "agent's" sequence of actions in `demo/scripted_client.py` and `demo/attacker_mode.py` is scripted, not an LLM reasoning live — but it drives the exact same proxy/broker/issuer code a real agent client would

**A named limitation, not a claim we don't make:** the Merkle log is single-node. It proves *inclusion* of a given entry under a given signed root, and *tamper-evidence* of that entry against a **previously pinned** receipt (see `covenant-verify check` below) — it does not prove global append-only *consistency* across successive signed heads. A dishonest operator with control of the signing key could still rewrite history and sign a new head over a different past. Catching that requires Merkle consistency proofs plus independent witnesses (the Certificate Transparency / Rekor model), which is a natural next step, not something implemented here.

## Prior art, credited

Covenant is a product layer on published primitives, not a new protocol: RFC 9396 (Rich Authorization Requests), RFC 8693 (Token Exchange), GNAP/RFC 9635, UCAN and Biscuit (offline capability attenuation), and Certificate Transparency / Rekor (the transparency-log shape this Merkle log borrows from).

## Project layout

```
src/covenant/
  capability.py   Capability token model: sign, verify, attenuate (narrow-only)
  issuer.py       Mints signed capabilities, logs grant_issued
  broker.py       Broker.authorize(): signature -> TTL -> audience -> scope -> quota
  audit.py        Hash-chained append-only audit log (JSONL)
  merkle.py       Merkle tree, signed tree heads, inclusion proofs, receipt CLI
  consent.py      ConsentProvider protocol: TerminalConsentProvider + ScriptedConsentProvider
  proxy.py        The MCP proxy: subprocess launch, both stdio legs, tools/call interception
  config.py       Paths, constants, trusted keystore (Ed25519, key_id-resolved)
demo/
  synthetic_mcp_server.py   Fake mail tools: read_thread, draft_reply, send_reply
  scripted_client.py        Drives the live proxy for the read/draft/send-denied/expiry-replay demo
  attacker_mode.py          Three attacks run against the real Broker/Issuer
tests/            One file per security property (capability, broker, expiry, audience, scope, audit, merkle)
scripts/demo.sh   The full ~90-second demo, unattended
```

## Running it

```bash
python3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"   # Windows
# .venv/bin/python -m pip install -e ".[dev]"          # macOS/Linux

.venv/Scripts/python.exe -m pytest -q                  # 31 tests, fast subset skips one real-sleep test
.venv/Scripts/python.exe -m pytest -q -m slow           # includes the real-TTL end-to-end test

bash scripts/demo.sh                                    # the full unattended demo
```

Or reproduce the same thing in Docker, no local Python needed:

```bash
docker compose build                     # build both images
docker compose run --rm covenant-tests   # pytest -q -> 31 passed
docker compose run --rm covenant-demo    # scripts/demo.sh, the full unattended demo
docker compose down                      # no volumes are declared, so there's nothing to preserve between runs
```
Verified working with Docker 29.8.0 / Compose v5.5.1: both images build cleanly, `docker compose up` runs both services to completion (`covenant-tests-1` and `covenant-demo-1` both exit 0), and `docker compose down` tears down cleanly. Container writes to `.covenant-data` stay inside the container's own filesystem — no volume is declared, so nothing persists between separate `run`/`up` invocations, and the host working tree is never touched.

### Manually driving the proxy

```bash
.venv/Scripts/python.exe -m covenant.proxy demo_target_command [args...]
# interactive consent on the real console (see "Known limitation" below), e.g.:
.venv/Scripts/python.exe -m covenant.proxy python demo/synthetic_mcp_server.py

# or, unattended (applies the same read+draft/no-send policy a human would approve by pressing Enter):
.venv/Scripts/python.exe -m covenant.proxy --auto --ttl 60 python demo/synthetic_mcp_server.py
```

### Verifying a Merkle inclusion proof independently

```bash
.venv/Scripts/python.exe -m covenant.merkle prove <seq> receipt.json   # generate + pin a receipt for audit entry #seq
.venv/Scripts/python.exe -m covenant.merkle check <seq> receipt.json   # re-check the CURRENT on-disk entry against the PINNED receipt
```
`check` re-reads the entry fresh from `.covenant-data/audit.log` but verifies it against the receipt captured earlier — that's what makes tampering detectable. A verifier who freshly recomputed *both* the entry and the root from current disk state would trivially "verify" tampered data, which is exactly the mistake this two-step design avoids.

## Wiring into Claude Desktop / Gemini CLI

Not applied automatically by this build — add manually when you're ready to demo against a real client.

**Modern, MSIX-packaged Claude Desktop builds (e.g. 2.110.1) don't use a hand-edited `mcpServers` block at all** — they use the Desktop Extensions / MCPB mechanism instead (confirmed by inspecting the installed Blender/Figma extensions on a real machine; no `mcpServers` key exists anywhere in that build's config or logs). For that path, see **[`extension/SETUP.md`](extension/SETUP.md)** for building and installing the `.mcpb` package. The `mcpServers` JSON block below is for classic Claude Desktop builds and Gemini CLI, which still read it.

**Claude Desktop (classic `mcpServers` config)** (`claude_desktop_config.json`, `%APPDATA%\Claude\` on Windows):
```json
{
  "mcpServers": {
    "covenant": {
      "command": "C:\\Users\\bavanasruthi\\APCL\\.venv\\Scripts\\python.exe",
      "args": [
        "-m", "covenant.proxy",
        "C:\\Users\\bavanasruthi\\APCL\\.venv\\Scripts\\python.exe",
        "C:\\Users\\bavanasruthi\\APCL\\demo\\synthetic_mcp_server.py"
      ]
    }
  }
}
```
**Both the `command` and the downstream target argument must be the venv's absolute `python.exe` path, not bare `"python"`.** Confirmed by testing: `stdio_client` inherits `PATH` from the launching process (Claude Desktop's own environment, not an activated venv), so a bare `"python"` for the downstream target resolves to whatever Python is first on Claude Desktop's `PATH` -- typically not this project's venv -- and the target subprocess fails with `ModuleNotFoundError: No module named 'mcp'` before Covenant ever gets a chance to relay anything.

**Gemini CLI** (`~/.gemini/settings.json`): same shape under `mcpServers`.

### Consent: terminal vs. no-console (Claude Desktop) vs. `--auto`

`select_consent_provider()` in `src/covenant/consent.py` picks the right consent surface automatically, based on how the proxy was launched:

1. **`--auto`** always bypasses consent entirely and applies the same read+draft/no-send policy a human would land on by accepting the defaults (`consent.default_demo_decision`) — for unattended demo/CI runs only. Unchanged from before this fix.
2. **A real console is attached** (you ran the proxy from a terminal): `TerminalConsentProvider` prompts on the actual console device (`CONIN$`/`CONOUT$` on Windows, `/dev/tty` elsewhere), independent of stdin/stdout, which are the live MCP JSON-RPC pipe. This is unchanged from before, and remains the default for terminal-launched/demo usage.
3. **No console is attached** — the situation when Claude Desktop launches the proxy as a GUI child process, where `CONIN$`/`CONOUT$` don't resolve to anything: `WebConsentProvider` serves a one-shot local HTML consent page on `127.0.0.1` (OS-assigned ephemeral port, random per-request token in the URL), opens it in the default browser, and **blocks** until a decision is submitted there or `--web-consent-timeout` (default 300s) elapses — timing out denies by default, it never auto-approves. This replaces what was previously an unresolved "Known limitation": the proxy no longer risks writing a consent prompt onto stdin/stdout when no console exists, because it no longer tries to use them for consent in that case at all.

Consent output (the browser-ready URL, timeout/denial notices) always goes to `stderr`, exactly like the existing `ALLOWED`/`DENIED` decision logging — `stdout` is reserved for MCP JSON-RPC only, in every consent path, verified by a dedicated test (`tests/test_consent.py::test_web_consent_provider_never_writes_to_stdout`).

**Verification status:** the exact command/args above were driven end to end with a real MCP client (the raw SDK, not `demo/scripted_client.py`) against the live proxy: `initialize()` succeeded, `list_tools()` returned the real downstream tool list, `read_thread`/`draft_reply` were ALLOWED and `send_reply` was DENIED with the broker's actual reason, and stdout carried valid JSON-RPC throughout. Claude Desktop itself was not installed in the environment this was originally verified in, so the real Claude Desktop application has not been exercised end-to-end with `WebConsentProvider` specifically — that verification used `--auto`, since no human or GUI could supply live console/browser input from that environment. `WebConsentProvider` itself is covered by its own test suite (HTTP approval round-trip, explicit denial, wrong-token rejection, timeout-denies, stdout-cleanliness) rather than a live Claude Desktop session.

## Demo script

`scripts/demo.sh` runs, unattended, end to end:
1. A live proxy run: consent grants read+draft but not send; `read_thread`/`draft_reply` succeed; `send_reply` is denied with a reason.
2. The capability's short TTL expires for real; replaying `send_reply` is denied because it's dead.
3. Three attacker scenarios (expired-token replay, audience swap, scope widening via unsigned edit) — all denied by the same `Broker.authorize()` the live proxy calls.
4. A Merkle inclusion receipt for the first grant is pinned, verified, then shown to fail once the underlying log is tampered with.
