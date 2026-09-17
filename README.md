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

Not applied automatically by this build — add manually when you're ready to demo against a real client:

**Claude Desktop** (`claude_desktop_config.json`, `%APPDATA%\Claude\` on Windows):
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

**Known limitation:** `TerminalConsentProvider` talks to the real console device (`CONIN$`/`CONOUT$` on Windows, `/dev/tty` elsewhere) rather than the proxy's own stdin/stdout, because those ARE the MCP JSON-RPC pipe once a client launches the proxy — reading/writing them for a human prompt would corrupt the protocol stream. This works when a console is attached to the launching process, but Claude Desktop is a GUI app that may launch the proxy without one. If consent silently fails to show a prompt in that setup, use `--auto` (unattended, same default policy) for the demo, or run the proxy from a terminal yourself as the reliable path. A proper fix — a real `elicitation/create` round-trip, or the local web-page consent surface described in the original plan — is a named follow-up, not implemented here.

**Verification status:** the exact command/args above were driven end to end with a real MCP client (the raw SDK, not `demo/scripted_client.py`) against the live proxy: `initialize()` succeeded, `list_tools()` returned the real downstream tool list, `read_thread`/`draft_reply` were ALLOWED and `send_reply` was DENIED with the broker's actual reason, and stdout carried valid JSON-RPC throughout (verified by the fact that the client's own JSON-RPC parser never choked). Claude Desktop itself was not installed in the environment this was verified in, so the real Claude Desktop application has not been exercised — only the exact command it would run has been. `--auto` consent was used for that automated check since no human or GUI could supply live console input; the real Claude Desktop path still goes through `TerminalConsentProvider` as configured above.

## Demo script

`scripts/demo.sh` runs, unattended, end to end:
1. A live proxy run: consent grants read+draft but not send; `read_thread`/`draft_reply` succeed; `send_reply` is denied with a reason.
2. The capability's short TTL expires for real; replaying `send_reply` is denied because it's dead.
3. Three attacker scenarios (expired-token replay, audience swap, scope widening via unsigned edit) — all denied by the same `Broker.authorize()` the live proxy calls.
4. A Merkle inclusion receipt for the first grant is pinned, verified, then shown to fail once the underlying log is tampered with.
