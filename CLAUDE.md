# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Covenant is an MCP proxy that sits between an agent client (Claude Desktop, Gemini CLI) and a real MCP tool server. Every `tools/call` is checked against a signed, human-approved, task-scoped **capability** (TTL-bound, audience-bound, quota-limited, and optionally restricted to specific argument values via a `TaskPolicy`) before it reaches the downstream tool. All grants/uses/denials are recorded in an append-only, hash-chained, Merkle-provable audit log.

```
Claude Desktop / Gemini CLI
        | MCP over stdio
        v
  Covenant Proxy  ──────► Broker.authorize() ──────► Audit log (hash-chained + Merkle)
        | MCP over stdio        (sig, TTL, audience, scope, arguments, quota)
        v
  Target MCP Server (demo/synthetic_mcp_server.py: read_thread, draft_reply, send_reply)
```

Ed25519 signing/verification, TTL/audience/scope/argument/quota enforcement, narrow-only attenuation, the hash-chained audit log + Merkle tree with signed heads/inclusion proofs, and the subprocess-based MCP proxy are all real and pytest-tested. The synthetic mail server and the scripted client/attacker/policy demos in `demo/` are simulated but drive the real proxy/broker/issuer code. The Merkle log is single-node: it proves inclusion/tamper-evidence against a previously pinned receipt, not global append-only consistency across signed heads.

**Argument-level scoping (`src/covenant/policy.py`):** a capability's `tools` list only answers "which tools may this agent call" — it can't answer "send_reply to whom, about what?" `ArgumentRule`/`TaskPolicy` add that: a declarative, human-editable policy file (`--policy PATH` on `covenant-proxy`, see `examples/read-only-email.json`) can restrict a granted tool down to specific argument values (`equals`/`in`/`not_in`/`regex` against a dotted field path). Rules are baked into `Capability.argument_constraints` and covered by the Ed25519 signature exactly like `tools` is, and `Broker.authorize()` checks them as the final step before quota. `attenuate()` extends narrow-only to arguments: a delegated capability may add stricter rules but can never drop one the parent already had.

## Commands

Setup (Python 3.12 required):
```bash
python3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"   # Windows
# .venv/bin/python -m pip install -e ".[dev]"          # macOS/Linux
```

Tests (pytest + pytest-asyncio, `testpaths = ["tests"]`, `asyncio_mode = "auto"`, 78 tests total):
```bash
.venv/Scripts/python.exe -m pytest -q                        # fast suite, skips the real-sleep test
.venv/Scripts/python.exe -m pytest -q -m slow                 # includes real-TTL wall-clock test
.venv/Scripts/python.exe -m pytest -q tests/test_broker.py::test_quota_exhaustion_denied  # single test
```
No ruff/mypy/black is configured in either `pyproject.toml` — pytest is the only configured tool.

Demo (end-to-end, ~90s, also tamper-detection check):
```bash
bash scripts/demo.sh
```

Argument-scoping demo (policy-driven, no interactive consent needed):
```bash
.venv/Scripts/python.exe demo/policy_client.py
```

Docker alternative (build once, no volumes — `.covenant-data` does not persist across separate `run` invocations):
```bash
docker compose build
docker compose run --rm covenant-tests   # pytest -q
docker compose run --rm covenant-demo    # scripts/demo.sh
```

Running the proxy manually against the synthetic server:
```bash
.venv/Scripts/python.exe -m covenant.proxy --auto --ttl 60 python demo/synthetic_mcp_server.py

# scoped by a declarative task policy (argument-level scoping, see Architecture below):
.venv/Scripts/python.exe -m covenant.proxy --auto --policy examples/read-only-email.json python demo/synthetic_mcp_server.py
```

Merkle inclusion proof CLI (`covenant-verify` entry point):
```bash
.venv/Scripts/python.exe -m covenant.merkle prove <seq> receipt.json
.venv/Scripts/python.exe -m covenant.merkle check <seq> receipt.json
```

## Architecture

`src/covenant/` module dependency graph (arrows = "depends on"):

- `config.py`, `capability.py`, `audit.py`, and `policy.py` — foundation, no covenant-internal imports between `config`/`audit`/`policy`; `capability.py` imports `ArgumentRule` from `policy.py`.
  - `config.py`: `DATA_DIR`/keystore paths, Ed25519 key load/create, `load_trusted_public_key(key_id)` resolves *only* from the local keystore (unknown `key_id` → `FileNotFoundError`) — this is what stops an attacker self-signing a token.
  - `policy.py`: `ArgumentRule` (`equals`/`in`/`not_in`/`regex` against a dotted field path into call arguments) + `match_arguments()`; `TaskPolicy`/`ToolGrant` (the unsigned, human-editable request a capability is minted from) + `load_task_policy()` (JSON, or YAML if `pyyaml` is installed) + `validate_against_tools_list()` (fails closed if a policy names a tool the live server doesn't offer).
  - `capability.py`: `Capability` (frozen dataclass, now including `argument_constraints: dict[str, tuple[ArgumentRule, ...]]`, covered by `canonical_bytes()` so tampering with rules breaks the signature like tampering with `tools` does), `SignedCapability` (sign/verify/token envelope), `attenuate()` — mints a narrower child capability from a parent, raising `ValueError` on any attempt to widen tools/TTL/quota, or to drop an argument rule the parent had (adding stricter rules is fine).
  - `audit.py`: `AuditLog` — JSONL, SHA-256 hash-chained (`prev_hash`), detects tampering on `verify_chain()`.
- `issuer.py` → `audit` + `capability` + `config` + `policy` (for the `argument_constraints` type). `Issuer.mint()` builds+signs a `Capability` and logs `grant_issued`.
- `broker.py` → `capability` + `config` + `policy`. `Broker.authorize()` is deliberately pure aside from the quota counter (no audit writes inside it); checks run in order: signature → not-yet-valid/expired → audience → scope → **arguments** (`policy.match_arguments()`) → quota, each with an exact denial reason string (e.g. `"Capability expired."`, `"Capability does not permit this action."`, `"Capability does not permit these arguments: <field> (expected ..., got ...)."`).
- `merkle.py` → `audit`. `MerkleAuditLog` wraps an `AuditLog`, rebuilding the tree and re-signing the head on every append; `covenant.merkle:main` is the `covenant-verify` CLI entry point.
- `consent.py` → `policy` (for `ArgumentRule`, display only). Standalone otherwise (stdlib only: `http.server`, `threading`, `webbrowser`). `select_consent_provider()` picks `ScriptedConsentProvider` (`--auto`), `TerminalConsentProvider` (real console attached, via `CONIN$`/`CONOUT$` on Windows so it doesn't collide with the MCP stdio pipe), or `WebConsentProvider` (one-shot localhost HTTP page, denies on timeout). `ConsentRequest.argument_constraints` is shown to the human (terminal prompt and the web form) but not editable there — rules come from the `TaskPolicy` file itself.
- `proxy.py` — top-level orchestrator, depends on everything above. `CovenantProxy`: launches the target MCP server subprocess, establishes a capability grant via consent + `Issuer.mint()`, then serves the upstream leg, intercepting `tools/call` through `Broker.authorize()` (now passing real call arguments) and logging every decision via `AuditLog`/`MerkleAuditLog`. `run()` is the `covenant-proxy` console-script entry point (parses `--auto`, `--ttl`, `--web-consent-timeout`, `--policy`). When `--policy` is given, it cross-validates against the live `tools/list` before minting (fail closed), and the proxy's `audience` is taken from the policy instead of the `"mail-server"` default.

Runtime flow: client → `proxy._on_call_tool` → `broker.authorize()` (validates the `issuer`-minted `SignedCapability`, including its arguments against `policy.match_arguments()`) → `audit.append()` (feeds `MerkleAuditLog`) → on ALLOW, forwarded to the real downstream tool subprocess.

`tests/` has one file per security property, matching the module list above (`test_audience.py`, `test_audit.py`, `test_broker.py`, `test_capability.py`, `test_consent.py`, `test_expiry.py`, `test_merkle.py`, `test_policy.py`, `test_scope.py`), including specific attack-scenario tests (audience swap, scope widening on an unsigned/hand-edited token, replay-after-expiry, hash-chain tamper detection).

`demo/` — `synthetic_mcp_server.py` (fake in-memory mail server: `read_thread`/`draft_reply`/`send_reply`, resets each run, never delivers anything), `scripted_client.py` (stands in for the agent client, drives the real proxy, shows read/draft allowed vs. send denied, then TTL-expiry replay), `policy_client.py` (drives a `--policy`-scoped proxy run: `send_reply` granted but denied for an unapproved reply body, allowed for the pre-approved one), `attacker_mode.py` (three attack scenarios run against the real `Issuer`/`Broker`, no mocked denial logic).

`examples/read-only-email.json` — a ready-to-run `TaskPolicy`: `read_thread`/`draft_reply` unrestricted, `send_reply` locked to one exact pre-approved reply body via an `equals` argument rule.

## The `extension/` directory

`extension/` is a **packaging staging copy**, not a second codebase (per `extension/SETUP.md`). It mirrors `pyproject.toml`, `src/covenant/`, and `demo/synthetic_mcp_server.py` byte-for-byte from the project root — it must be regenerated (not hand-edited) whenever root sources change:
```bash
rm -rf extension/src extension/demo extension/pyproject.toml extension/uv.lock extension/.venv extension/.covenant-data
mkdir -p extension/src/covenant extension/demo
cp pyproject.toml extension/pyproject.toml
cp src/covenant/*.py extension/src/covenant/
cp demo/synthetic_mcp_server.py extension/demo/
# extension/manifest.json is hand-authored and does not need regenerating.
```
`extension/manifest.json` is the one hand-authored file — the MCPB (MCP Bundle / Desktop Extension) manifest, `manifest_version: "0.4"`, `server.type: "uv"`, restricted to `compatibility.platforms: ["win32"]`. It's validated and packed into the root-level `covenant.mcpb` (a zip archive installed into Claude Desktop via Settings → Extensions) via:
```bash
npx --yes @anthropic-ai/mcpb validate extension/manifest.json
npx --yes @anthropic-ai/mcpb pack extension covenant.mcpb
```
If you edit anything under `src/covenant/` or `demo/synthetic_mcp_server.py`, remember `extension/` is now stale until regenerated — it is not auto-synced.

## Data directory

Runtime state (Ed25519 keystore, audit log) lives in `.covenant-data/` (path overridable via `COVENANT_DATA_DIR`), git- and docker-ignored. A fresh clone/container always starts from a clean slate; `scripts/demo.sh` explicitly `rm -rf`s it first.
