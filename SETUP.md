# Setting up Covenant

This covers getting the project running locally: installing it, running the
test suite, and running the demo. For installing Covenant as a Claude Desktop
extension (`.mcpb` package) instead, see [`extension/SETUP.md`](extension/SETUP.md) —
that's a separate, optional path and isn't needed to run or review the core
project.

## Prerequisites

- **Python 3.12** — required exactly; other versions may fail to install.
- (Optional) Docker + Docker Compose, if you'd rather not install Python
  locally at all — see [Docker alternative](#docker-alternative) below.
- (Optional) Node.js, only needed if you're building the Claude Desktop
  extension package (see `extension/SETUP.md`).

## 1. Install

```bash
python3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"   # Windows
# .venv/bin/python -m pip install -e ".[dev]"          # macOS/Linux
```

## 2. Run the tests

```bash
.venv/Scripts/python.exe -m pytest -q                 # fast suite, skips the real-sleep test
.venv/Scripts/python.exe -m pytest -q -m slow          # includes the real-TTL wall-clock test
.venv/Scripts/python.exe -m pytest -q tests/test_broker.py::test_quota_exhaustion_denied  # single test
```

No `ruff`/`mypy`/`black` is configured — `pytest` is the only configured tool.

## 3. Run the demo

```bash
bash scripts/demo.sh
```

This runs, unattended, end to end (~90s):
1. A live proxy run: consent grants read+draft but not send; `read_thread`/`draft_reply`
   succeed; `send_reply` is denied with a reason.
2. The capability's short TTL expires for real; replaying `send_reply` is denied
   because it's dead.
3. Three attacker scenarios (expired-token replay, audience swap, scope widening
   via unsigned edit) — all denied by the same `Broker.authorize()` the live proxy calls.
4. A Merkle inclusion receipt for the first grant is pinned, verified, then shown
   to fail once the underlying log is tampered with.

For the argument-level scoping demo (policy-driven, no interactive consent needed):

```bash
.venv/Scripts/python.exe demo/policy_client.py
```

All demo data is synthetic (`demo/synthetic_mcp_server.py`) — an in-memory fake
mail server that resets every run and never sends anything. Every command above
is safe to re-run freely.

## Docker alternative

No local Python needed:

```bash
docker compose build                     # build both images
docker compose run --rm covenant-tests   # pytest -q
docker compose run --rm covenant-demo    # scripts/demo.sh
docker compose down
```

No volumes are declared, so nothing in `.covenant-data` persists between
separate `run`/`up` invocations — each run starts from a clean slate, and the
host working tree is never touched.

## Running the proxy manually

```bash
.venv/Scripts/python.exe -m covenant.proxy --auto --ttl 60 python demo/synthetic_mcp_server.py

# scoped by a declarative task policy (argument-level scoping):
.venv/Scripts/python.exe -m covenant.proxy --auto --policy examples/read-only-email.json python demo/synthetic_mcp_server.py
```

Drop `--auto` to get an interactive consent prompt on the real console instead
of the scripted read+draft/no-send decision.

## Verifying a Merkle inclusion proof independently

```bash
.venv/Scripts/python.exe -m covenant.merkle prove <seq> receipt.json   # generate + pin a receipt for audit entry #seq
.venv/Scripts/python.exe -m covenant.merkle check <seq> receipt.json   # re-check the CURRENT on-disk entry against the PINNED receipt
```

`check` re-reads the entry fresh from `.covenant-data/audit.log` but verifies it
against the receipt captured earlier — that's what makes tampering detectable.

## Data directory

Runtime state (Ed25519 keystore, audit log) lives in `.covenant-data/` (path
overridable via `COVENANT_DATA_DIR`), git- and docker-ignored. A fresh
clone/container always starts from a clean slate; `scripts/demo.sh` explicitly
`rm -rf`s it first.

## Wiring into a real MCP client (Claude Desktop / Gemini CLI)

Not required to run the tests or demo above — only needed if you want to
exercise Covenant against a real agent client. See the "Wiring into Claude
Desktop / Gemini CLI" section of [`README.md`](README.md) for the config block
and known gotchas (absolute venv `python.exe` paths, consent-provider
selection, MSIX-packaged Desktop builds needing the `.mcpb` extension path
instead — see `extension/SETUP.md`).
