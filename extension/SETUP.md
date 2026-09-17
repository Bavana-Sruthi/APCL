# Installing Covenant as a Claude Desktop extension

This covers building the `.mcpb` package and installing it into a real
Claude Desktop (tested against 2.110.1, MSIX-packaged, which uses the
Desktop Extensions / MCPB mechanism rather than a hand-edited
`claude_desktop_config.json` — see the project README for how that was
determined).

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) on `PATH`. Claude Desktop 2.110.1 also
  bundles its own `uv`/Python runtime internally, but you need a system `uv`
  to build the package.
- Node.js, to run the official packaging CLI via `npx` (no local install
  needed): `@anthropic-ai/mcpb`.
- Claude Desktop already installed and working (this doesn't install Claude
  Desktop itself).

## 1. Build the package

The `extension/` directory is a **packaging staging copy**, not a second
codebase — it mirrors `pyproject.toml`, `src/covenant/`, and
`demo/synthetic_mcp_server.py` from the project root. Regenerate it before
packaging if the source has changed since it was last copied:

```bash
cd /path/to/APCL
rm -rf extension/src extension/demo extension/pyproject.toml extension/uv.lock extension/.venv extension/.covenant-data
mkdir -p extension/src/covenant extension/demo
cp pyproject.toml extension/pyproject.toml
cp src/covenant/*.py extension/src/covenant/
cp demo/synthetic_mcp_server.py extension/demo/
# extension/manifest.json is hand-authored and does not need regenerating.
```

Validate and pack:

```bash
npx --yes @anthropic-ai/mcpb validate extension/manifest.json
npx --yes @anthropic-ai/mcpb pack extension covenant.mcpb
```

Before installing, verify the package is clean and portable (no
machine-specific paths, no leftover build artifacts):

```bash
npx --yes @anthropic-ai/mcpb info covenant.mcpb
npx --yes @anthropic-ai/mcpb unpack covenant.mcpb /tmp/covenant_unpacked
grep -rn "C:\\\\Users\|/home/" /tmp/covenant_unpacked/   # must produce no output
```

If `uv` left a `.venv/`, `.covenant-data/`, or `src/covenant.egg-info/`
inside `extension/` from a local test run, delete them before re-packing —
`type: "uv"` means dependencies are meant to be resolved fresh on whatever
machine installs the extension, not bundled at packaging time.

## 2. Install into Claude Desktop

This is a manual, GUI step — there is no file association or CLI install
path for `.mcpb` files on this build, and the install confirmation is
designed to require a human click (extensions run arbitrary code, same as
the already-installed Blender/Figma extensions).

1. Open Claude Desktop → **Settings → Extensions**.
2. Use **Install from file** (or drag-and-drop) and select `covenant.mcpb`.
3. Approve the install prompt (it will show as `unsigned`, same as Blender/Figma).
4. Restart Claude Desktop if the extension doesn't appear immediately.

## 3. Exercise it end to end

In a Claude Desktop chat, ask it to read the thread, draft a reply, then
send it. Expected sequence:

1. A **browser tab opens** on `http://127.0.0.1:<port>/<token>` — this is
   `WebConsentProvider`, used because Claude Desktop launches the proxy with
   no attached console. Approve `read_thread` and `draft_reply`, leave
   `send_reply` unchecked, submit.
2. `read_thread` and `draft_reply` succeed.
3. `send_reply` is denied: *"Capability does not permit this action."*
4. Wait ~60 seconds (the TTL baked into `manifest.json`'s `--ttl 60`), then
   try again — everything is now denied: *"Capability expired."*

## Troubleshooting

- **No browser tab appears / consent seems to hang**: check
  `%LOCALAPPDATA%\Claude\Logs\mcp-server-covenant.log` for the printed
  consent URL (it's logged to stderr, which Claude Desktop captures
  per-server into this file) and open it manually.
- **Extension fails to start**: same log file will show the `uv run` output,
  including dependency-resolution errors.
- **Audit trail**: `uv run --project <extension install dir> python -m
  covenant.merkle prove <seq> receipt.json` against the extension's own
  `.covenant-data/audit.log` (wherever `uv` executed it from) reproduces the
  same inclusion-proof verification the test suite and `scripts/demo.sh`
  already exercise.

## Uninstalling

Claude Desktop → Settings → Extensions → remove Covenant from there; don't
hand-edit `extensions-installations.json` or the `Claude Extensions` /
`Claude Extensions Settings` folders directly.
