# Covenant — Task-Exact Execution: Architecture & Build Plan

## 1. Problem this solves

Today, when Claude Desktop / Gemini CLI is connected to an external MCP tool server (email, calendar, files, a database — anything), the agent gets **tool-name-level** permission only: "this session may call `send_reply`," full stop. Covenant already turns that into a signed, TTL-bound, audited grant instead of a standing permission — but it still can't answer *"send_reply to whom, about what thread?"* An agent that's allowed to send email at all can send it to the wrong recipient, and Covenant today would ALLOW that, because it only checks the tool name, not the arguments.

**Goal:** for any task given to an MCP-connected agent, guarantee the agent can execute *only* the exact operation intended — right tool, right target, right data — and nothing adjacent, regardless of what the model decides to try. Enforcement must happen outside the model (in the broker), so it holds even if the model reasons incorrectly or the prompt is manipulated (e.g. prompt injection from tool output).

This plan extends Covenant (still a **local proxy + CLI tool**, not a hosted platform) with **argument-level scoping** and a **declarative per-task policy** on top of the existing signature/TTL/audience/scope/quota checks, and generalizes it to work against **any MCP server**, not just the synthetic email demo.

## 2. Architecture

```
                         ┌─────────────────────────┐
   task.yaml (policy) ──►│   covenant.policy        │  loads + validates a declarative
                         │   (NEW)                  │  per-task scope: tools + argument rules
                         └───────────┬──────────────┘
                                     │ TaskPolicy
                                     v
  Claude Desktop /      ┌─────────────────────────┐
  Gemini CLI  ───stdio──►│      proxy.py            │
                         │  CovenantProxy           │
                         └──┬───────────┬───────────┘
                            │           │
                 discovers  │           │ tools/call (name, arguments)
                 tools/list │           v
                            │   ┌─────────────────────────┐      ┌────────────────────┐
                            │   │       broker.py           │────►│   policy.py (NEW)   │
                            │   │  Broker.authorize()       │     │  match_arguments()  │
                            │   │  sig→TTL→audience→scope   │◄────│  ArgumentRule eval  │
                            │   │  →quota→ARGUMENTS (NEW)   │     └────────────────────┘
                            │   └──────────┬─────────────────┘
                            │              │ Decision(ALLOW/DENY, reason)
                            v              v
                  ┌───────────────┐  ┌─────────────────────┐
                  │  consent.py    │  │      audit.py         │──► merkle.py (unchanged)
                  │  shows the     │  │  logs decision +      │    signed heads, inclusion
                  │  EXACT scope   │  │  which rule matched/  │    proofs, tamper detection
                  │  (tools + arg  │  │  failed               │
                  │  rules) for    │  └─────────────────────┘
                  │  human approval│
                  └───────────────┘
                            │ approved scope
                            v
                  ┌───────────────┐
                  │   issuer.py    │  mints SignedCapability whose
                  │  Issuer.mint() │  canonical_bytes() now includes
                  │  (extended)    │  argument_constraints (so they
                  └───────────────┘  can't be widened post-signature)
                            │
                            v
                  Target MCP Server (any — email, calendar, files, generic)
```

**Key architectural decision — generic, not per-service:** no service-specific adapter code is added. Covenant already intercepts MCP `tools/call` at the protocol level, so email/calendar/files/anything work identically. The one new piece of discovery logic is that the proxy calls the downstream server's `tools/list` (which MCP already returns, including each tool's JSON input schema) at startup and validates that a policy's tool names and argument field paths actually exist on *this* server — a policy referencing a nonexistent tool/field fails closed at startup, not silently at authorize-time.

## 3. Orchestration (per-task flow)

1. Before a task runs, a **TaskPolicy** is provided — either a declarative `task.yaml` file (primary path) or, for the existing demo flow, the current `--auto`/`default_demo_decision` logic (kept for backward compatibility, now expressed as a TaskPolicy internally).
2. `covenant.policy` loads and schema-validates the file, and cross-checks it against the live `tools/list` from the downstream server.
3. `consent.py` presents the **exact** resolved scope (tool names + per-tool argument rules + TTL + quota) to a human for approval — this is the accuracy checkpoint; nothing is minted without it (except `--auto`, unattended-demo only, unchanged).
4. On approval, `issuer.py::Issuer.mint()` builds a `Capability` including `argument_constraints` and signs it (Ed25519, unchanged signing mechanism).
5. For every `tools/call` the agent makes, `proxy.py::_on_call_tool` passes both the tool name **and its arguments** into `broker.py::Broker.authorize()`.
6. `Broker.authorize()` runs the existing checks in order (signature → not-yet-valid/expired → audience → scope) and adds a new final check: **argument constraints**, via `policy.py::match_arguments(tool_name, arguments, constraints)`. Any rule failure denies with a new explicit reason, e.g. `"Capability does not permit these arguments: to (expected one of ['a@x.com','b@x.com'], got 'c@x.com')"`.
7. Only quota is incremented / call forwarded on full ALLOW.
8. `audit.py` logs the decision including which rule (if any) caused denial; `merkle.py` continues to hash/chain/Merkle-prove entries unchanged (it hashes the full entry, so the new fields are covered automatically).

## 4. Schemas

**`Capability` (extended, `src/covenant/capability.py`):**
```
Capability:
  grant_id: str
  subject: str
  audience: str
  tools: list[str]                       # unchanged — coarse allow-list
  argument_constraints: dict[str, list[ArgumentRule]]   # NEW — tool_name -> rules, empty list = no extra constraint
  issued_at: float
  expires_at: float
  quota: int
  parent_grant_id: str | None
  nonce: str
```
`canonical_bytes()` must serialize `argument_constraints` deterministically (sorted keys) so it's covered by the Ed25519 signature — this is what stops an attacker from widening argument scope on an otherwise-valid signed token.

**`ArgumentRule` (new, `src/covenant/policy.py`):**
```
ArgumentRule:
  field: str        # dotted/JSON-path into the call arguments, e.g. "to", "filters.folder"
  operator: Literal["equals", "in", "regex", "not_in"]
  value: str | list[str]
```
`match_arguments(tool_name, call_arguments, constraints) -> (bool, str | None)` — returns pass/fail and, on failure, the specific rule and value that failed (for the audit reason string).

**`TaskPolicy` file (new, declarative input — YAML or JSON, loaded by `covenant.policy.load_task_policy()`):**
```yaml
subject: "user@local"
audience: "mail-server"       # must match the downstream server's identity
ttl_seconds: 300
quota: 3
grants:
  - tool: read_thread
  - tool: draft_reply
  - tool: send_reply
    arguments:
      - field: to
        operator: in
        value: ["known-recipient@example.com"]
```
This is the human-editable, pre-signature request. `Capability`/`SignedCapability` remain the signed, runtime-enforced artifact minted *from* it after consent approval — the policy file itself is never trusted directly by the broker.

**Audit entry (extended, `src/covenant/audit.py`):** add optional `matched_rule: str | None` field to `AuditEntry`, populated on argument-based denials, included in `entry_hash()` like every other field (no special-casing needed since hashing is already whole-entry).

## 5. APIs / interfaces (this stays a local tool — no HTTP service is introduced except what already exists)

- **MCP JSON-RPC over stdio** — unchanged, existing surface between client↔proxy↔target.
- **CLI (`covenant-proxy` entry point, `src/covenant/proxy.py::run`)** — new flag `--policy <path>` to load a `TaskPolicy` file instead of (or in addition to) `--auto`/interactive consent; existing `--ttl`, `--web-consent-timeout` flags unchanged.
- **`WebConsentProvider` local HTTP page (`consent.py`)** — extended to render the full proposed scope (tool list + argument rules per tool) instead of just a yes/no per tool, so the human approving actually sees what they're approving. Still localhost-only, ephemeral port, random token — no new network surface.
- **Python module API** — `covenant.policy.load_task_policy(path)`, `covenant.policy.match_arguments(...)`, and `Issuer.mint()` gain an `argument_constraints` parameter — these are the internal APIs other code (and tests) call; no REST endpoints are added, consistent with "extended local tool" scope.
- **`covenant-verify` CLI (`merkle.py`)** — unchanged (`prove`/`check`), continues to work since it operates on whole audit entries.

## 6. What needs to be built (phased)

**Phase A — core enforcement (highest priority, everything else depends on it):**
1. `src/covenant/policy.py` (new): `ArgumentRule`, `match_arguments()`, `TaskPolicy` dataclass, `load_task_policy()` (YAML/JSON parse + schema validation), `validate_against_tools_list()` (cross-check against live downstream `tools/list`).
2. Extend `Capability` in `capability.py`: add `argument_constraints`, update `canonical_bytes()`, `to_dict()`/`from_dict()`, and `attenuate()` (narrowing must also apply to argument rules — a child capability's rules must be a subset/tightening of the parent's, never wider).
3. Extend `Broker.authorize()` in `broker.py` to accept `arguments: dict` and call `policy.match_arguments()` as the final check, with the new denial reason format.
4. Extend `Issuer.mint()` in `issuer.py` to accept and pass through `argument_constraints`.
5. Wire `proxy.py::_on_call_tool` to pass real call arguments to `broker.authorize()`.

**Phase B — usability / accuracy of consent:**
6. Extend `consent.py` (`TerminalConsentProvider`, `WebConsentProvider`) to display argument rules, not just tool names.
7. Add `--policy` flag handling in `proxy.py::run()`, loading a `TaskPolicy` and driving consent from it instead of only `default_demo_decision`.
8. Startup `tools/list` cross-validation (fail closed if the policy references an unknown tool/field).

**Phase C — tests (one file per new property, matching existing `tests/` convention):**
9. `tests/test_policy.py` — rule matching (`equals`/`in`/`regex`/`not_in`), malformed policy file rejected, cross-validation against a fake `tools/list`.
10. Extend `tests/test_broker.py` — argument-constrained allow, argument-constrained deny (with exact reason string), no-constraint tools still work unchanged (backward compatible).
11. Extend `tests/test_capability.py` — signature covers `argument_constraints` (tampering with rules post-signature fails verification), `attenuate()` rejects widened argument rules.
12. Extend `tests/test_audit.py` / `test_merkle.py` only if the new `matched_rule` field changes any fixture data — otherwise unaffected, since hashing is whole-entry.

**Phase D — docs (after the above is implemented and tests pass):**
13. Update `README.md` and `CLAUDE.md` with the policy file format, the new `--policy` flag, and the argument-scoping guarantee — explicitly keep the "what's real vs simulated" framing this repo already uses.

**Explicitly out of scope for this plan** (per your answers): no REST API, no database, no multi-user/web dashboard, no service-specific adapters — the existing generic MCP proxy model is kept and sharpened, not replaced.

## 7. Verification

- `pytest -q` (existing 31 tests must keep passing — backward compatibility) plus new Phase C tests.
- Manual run: `covenant-proxy --policy examples/read-only-email.yaml python demo/synthetic_mcp_server.py`, confirm `send_reply` is denied even though the demo's default policy would normally allow drafting, and confirm the denial reason names the exact failed rule.
- `scripts/demo.sh`-style scenario extended (or a new `demo/attacker_mode.py` case) for "correctly-scoped tool, wrong argument" — e.g. `send_reply` to an address outside the allow-list — proving the new check catches what today's Covenant would miss.
