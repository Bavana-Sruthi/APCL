"""Minimal local consent surface: a human approves plain-English scope, not raw scopes.

TerminalConsentProvider is the sole implementation for this prototype -- no
extra process, port, or browser to manage during a live demo. Swapping in a
different UI later is a one-line change since proxy.py depends only on the
ConsentProvider protocol below.
"""

from __future__ import annotations

import sys
from typing import Callable, NamedTuple, Protocol


class ConsentRequest(NamedTuple):
    subject: str
    audience: str
    requested_tools: list[str]
    ttl_seconds: int
    quota: int


class ConsentDecision(NamedTuple):
    approved: bool
    granted_tools: list[str]
    ttl_seconds: int
    quota: int


class ConsentProvider(Protocol):
    def request_consent(self, req: ConsentRequest) -> ConsentDecision: ...


_TOOL_DESCRIPTIONS = {
    "read_thread": "read the email thread",
    "draft_reply": "draft a reply (not send it)",
    "send_reply": "send a reply on your behalf",
}

# Demo default: read + draft pre-approved, send NOT pre-approved.
_DEFAULT_APPROVE = {"read_thread": True, "draft_reply": True, "send_reply": False}


def _describe(tool: str) -> str:
    return _TOOL_DESCRIPTIONS.get(tool, tool)


def default_demo_decision(req: ConsentRequest) -> ConsentDecision:
    """The exact policy the 90-second demo script narrates: approve read +
    draft, withhold send. Shared by TerminalConsentProvider's own defaults
    and by ScriptedConsentProvider so the unattended demo exercises the
    identical policy a human would land on by just pressing Enter."""
    granted = [t for t in req.requested_tools if _DEFAULT_APPROVE.get(t, True)]
    return ConsentDecision(approved=bool(granted), granted_tools=granted, ttl_seconds=req.ttl_seconds, quota=req.quota)


def _open_console():
    """Opens the real console device directly, bypassing sys.stdin/stdout.

    This matters because when the proxy is launched by Claude Desktop / Gemini
    CLI, sys.stdin and sys.stdout ARE the MCP JSON-RPC pipe for the entire
    process lifetime -- calling input()/print() on them would corrupt the
    protocol stream (and read garbage as "keystrokes"). The human approving a
    grant needs a channel independent of that pipe, so we talk to the
    console device itself: CONIN$/CONOUT$ on Windows, /dev/tty on POSIX.

    Falls back to sys.stdin/sys.stdout when no console is attached at all
    (e.g. running the proxy standalone under a test harness) -- safe there
    precisely because nothing else is consuming stdio as an MCP pipe in that
    case.
    """
    try:
        if sys.platform == "win32":
            return open("CONIN$", "r", encoding="utf-8"), open("CONOUT$", "w", encoding="utf-8")
        return open("/dev/tty", "r"), open("/dev/tty", "w")
    except OSError:
        return sys.stdin, sys.stdout


class TerminalConsentProvider:
    """Prompts a human on the real console, independent of the MCP stdio pipe."""

    def request_consent(self, req: ConsentRequest) -> ConsentDecision:
        console_in, console_out = _open_console()

        def out(msg: str = "") -> None:
            print(msg, file=console_out, flush=True)

        def ask(prompt: str) -> str:
            console_out.write(prompt)
            console_out.flush()
            return console_in.readline().strip()

        out()
        out(f"Agent '{req.subject}' wants permission to, on '{req.audience}':")
        for tool in req.requested_tools:
            out(f"  - {_describe(tool)}")
        out(f"Duration: {req.ttl_seconds // 60} minutes")
        out(f"Quota: {req.quota} calls")
        out()

        granted: list[str] = []
        for tool in req.requested_tools:
            default = _DEFAULT_APPROVE.get(tool, True)
            hint = "Y/n" if default else "y/N"
            answer = ask(f"Allow '{_describe(tool)}'? [{hint}] ").lower()
            approve = default if answer == "" else answer in ("y", "yes")
            if approve:
                granted.append(tool)

        if not granted:
            out("No tools approved -- denying the grant entirely.")
            return ConsentDecision(approved=False, granted_tools=[], ttl_seconds=req.ttl_seconds, quota=req.quota)

        ttl_raw = ask(f"TTL in seconds [{req.ttl_seconds}]: ")
        ttl_seconds = int(ttl_raw) if ttl_raw else req.ttl_seconds

        quota_raw = ask(f"Quota [{req.quota}]: ")
        quota = int(quota_raw) if quota_raw else req.quota

        out(f"Approved: {granted} for {ttl_seconds}s, quota={quota}")
        out()
        return ConsentDecision(approved=True, granted_tools=granted, ttl_seconds=ttl_seconds, quota=quota)


class ScriptedConsentProvider:
    """A pre-baked or callable-driven consent decision, for automated demos and tests.

    scripts/demo.sh and demo/attacker_mode.py use this instead of blocking on
    real console input -- it goes through the exact same Broker/Issuer code
    path as the interactive provider, so nothing about enforcement is faked,
    only the human's yes/no is pre-recorded.
    """

    def __init__(self, decision: ConsentDecision | Callable[[ConsentRequest], ConsentDecision]):
        self._decision = decision

    def request_consent(self, req: ConsentRequest) -> ConsentDecision:
        if callable(self._decision):
            return self._decision(req)
        return self._decision
