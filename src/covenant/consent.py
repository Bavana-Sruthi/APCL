"""Local consent surfaces: a human approves plain-English scope, not raw scopes.

Two real implementations, selected automatically by `select_consent_provider`:

- TerminalConsentProvider: prompts on the real console device. Used when a
  console is actually attached to this process (a human ran the proxy from a
  terminal).
- WebConsentProvider: serves a one-shot local HTTP page on 127.0.0.1 and
  blocks until the human submits a decision there, or a timeout elapses.
  Used when no console is attached -- the case when Claude Desktop launches
  the proxy as a GUI child process, where stdin/stdout are the live MCP
  JSON-RPC pipe and CONIN$/CONOUT$ (Windows) or /dev/tty (POSIX) don't
  resolve to anything.

Both share the same ConsentProvider protocol, so proxy.py never has to know
which one it got. `--auto` bypasses both via ScriptedConsentProvider.
"""

from __future__ import annotations

import http.server
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from typing import Callable, NamedTuple, Protocol

from covenant.policy import ArgumentRule


class ConsentRequest(NamedTuple):
    subject: str
    audience: str
    requested_tools: list[str]
    ttl_seconds: int
    quota: int
    # tool_name -> rules narrowing that tool's arguments, shown to the human
    # approving the grant (see _describe_rules) but never editable here --
    # they come from the TaskPolicy file the human already authored/reviewed.
    argument_constraints: dict[str, list[ArgumentRule]] = {}


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

DEFAULT_WEB_CONSENT_TIMEOUT_SECONDS = 300


def _describe(tool: str) -> str:
    return _TOOL_DESCRIPTIONS.get(tool, tool)


def _describe_rules(tool: str, argument_constraints: dict[str, list[ArgumentRule]]) -> str | None:
    """Plain-English summary of a tool's argument rules, or None if unrestricted."""
    rules = argument_constraints.get(tool, [])
    if not rules:
        return None
    return "; ".join(f"{r.field} {r.operator} {r.value!r}" for r in rules)


def default_demo_decision(req: ConsentRequest) -> ConsentDecision:
    """The exact policy the 90-second demo script narrates: approve read +
    draft, withhold send. Shared by TerminalConsentProvider's/WebConsentProvider's
    own defaults and by ScriptedConsentProvider so the unattended demo exercises
    the identical policy a human would land on by just accepting the defaults."""
    granted = [t for t in req.requested_tools if _DEFAULT_APPROVE.get(t, True)]
    return ConsentDecision(approved=bool(granted), granted_tools=granted, ttl_seconds=req.ttl_seconds, quota=req.quota)


def _default_console_opener(path: str, mode: str):
    return open(path, mode, encoding="utf-8")


def _open_console(opener: Callable[[str, str], object] = _default_console_opener):
    """Opens the real console device directly, bypassing sys.stdin/stdout.

    This matters because when the proxy is launched by Claude Desktop / Gemini
    CLI, sys.stdin and sys.stdout ARE the MCP JSON-RPC pipe for the entire
    process lifetime -- calling input()/print() on them would corrupt the
    protocol stream (and read garbage as "keystrokes"). The human approving a
    grant needs a channel independent of that pipe, so we talk to the
    console device itself: CONIN$/CONOUT$ on Windows, /dev/tty on POSIX.

    Raises RuntimeError when no console is attached, rather than silently
    falling back to sys.stdin/sys.stdout -- that fallback used to be the
    actual corruption risk this module exists to avoid. Callers should use
    select_consent_provider()/_console_available() to pick TerminalConsentProvider
    only when a console genuinely exists; if this still raises, that's a bug
    in the selection, not something to paper over here.
    """
    try:
        if sys.platform == "win32":
            return opener("CONIN$", "r"), opener("CONOUT$", "w")
        return opener("/dev/tty", "r"), opener("/dev/tty", "w")
    except OSError as e:
        raise RuntimeError(
            "No console is attached to this process -- the terminal consent "
            "prompt cannot be shown here. Use select_consent_provider() so "
            "WebConsentProvider is chosen instead in this situation."
        ) from e


def _console_available(opener: Callable[[str, str], object] = _default_console_opener) -> bool:
    """Cheap probe: can a real console device actually be opened right now?

    Opens and immediately closes it -- this is only used to pick a provider,
    never to hold the console open.
    """
    try:
        console_in, console_out = _open_console(opener)
    except RuntimeError:
        return False
    for handle in (console_in, console_out):
        try:
            handle.close()
        except OSError:
            pass
    return True


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
            rules = _describe_rules(tool, req.argument_constraints)
            if rules:
                out(f"      restricted to: {rules}")
        out(f"Duration: {req.ttl_seconds // 60} minutes")
        out(f"Quota: {req.quota} calls")
        out()

        granted: list[str] = []
        for tool in req.requested_tools:
            default = _DEFAULT_APPROVE.get(tool, True)
            hint = "Y/n" if default else "y/N"
            rules = _describe_rules(tool, req.argument_constraints)
            prompt = f"Allow '{_describe(tool)}'"
            if rules:
                prompt += f" (restricted to: {rules})"
            answer = ask(f"{prompt}? [{hint}] ").lower()
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


def _render_form(req: ConsentRequest, token: str) -> str:
    rows = []
    for tool in req.requested_tools:
        checked = "checked" if _DEFAULT_APPROVE.get(tool, True) else ""
        rules = _describe_rules(tool, req.argument_constraints)
        rules_html = (
            f'<small style="display:block;margin-left:24px;color:#555;">restricted to: {rules}</small>'
            if rules
            else ""
        )
        rows.append(
            f'<label style="display:block;margin:6px 0;">'
            f'<input type="checkbox" name="tools" value="{tool}" {checked}> {_describe(tool)}'
            f"</label>{rules_html}"
        )
    checkboxes = "\n".join(rows)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Covenant consent request</title></head>
<body style="font-family: sans-serif; max-width: 480px; margin: 40px auto;">
<h2>Agent &#39;{req.subject}&#39; wants permission, on &#39;{req.audience}&#39;:</h2>
<form method="post" action="/{token}/decide">
{checkboxes}
<p>Duration (seconds): <input type="number" name="ttl_seconds" value="{req.ttl_seconds}"></p>
<p>Quota (calls): <input type="number" name="quota" value="{req.quota}"></p>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body></html>"""


def _render_confirmation(decision: ConsentDecision) -> str:
    if decision.approved:
        message = f"Approved: {decision.granted_tools} for {decision.ttl_seconds}s, quota={decision.quota}"
    else:
        message = "Denied -- no capability issued."
    return f"""<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; max-width: 480px; margin: 40px auto;">
<h2>{message}</h2>
<p>You can close this tab and return to your agent client.</p>
</body></html>"""


def _make_consent_handler(
    req: ConsentRequest,
    token: str,
    decision_holder: dict[str, ConsentDecision],
    done: threading.Event,
) -> type[http.server.BaseHTTPRequestHandler]:
    class ConsentHandler(http.server.BaseHTTPRequestHandler):
        def _write_html(self, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802 (http.server's naming convention)
            if self.path != f"/{token}":
                self.send_response(404)
                self.end_headers()
                return
            self._write_html(_render_form(req, token))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != f"/{token}/decide":
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", "0"))
            fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            action = fields.get("action", ["deny"])[0]

            if action == "approve":
                granted = fields.get("tools", [])
                try:
                    ttl_seconds = int(fields.get("ttl_seconds", [str(req.ttl_seconds)])[0])
                except ValueError:
                    ttl_seconds = req.ttl_seconds
                try:
                    quota = int(fields.get("quota", [str(req.quota)])[0])
                except ValueError:
                    quota = req.quota
                decision = ConsentDecision(
                    approved=bool(granted), granted_tools=granted, ttl_seconds=ttl_seconds, quota=quota
                )
            else:
                decision = ConsentDecision(
                    approved=False, granted_tools=[], ttl_seconds=req.ttl_seconds, quota=req.quota
                )

            decision_holder["decision"] = decision
            self._write_html(_render_confirmation(decision))

            done.set()
            # Shutting a socketserver down from inside its own request handler
            # deadlocks (shutdown() blocks until the serve_forever loop notices
            # it, which can't happen until this handler returns) -- so signal
            # it from a separate thread instead.
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass  # suppress per-request access-log noise; base impl already targets stderr, never stdout

    return ConsentHandler


class WebConsentProvider:
    """Serves a one-shot local consent page on 127.0.0.1, for use when no
    console is attached to this process (e.g. launched by Claude Desktop).

    Binds to loopback only, on an OS-assigned ephemeral port, and requires a
    random per-request token in the URL path -- see the module docstring and
    README for the exact security properties this does and doesn't provide.
    Blocks until a decision is submitted or `timeout_seconds` elapses, at
    which point it denies by default (never auto-approves on timeout).
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        timeout_seconds: int = DEFAULT_WEB_CONSENT_TIMEOUT_SECONDS,
        open_browser: bool = True,
        on_ready: Callable[[str], None] | None = None,
    ):
        self._host = host
        self._timeout_seconds = timeout_seconds
        self._open_browser = open_browser
        self._on_ready = on_ready

    def request_consent(self, req: ConsentRequest) -> ConsentDecision:
        token = secrets.token_urlsafe(24)
        decision_holder: dict[str, ConsentDecision] = {}
        done = threading.Event()

        handler_cls = _make_consent_handler(req, token, decision_holder, done)
        server = http.server.HTTPServer((self._host, 0), handler_cls)
        host, port = server.server_address
        url = f"http://{host}:{port}/{token}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        print(f"Waiting for consent approval in your browser: {url}", file=sys.stderr, flush=True)
        if self._on_ready is not None:
            self._on_ready(url)
        if self._open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass  # best-effort; the URL is already logged to stderr above

        answered = done.wait(self._timeout_seconds)
        if not answered:
            print("Consent request timed out -- denying by default.", file=sys.stderr, flush=True)
            server.shutdown()
        thread.join(timeout=5)

        if not answered:
            return ConsentDecision(approved=False, granted_tools=[], ttl_seconds=req.ttl_seconds, quota=req.quota)
        return decision_holder["decision"]


def select_consent_provider(
    *,
    auto: bool,
    web_timeout_seconds: int = DEFAULT_WEB_CONSENT_TIMEOUT_SECONDS,
    console_check: Callable[[], bool] = _console_available,
) -> ConsentProvider:
    """Picks the right ConsentProvider for how this process was launched.

    --auto always bypasses consent entirely (unattended demo/CI), regardless
    of console availability. Otherwise: a real console -> TerminalConsentProvider;
    no console (e.g. launched by Claude Desktop as a GUI child process) ->
    WebConsentProvider.
    """
    if auto:
        return ScriptedConsentProvider(default_demo_decision)
    if console_check():
        return TerminalConsentProvider()
    return WebConsentProvider(timeout_seconds=web_timeout_seconds)
