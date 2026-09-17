import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from covenant.consent import (
    ConsentDecision,
    ConsentRequest,
    ScriptedConsentProvider,
    TerminalConsentProvider,
    WebConsentProvider,
    _console_available,
    _open_console,
    default_demo_decision,
    select_consent_provider,
)


def _make_request(**overrides):
    defaults = dict(
        subject="demo-agent",
        audience="mail-server",
        requested_tools=["read_thread", "draft_reply", "send_reply"],
        ttl_seconds=900,
        quota=10,
    )
    defaults.update(overrides)
    return ConsentRequest(**defaults)


# --- selection / fallback behavior -----------------------------------------


def test_auto_bypasses_consent_regardless_of_console_availability():
    with_console = select_consent_provider(auto=True, console_check=lambda: True)
    without_console = select_consent_provider(auto=True, console_check=lambda: False)
    assert isinstance(with_console, ScriptedConsentProvider)
    assert isinstance(without_console, ScriptedConsentProvider)


def test_selects_terminal_provider_when_console_available():
    provider = select_consent_provider(auto=False, console_check=lambda: True)
    assert isinstance(provider, TerminalConsentProvider)


def test_selects_web_provider_when_no_console_available():
    provider = select_consent_provider(auto=False, console_check=lambda: False)
    assert isinstance(provider, WebConsentProvider)


def test_auto_decision_matches_default_demo_policy():
    req = _make_request()
    provider = select_consent_provider(auto=True, console_check=lambda: True)
    decision = provider.request_consent(req)
    assert decision.approved
    assert decision.granted_tools == ["read_thread", "draft_reply"]
    assert decision == default_demo_decision(req)


# --- _open_console / _console_available safety fix --------------------------


def test_open_console_raises_runtime_error_when_no_console_present():
    def raising_opener(path, mode):
        raise OSError("no console attached")

    with pytest.raises(RuntimeError):
        _open_console(opener=raising_opener)


def test_console_available_returns_false_without_raising_when_no_console():
    def raising_opener(path, mode):
        raise OSError("no console attached")

    assert _console_available(opener=raising_opener) is False


def test_console_available_returns_true_and_closes_handles():
    closed = []

    class FakeHandle:
        def close(self):
            closed.append(True)

    def fake_opener(path, mode):
        return FakeHandle()

    assert _console_available(opener=fake_opener) is True
    assert len(closed) == 2  # both console_in and console_out were closed


# --- WebConsentProvider: HTTP flow, stdout cleanliness, timeout -------------


def _drive_approval(url: str, tools: list[str], ttl_seconds: int, quota: int) -> None:
    fields = [("tools", t) for t in tools]
    fields += [("ttl_seconds", str(ttl_seconds)), ("quota", str(quota)), ("action", "approve")]
    data = urllib.parse.urlencode(fields).encode("utf-8")
    with urllib.request.urlopen(f"{url}/decide", data=data, timeout=5) as resp:
        resp.read()


def _drive_denial(url: str) -> None:
    data = urllib.parse.urlencode([("action", "deny")]).encode("utf-8")
    with urllib.request.urlopen(f"{url}/decide", data=data, timeout=5) as resp:
        resp.read()


def test_web_consent_provider_approval_round_trip():
    ready = threading.Event()
    captured_url: dict[str, str] = {}

    def on_ready(url: str) -> None:
        captured_url["url"] = url
        ready.set()

    provider = WebConsentProvider(timeout_seconds=10, open_browser=False, on_ready=on_ready)
    req = _make_request()
    result: dict[str, ConsentDecision] = {}

    worker = threading.Thread(target=lambda: result.__setitem__("decision", provider.request_consent(req)))
    worker.start()

    assert ready.wait(5), "server never signalled readiness"
    _drive_approval(captured_url["url"], ["read_thread", "draft_reply"], ttl_seconds=120, quota=5)
    worker.join(timeout=5)

    decision = result["decision"]
    assert decision.approved
    assert decision.granted_tools == ["read_thread", "draft_reply"]
    assert decision.ttl_seconds == 120
    assert decision.quota == 5


def test_web_consent_provider_explicit_denial():
    ready = threading.Event()
    captured_url: dict[str, str] = {}

    provider = WebConsentProvider(
        timeout_seconds=10, open_browser=False, on_ready=lambda url: (captured_url.setdefault("url", url), ready.set())
    )
    req = _make_request()
    result: dict[str, ConsentDecision] = {}
    worker = threading.Thread(target=lambda: result.__setitem__("decision", provider.request_consent(req)))
    worker.start()

    assert ready.wait(5)
    _drive_denial(captured_url["url"])
    worker.join(timeout=5)

    decision = result["decision"]
    assert not decision.approved
    assert decision.granted_tools == []


def test_web_consent_provider_wrong_token_is_rejected():
    ready = threading.Event()
    captured_url: dict[str, str] = {}

    provider = WebConsentProvider(
        timeout_seconds=2, open_browser=False, on_ready=lambda url: (captured_url.setdefault("url", url), ready.set())
    )
    req = _make_request()
    result: dict[str, ConsentDecision] = {}
    worker = threading.Thread(target=lambda: result.__setitem__("decision", provider.request_consent(req)))
    worker.start()

    assert ready.wait(5)
    base = captured_url["url"].rsplit("/", 1)[0]  # strip the real token
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{base}/wrong-token", timeout=5)
    assert exc_info.value.code == 404

    worker.join(timeout=5)  # times out and denies since the real token was never hit
    assert not result["decision"].approved


def test_web_consent_provider_times_out_and_denies_by_default():
    provider = WebConsentProvider(timeout_seconds=1, open_browser=False)
    req = _make_request()

    start = time.monotonic()
    decision = provider.request_consent(req)
    elapsed = time.monotonic() - start

    assert not decision.approved
    assert decision.granted_tools == []
    assert elapsed < 5  # denied promptly after the 1s timeout, not hung forever


def test_web_consent_provider_never_writes_to_stdout(capsys):
    ready = threading.Event()
    captured_url: dict[str, str] = {}

    provider = WebConsentProvider(
        timeout_seconds=10, open_browser=False, on_ready=lambda url: (captured_url.setdefault("url", url), ready.set())
    )
    req = _make_request()
    result: dict[str, ConsentDecision] = {}
    worker = threading.Thread(target=lambda: result.__setitem__("decision", provider.request_consent(req)))
    worker.start()

    assert ready.wait(5)
    _drive_approval(captured_url["url"], ["read_thread"], ttl_seconds=60, quota=1)
    worker.join(timeout=5)

    captured = capsys.readouterr()
    assert captured.out == ""  # everything (readiness message, timeout message) goes to stderr, never stdout
