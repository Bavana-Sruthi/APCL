import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.broker import Broker, Decision
from covenant.capability import Capability, sign_capability


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _token(key, ttl_seconds, issued_at=None):
    issued_at = issued_at or datetime.now(timezone.utc)
    cap = Capability(
        grant_id="grant-1",
        subject="demo-agent",
        audience="mail-server",
        tools=("read_thread", "draft_reply", "send_reply"),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
        quota=10,
    )
    return sign_capability(cap, key, "key-1")


def test_denied_after_expiry_with_injected_clock(key):
    now = datetime.now(timezone.utc)
    token = _token(key, ttl_seconds=60, issued_at=now)

    clock = {"t": now + timedelta(seconds=61)}
    broker = Broker(clock=lambda: clock["t"], key_resolver=lambda key_id: key.public_key())

    result = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert result.decision == Decision.DENY
    assert result.reason == "Capability expired."


def test_replay_after_expiry_denied_both_calls_are_distinguishable(key):
    now = datetime.now(timezone.utc)
    token = _token(key, ttl_seconds=60, issued_at=now)
    clock = {"t": now}
    broker = Broker(clock=lambda: clock["t"], key_resolver=lambda key_id: key.public_key())

    before = broker.authorize(token, tool_name="send_reply", audience="mail-server")
    assert before.decision == Decision.ALLOW

    clock["t"] = now + timedelta(seconds=61)
    replay = broker.authorize(token, tool_name="send_reply", audience="mail-server")
    assert replay.decision == Decision.DENY
    assert replay.reason == "Capability expired."


@pytest.mark.slow
def test_real_wall_clock_expiry(key):
    token = _token(key, ttl_seconds=1)
    broker = Broker(key_resolver=lambda key_id: key.public_key())

    immediate = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert immediate.decision == Decision.ALLOW

    time.sleep(1.2)

    after = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert after.decision == Decision.DENY
    assert after.reason == "Capability expired."
