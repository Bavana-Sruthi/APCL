from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.broker import Broker, Decision, InMemoryQuotaStore
from covenant.capability import Capability, sign_capability


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _token(key, **overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        grant_id="grant-1",
        subject="demo-agent",
        audience="mail-server",
        tools=("read_thread", "draft_reply"),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        quota=3,
    )
    defaults.update(overrides)
    cap = Capability(**defaults)
    return sign_capability(cap, key, "key-1")


def _broker(key, clock=None):
    return Broker(
        quota_store=InMemoryQuotaStore(),
        clock=clock or (lambda: datetime.now(timezone.utc)),
        key_resolver=lambda key_id: key.public_key(),
    )


def test_valid_capability_allows_listed_tool(key):
    broker = _broker(key)
    token = _token(key)
    result = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert result.decision == Decision.ALLOW


def test_invalid_signature_denied(key):
    broker = _broker(key)
    token = _token(key)
    other_key = Ed25519PrivateKey.generate()
    forged = sign_capability(token.capability, other_key, "key-1")
    result = broker.authorize(forged, tool_name="read_thread", audience="mail-server")
    assert result.decision == Decision.DENY
    assert result.reason == "Capability signature invalid."


def test_unknown_key_id_denied(key):
    broker = Broker(key_resolver=lambda key_id: (_ for _ in ()).throw(FileNotFoundError()))
    token = _token(key)
    result = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert result.decision == Decision.DENY


def test_quota_exhaustion_denied(key):
    broker = _broker(key)
    token = _token(key, quota=2)
    assert broker.authorize(token, tool_name="read_thread", audience="mail-server").decision == Decision.ALLOW
    assert broker.authorize(token, tool_name="read_thread", audience="mail-server").decision == Decision.ALLOW
    third = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert third.decision == Decision.DENY
    assert third.reason == "Capability quota exhausted."


def test_denied_calls_do_not_consume_quota(key):
    broker = _broker(key)
    token = _token(key, quota=1)
    denied = broker.authorize(token, tool_name="send_reply", audience="mail-server")
    assert denied.decision == Decision.DENY
    allowed = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert allowed.decision == Decision.ALLOW
