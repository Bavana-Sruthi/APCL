from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.broker import Broker, Decision
from covenant.capability import Capability, sign_capability


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _token(key, audience):
    now = datetime.now(timezone.utc)
    cap = Capability(
        grant_id="grant-1",
        subject="demo-agent",
        audience=audience,
        tools=("read_thread",),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        quota=10,
    )
    return sign_capability(cap, key, "key-1")


def test_mismatched_audience_denied(key):
    token = _token(key, audience="mail-server")
    broker = Broker(key_resolver=lambda key_id: key.public_key())
    result = broker.authorize(token, tool_name="read_thread", audience="calendar-server")
    assert result.decision == Decision.DENY
    assert result.reason == "Capability not valid for this server."


def test_audience_swap_attack_denied(key):
    """A capability minted for one server must not work against a different one,
    even though the signature and every other field are perfectly valid."""
    token = _token(key, audience="mail-server")
    broker = Broker(key_resolver=lambda key_id: key.public_key())
    assert token.verify_signature(key.public_key())  # signature itself is fine
    result = broker.authorize(token, tool_name="read_thread", audience="crm-server")
    assert result.decision == Decision.DENY


def test_matching_audience_allowed(key):
    token = _token(key, audience="mail-server")
    broker = Broker(key_resolver=lambda key_id: key.public_key())
    result = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    assert result.decision == Decision.ALLOW
