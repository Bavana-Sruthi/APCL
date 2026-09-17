import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.broker import Broker, Decision
from covenant.capability import Capability, SignedCapability, sign_capability


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _token(key, tools):
    now = datetime.now(timezone.utc)
    cap = Capability(
        grant_id="grant-1",
        subject="demo-agent",
        audience="mail-server",
        tools=tools,
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        quota=10,
    )
    return sign_capability(cap, key, "key-1")


def test_tool_out_of_scope_denied(key):
    token = _token(key, tools=("read_thread", "draft_reply"))
    broker = Broker(key_resolver=lambda key_id: key.public_key())
    result = broker.authorize(token, tool_name="send_reply", audience="mail-server")
    assert result.decision == Decision.DENY
    assert result.reason == "Capability does not permit this action."


def test_in_scope_tool_allowed(key):
    token = _token(key, tools=("read_thread", "draft_reply"))
    broker = Broker(key_resolver=lambda key_id: key.public_key())
    result = broker.authorize(token, tool_name="draft_reply", audience="mail-server")
    assert result.decision == Decision.ALLOW


def test_scope_widening_attack_fails_on_signature(key):
    """Hand-edit a valid token's JSON to add 'send_reply' to its tools list,
    without re-signing. The broker must deny it -- on signature, not on the
    (attacker-controlled) scope string, since the string alone proves nothing."""
    token = _token(key, tools=("read_thread",))
    raw = base64.urlsafe_b64decode(token.to_token().encode("ascii"))
    envelope = json.loads(raw)
    envelope["capability"]["tools"] = ["read_thread", "send_reply"]
    tampered_raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered_token = SignedCapability.from_token(base64.urlsafe_b64encode(tampered_raw).decode("ascii"))

    assert "send_reply" in tampered_token.capability.tools  # the attacker's edit landed
    assert not tampered_token.verify_signature(key.public_key())  # but it doesn't verify

    broker = Broker(key_resolver=lambda key_id: key.public_key())
    result = broker.authorize(tampered_token, tool_name="send_reply", audience="mail-server")
    assert result.decision == Decision.DENY
    assert result.reason == "Capability signature invalid."
