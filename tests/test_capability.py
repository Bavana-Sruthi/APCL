from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.capability import Capability, attenuate, sign_capability


def _make_key():
    return Ed25519PrivateKey.generate()


def _make_capability(**overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        grant_id="grant-1",
        subject="demo-agent",
        audience="mail-server",
        tools=("read_thread", "draft_reply"),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        quota=10,
    )
    defaults.update(overrides)
    return Capability(**defaults)


def test_valid_signature_verifies():
    key = _make_key()
    cap = _make_capability()
    signed = sign_capability(cap, key, "key-1")
    assert signed.verify_signature(key.public_key())


def test_tampered_capability_fails_verification():
    key = _make_key()
    cap = _make_capability()
    signed = sign_capability(cap, key, "key-1")

    tampered_cap = Capability(**{**cap.__dict__, "tools": ("read_thread", "draft_reply", "send_reply")})
    tampered = signed.__class__(capability=tampered_cap, signature=signed.signature, key_id=signed.key_id)
    assert not tampered.verify_signature(key.public_key())


def test_token_round_trip():
    key = _make_key()
    cap = _make_capability()
    signed = sign_capability(cap, key, "key-1")
    token = signed.to_token()
    restored = signed.__class__.from_token(token)
    assert restored.capability == cap
    assert restored.verify_signature(key.public_key())


def test_attenuate_cannot_widen_scope():
    key = _make_key()
    parent = sign_capability(_make_capability(tools=("read_thread",)), key, "key-1")
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        attenuate(
            parent,
            grant_id="grant-2",
            tools={"read_thread", "send_reply"},
            expires_at=parent.capability.expires_at,
            quota=parent.capability.quota,
            issued_at=now,
            private_key=key,
            key_id="key-1",
        )


def test_attenuate_cannot_extend_ttl():
    key = _make_key()
    parent = sign_capability(_make_capability(), key, "key-1")
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        attenuate(
            parent,
            grant_id="grant-2",
            tools={"read_thread"},
            expires_at=parent.capability.expires_at + timedelta(minutes=5),
            quota=parent.capability.quota,
            issued_at=now,
            private_key=key,
            key_id="key-1",
        )


def test_attenuate_cannot_widen_quota():
    key = _make_key()
    parent = sign_capability(_make_capability(quota=5), key, "key-1")
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        attenuate(
            parent,
            grant_id="grant-2",
            tools={"read_thread"},
            expires_at=parent.capability.expires_at,
            quota=10,
            issued_at=now,
            private_key=key,
            key_id="key-1",
        )


def test_attenuate_valid_narrowing_succeeds():
    key = _make_key()
    parent = sign_capability(_make_capability(tools=("read_thread", "draft_reply"), quota=10), key, "key-1")
    now = datetime.now(timezone.utc)
    child = attenuate(
        parent,
        grant_id="grant-2",
        tools={"read_thread"},
        expires_at=parent.capability.expires_at,
        quota=5,
        issued_at=now,
        private_key=key,
        key_id="key-1",
    )
    assert child.capability.tools == ("read_thread",)
    assert child.capability.parent_grant_id == parent.capability.grant_id
    assert child.verify_signature(key.public_key())
