from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.capability import Capability, attenuate, sign_capability
from covenant.policy import ArgumentRule


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


# --- argument_constraints: signing, tampering, attenuation --------------------


def test_signature_covers_argument_constraints():
    key = _make_key()
    cap = _make_capability(
        argument_constraints={"send_reply": (ArgumentRule(field="to", operator="in", value=["a@x.com"]),)}
    )
    signed = sign_capability(cap, key, "key-1")
    assert signed.verify_signature(key.public_key())


def test_tampering_argument_constraints_fails_verification():
    key = _make_key()
    cap = _make_capability(
        argument_constraints={"send_reply": (ArgumentRule(field="to", operator="in", value=["a@x.com"]),)}
    )
    signed = sign_capability(cap, key, "key-1")

    widened_cap = Capability(
        **{
            **cap.__dict__,
            "argument_constraints": {
                "send_reply": (ArgumentRule(field="to", operator="in", value=["a@x.com", "evil@x.com"]),)
            },
        }
    )
    tampered = signed.__class__(capability=widened_cap, signature=signed.signature, key_id=signed.key_id)
    assert not tampered.verify_signature(key.public_key())


def test_argument_constraints_round_trip_through_token():
    key = _make_key()
    cap = _make_capability(
        argument_constraints={"send_reply": (ArgumentRule(field="to", operator="in", value=["a@x.com"]),)}
    )
    signed = sign_capability(cap, key, "key-1")
    restored = signed.__class__.from_token(signed.to_token())
    assert restored.capability.argument_constraints == cap.argument_constraints
    assert restored.verify_signature(key.public_key())


def test_attenuate_inherits_parent_argument_constraints_by_default():
    key = _make_key()
    rule = ArgumentRule(field="to", operator="in", value=["a@x.com"])
    parent = sign_capability(
        _make_capability(tools=("read_thread", "send_reply"), argument_constraints={"send_reply": (rule,)}),
        key,
        "key-1",
    )
    now = datetime.now(timezone.utc)
    child = attenuate(
        parent,
        grant_id="grant-2",
        tools={"send_reply"},
        expires_at=parent.capability.expires_at,
        quota=parent.capability.quota,
        issued_at=now,
        private_key=key,
        key_id="key-1",
    )
    assert child.capability.argument_constraints == {"send_reply": (rule,)}


def test_attenuate_can_add_stricter_argument_constraints():
    key = _make_key()
    parent = sign_capability(_make_capability(tools=("read_thread", "send_reply")), key, "key-1")
    now = datetime.now(timezone.utc)
    stricter_rule = ArgumentRule(field="to", operator="in", value=["a@x.com"])
    child = attenuate(
        parent,
        grant_id="grant-2",
        tools={"send_reply"},
        expires_at=parent.capability.expires_at,
        quota=parent.capability.quota,
        issued_at=now,
        private_key=key,
        key_id="key-1",
        argument_constraints={"send_reply": (stricter_rule,)},
    )
    assert child.capability.argument_constraints == {"send_reply": (stricter_rule,)}


def test_attenuate_cannot_drop_a_parent_argument_constraint():
    key = _make_key()
    rule = ArgumentRule(field="to", operator="in", value=["a@x.com"])
    parent = sign_capability(
        _make_capability(tools=("read_thread", "send_reply"), argument_constraints={"send_reply": (rule,)}),
        key,
        "key-1",
    )
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        attenuate(
            parent,
            grant_id="grant-2",
            tools={"send_reply"},
            expires_at=parent.capability.expires_at,
            quota=parent.capability.quota,
            issued_at=now,
            private_key=key,
            key_id="key-1",
            argument_constraints={"send_reply": ()},
        )
