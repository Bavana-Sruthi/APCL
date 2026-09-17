"""Capability token model: what an agent may do, for how long, against what, how often.

A `Capability` is the unsigned claim; a `SignedCapability` pairs it with an
Ed25519 signature over its canonical bytes plus the `key_id` that produced it.
Verification always resolves `key_id` against the broker's trusted keystore
(see config.load_trusted_public_key) -- a capability never carries its own
public key, so an attacker who edits a token's JSON also breaks its signature.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Capability:
    grant_id: str
    subject: str
    audience: str
    tools: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    quota: int
    parent_grant_id: str | None = None
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))

    def canonical_bytes(self) -> bytes:
        """Deterministic byte encoding used for both signing and hashing."""
        payload = {
            "grant_id": self.grant_id,
            "subject": self.subject,
            "audience": self.audience,
            "tools": list(self.tools),
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "quota": self.quota,
            "parent_grant_id": self.parent_grant_id,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        return json.loads(self.canonical_bytes())

    @classmethod
    def from_dict(cls, d: dict) -> "Capability":
        return cls(
            grant_id=d["grant_id"],
            subject=d["subject"],
            audience=d["audience"],
            tools=tuple(d["tools"]),
            issued_at=_parse_iso(d["issued_at"]),
            expires_at=_parse_iso(d["expires_at"]),
            quota=d["quota"],
            parent_grant_id=d.get("parent_grant_id"),
            nonce=d["nonce"],
        )


@dataclass(frozen=True)
class SignedCapability:
    capability: Capability
    signature: bytes
    key_id: str

    def verify_signature(self, trusted_public_key: Ed25519PublicKey) -> bool:
        try:
            trusted_public_key.verify(self.signature, self.capability.canonical_bytes())
            return True
        except InvalidSignature:
            return False

    def to_token(self) -> str:
        envelope = {
            "capability": self.capability.to_dict(),
            "signature": base64.urlsafe_b64encode(self.signature).decode("ascii"),
            "key_id": self.key_id,
        }
        raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @classmethod
    def from_token(cls, token: str) -> "SignedCapability":
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        envelope = json.loads(raw)
        return cls(
            capability=Capability.from_dict(envelope["capability"]),
            signature=base64.urlsafe_b64decode(envelope["signature"]),
            key_id=envelope["key_id"],
        )


def sign_capability(capability: Capability, private_key: Ed25519PrivateKey, key_id: str) -> SignedCapability:
    signature = private_key.sign(capability.canonical_bytes())
    return SignedCapability(capability=capability, signature=signature, key_id=key_id)


def attenuate(
    parent: SignedCapability,
    *,
    grant_id: str,
    tools: set[str],
    expires_at: datetime,
    quota: int,
    issued_at: datetime,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> SignedCapability:
    """Mints a narrower capability derived from `parent`.

    A delegated/attenuated capability can only ever shrink what the parent
    granted -- never widen it. Any attempt to exceed the parent's tools, TTL,
    or quota raises ValueError before a signature is ever produced.
    """
    parent_tools = set(parent.capability.tools)
    if not tools.issubset(parent_tools):
        raise ValueError(f"Cannot widen tools beyond parent grant: {tools - parent_tools}")
    if expires_at > parent.capability.expires_at:
        raise ValueError("Cannot extend expiry beyond parent grant.")
    if quota > parent.capability.quota:
        raise ValueError("Cannot widen quota beyond parent grant.")

    child = Capability(
        grant_id=grant_id,
        subject=parent.capability.subject,
        audience=parent.capability.audience,
        tools=tuple(sorted(tools)),
        issued_at=issued_at,
        expires_at=expires_at,
        quota=quota,
        parent_grant_id=parent.capability.grant_id,
    )
    return sign_capability(child, private_key, key_id)
