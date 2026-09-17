"""Mints and signs capability tokens, recording every grant in the audit log."""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from covenant.audit import AuditLog
from covenant.capability import Capability, SignedCapability, sign_capability
from covenant.config import ISSUER_KEY_ID, load_or_create_issuer_key
from covenant.policy import ArgumentRule


class Issuer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str, audit_log: AuditLog):
        self._private_key = private_key
        self._key_id = key_id
        self._audit_log = audit_log

    @classmethod
    def load_or_create(cls, audit_log: AuditLog, key_id: str = ISSUER_KEY_ID) -> "Issuer":
        return cls(load_or_create_issuer_key(key_id), key_id, audit_log)

    def mint(
        self,
        *,
        subject: str,
        audience: str,
        tools: Sequence[str],
        ttl_seconds: int,
        quota: int,
        argument_constraints: dict[str, Sequence[ArgumentRule]] | None = None,
    ) -> SignedCapability:
        now = datetime.now(timezone.utc)
        capability = Capability(
            grant_id=f"grant-{secrets.token_hex(6)}",
            subject=subject,
            audience=audience,
            tools=tuple(tools),
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            quota=quota,
            argument_constraints={
                tool: tuple(rules) for tool, rules in (argument_constraints or {}).items()
            },
        )
        signed = sign_capability(capability, self._private_key, self._key_id)
        self._audit_log.append(
            event_type="grant_issued",
            grant_id=capability.grant_id,
            subject=subject,
            reason=f"tools={list(tools)} ttl={ttl_seconds}s quota={quota}",
        )
        return signed

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
