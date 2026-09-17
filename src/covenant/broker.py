"""The authorization decision engine.

`Broker.authorize` is the single place every tool call is checked against a
capability. It is deliberately pure aside from the quota counter: no audit
writes happen inside it. The caller (the proxy) is responsible for logging
every decision immediately after calling authorize(), allow or deny alike --
that keeps this security-critical core trivially unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol

from covenant.capability import SignedCapability
from covenant.config import load_trusted_public_key
from covenant.policy import match_arguments


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class BrokerResult:
    decision: Decision
    reason: str
    grant_id: str | None
    remaining_quota: int | None = None


class QuotaStore(Protocol):
    def get_used(self, grant_id: str) -> int: ...
    def increment(self, grant_id: str) -> int: ...


class InMemoryQuotaStore:
    def __init__(self) -> None:
        self._used: dict[str, int] = {}

    def get_used(self, grant_id: str) -> int:
        return self._used.get(grant_id, 0)

    def increment(self, grant_id: str) -> int:
        self._used[grant_id] = self.get_used(grant_id) + 1
        return self._used[grant_id]


class Broker:
    def __init__(
        self,
        quota_store: QuotaStore | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        key_resolver: Callable[[str], object] = load_trusted_public_key,
    ):
        self._quota_store = quota_store or InMemoryQuotaStore()
        self._clock = clock
        self._key_resolver = key_resolver

    def authorize(
        self,
        token: SignedCapability,
        *,
        tool_name: str,
        audience: str,
        arguments: dict | None = None,
    ) -> BrokerResult:
        grant_id = token.capability.grant_id

        try:
            trusted_public_key = self._key_resolver(token.key_id)
        except FileNotFoundError:
            return BrokerResult(Decision.DENY, "Capability signature invalid.", grant_id)

        if not token.verify_signature(trusted_public_key):
            return BrokerResult(Decision.DENY, "Capability signature invalid.", grant_id)

        now = self._clock()
        if now < token.capability.issued_at:
            return BrokerResult(Decision.DENY, "Capability not yet valid.", grant_id)
        if now >= token.capability.expires_at:
            return BrokerResult(Decision.DENY, "Capability expired.", grant_id)

        if audience != token.capability.audience:
            return BrokerResult(Decision.DENY, "Capability not valid for this server.", grant_id)

        if tool_name not in token.capability.tools:
            return BrokerResult(Decision.DENY, "Capability does not permit this action.", grant_id)

        args_ok, args_reason = match_arguments(tool_name, arguments or {}, token.capability.argument_constraints)
        if not args_ok:
            return BrokerResult(Decision.DENY, args_reason, grant_id)

        used = self._quota_store.get_used(grant_id)
        if used >= token.capability.quota:
            return BrokerResult(Decision.DENY, "Capability quota exhausted.", grant_id, remaining_quota=0)

        used = self._quota_store.increment(grant_id)
        remaining = token.capability.quota - used
        return BrokerResult(Decision.ALLOW, "Allowed.", grant_id, remaining_quota=remaining)
