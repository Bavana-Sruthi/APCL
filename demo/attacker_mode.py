"""Three attacker scenarios, run against the real Issuer/Broker -- no
separate "fake denial" logic. Each mints or manipulates a token exactly the
way an attacker would, then calls the same Broker.authorize() the live proxy
calls on every tools/call.

Run: python demo/attacker_mode.py
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from covenant.audit import AuditLog
from covenant.broker import Broker, Decision
from covenant.capability import SignedCapability
from covenant.config import AUDIT_LOG_PATH, ISSUER_KEY_ID, load_trusted_public_key
from covenant.issuer import Issuer


def _report(title: str, result) -> None:
    status = "DENIED" if result.decision is Decision.DENY else "ALLOWED"
    print(f"[{title}] {status}")
    print(f"  reason: {result.reason}")
    print()


def scenario_expired_token_replay(issuer: Issuer, broker: Broker) -> None:
    print("=== Attack 1: expired token replay ===")
    token = issuer.mint(subject="demo-agent", audience="mail-server", tools=["read_thread"], ttl_seconds=1, quota=10)

    live = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    print("  (immediately after issuance)")
    _report("expired-replay: fresh call", live)

    import time

    time.sleep(1.2)
    replay = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    print("  (replayed 1.2s later, past the 1s TTL)")
    _report("expired-replay: replay after TTL", replay)
    assert replay.decision is Decision.DENY and replay.reason == "Capability expired."


def scenario_audience_swap(issuer: Issuer, broker: Broker) -> None:
    print("=== Attack 2: audience swap ===")
    token = issuer.mint(
        subject="demo-agent", audience="mail-server", tools=["read_thread"], ttl_seconds=900, quota=10
    )
    legit = broker.authorize(token, tool_name="read_thread", audience="mail-server")
    _report("audience-swap: intended audience (mail-server)", legit)

    swapped = broker.authorize(token, tool_name="read_thread", audience="crm-server")
    _report("audience-swap: replayed against crm-server", swapped)
    assert swapped.decision is Decision.DENY and swapped.reason == "Capability not valid for this server."


def scenario_scope_widening(issuer: Issuer, broker: Broker) -> None:
    print("=== Attack 3: scope widening (edited, unsigned) ===")
    token = issuer.mint(
        subject="demo-agent", audience="mail-server", tools=["read_thread"], ttl_seconds=900, quota=10
    )
    narrow = broker.authorize(token, tool_name="send_reply", audience="mail-server")
    _report("scope-widening: send_reply against the real narrow token", narrow)

    raw = base64.urlsafe_b64decode(token.to_token().encode("ascii"))
    envelope = json.loads(raw)
    envelope["capability"]["tools"] = ["read_thread", "send_reply"]
    edited_raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    edited_token = SignedCapability.from_token(base64.urlsafe_b64encode(edited_raw).decode("ascii"))
    print("  attacker edited the token's JSON to add 'send_reply' to tools, without re-signing")

    widened = broker.authorize(edited_token, tool_name="send_reply", audience="mail-server")
    _report("scope-widening: send_reply against the edited token", widened)
    assert widened.decision is Decision.DENY and widened.reason == "Capability signature invalid."


def main() -> None:
    audit_log = AuditLog(AUDIT_LOG_PATH)
    issuer = Issuer.load_or_create(audit_log, ISSUER_KEY_ID)
    broker = Broker(key_resolver=load_trusted_public_key)

    scenario_expired_token_replay(issuer, broker)
    scenario_audience_swap(issuer, broker)
    scenario_scope_widening(issuer, broker)

    print("All three attacks were denied by the same Broker.authorize() the live proxy uses.")


if __name__ == "__main__":
    main()
