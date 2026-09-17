"""Append-only, hash-chained audit log.

Every grant issued and every tool-call decision (allow or deny) is recorded
here. Each entry embeds the hash of the previous entry, so any edit to a
past line breaks the chain from that point forward -- independent of, and in
addition to, the Merkle inclusion proofs built on top of this log in
merkle.py.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: datetime
    event_type: str  # "grant_issued" | "tool_call"
    grant_id: str | None
    subject: str | None
    tool_name: str | None
    decision: str | None  # "allow" | "deny" | None (grant_issued has no decision)  
    reason: str | None
    prev_hash: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "seq": self.seq,
            "timestamp": _iso(self.timestamp),
            "event_type": self.event_type,
            "grant_id": self.grant_id,
            "subject": self.subject,
            "tool_name": self.tool_name,
            "decision": self.decision,
            "reason": self.reason,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def entry_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict:
        return json.loads(self.canonical_bytes())

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(
            seq=d["seq"],
            timestamp=_parse_iso(d["timestamp"]),
            event_type=d["event_type"],
            grant_id=d.get("grant_id"),
            subject=d.get("subject"),
            tool_name=d.get("tool_name"),
            decision=d.get("decision"),
            reason=d.get("reason"),
            prev_hash=d["prev_hash"],
        )


class AuditLog:
    """A JSONL-backed, hash-chained append-only log.

    Loads existing entries on init (if the file already exists) so the chain
    continues correctly across process restarts.
    """

    def __init__(self, path: Path):
        self._path = path
        self._entries: list[AuditEntry] = []
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._entries.append(AuditEntry.from_dict(json.loads(line)))

    def append(
        self,
        *,
        event_type: str,
        grant_id: str | None = None,
        subject: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash() if self._entries else GENESIS_HASH
        entry = AuditEntry(
            seq=len(self._entries) + 1,
            timestamp=now or datetime.now(timezone.utc),
            event_type=event_type,
            grant_id=grant_id,
            subject=subject,
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            prev_hash=prev_hash,
        )
        self._entries.append(entry)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def all_entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> tuple[bool, int | None]:
        """Returns (True, None) if the hash chain is intact, else (False, first_bad_seq)."""
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != prev_hash:
                return False, entry.seq
            prev_hash = entry.entry_hash()
        return True, None
