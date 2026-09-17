"""Merkle tree over the audit log, with a signed tree head and inclusion proofs.

This gives a third party a way to verify "entry #N was recorded, unmodified,
under this signed root" without trusting Covenant's live server -- they only
need the entry, its proof, and the signed head, all of which are exported by
`prove_inclusion` below.

Scope, stated plainly: this is a single-node prototype. It proves *inclusion*
of a given entry in a given signed tree, and *tamper-evidence* of that entry
(any single-byte change anywhere in it changes the recomputed root). It does
NOT prove global append-only consistency across successive signed heads -- a
dishonest operator could still rewrite history and sign a new head over a
different past. That requires Merkle consistency proofs plus independent
witnesses (the Certificate Transparency / Rekor model), which is out of scope
here and left as a named follow-up, not something this code claims to do.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from covenant.audit import AuditEntry, AuditLog

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

Side = Literal["L", "R"]


def leaf_hash(entry: AuditEntry) -> bytes:
    """Domain-separated leaf hash: blocks a leaf hash from being replayed as an internal node hash."""
    return hashlib.sha256(LEAF_PREFIX + entry.canonical_bytes()).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


class MerkleTree:
    """A binary Merkle tree built bottom-up over an ordered list of leaf hashes.

    Convention: at any level with an odd number of nodes, the last node is
    duplicated upward. This is a documented choice (RFC 6962-style trees
    handle the odd case differently) -- either is fine for a prototype as
    long as build and verify agree, which they do here.
    """

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf.")
        self._levels: list[list[bytes]] = [list(leaves)]
        level = leaves
        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                next_level.append(node_hash(left, right))
            self._levels.append(next_level)
            level = next_level

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def inclusion_proof(self, index: int) -> list[tuple[bytes, Side]]:
        if not (0 <= index < len(self._levels[0])):
            raise IndexError(f"leaf index {index} out of range")
        proof: list[tuple[bytes, Side]] = []
        idx = index
        for level in self._levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx >= len(level):
                sibling_idx = idx  # duplicated node at an odd level boundary
            sibling = level[sibling_idx]
            side: Side = "L" if is_right else "R"
            proof.append((sibling, side))
            idx //= 2
        return proof


def _fold_proof(leaf: bytes, proof: list[tuple[bytes, Side]]) -> bytes:
    acc = leaf
    for sibling, side in proof:
        acc = node_hash(sibling, acc) if side == "L" else node_hash(acc, sibling)
    return acc


@dataclass(frozen=True)
class SignedTreeHead:
    tree_size: int
    root_hash: bytes
    timestamp: datetime
    signature: bytes
    key_id: str

    def _signed_bytes(self) -> bytes:
        payload = {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash.hex(),
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify_signature(self, trusted_public_key: Ed25519PublicKey) -> bool:
        try:
            trusted_public_key.verify(self.signature, self._signed_bytes())
            return True
        except InvalidSignature:
            return False

    def to_dict(self) -> dict:
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash.hex(),
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "signature": base64.urlsafe_b64encode(self.signature).decode("ascii"),
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignedTreeHead":
        return cls(
            tree_size=d["tree_size"],
            root_hash=bytes.fromhex(d["root_hash"]),
            timestamp=datetime.fromisoformat(d["timestamp"]),
            signature=base64.urlsafe_b64decode(d["signature"]),
            key_id=d["key_id"],
        )


def sign_tree_head(tree_size: int, root_hash: bytes, private_key: Ed25519PrivateKey, key_id: str) -> SignedTreeHead:
    timestamp = datetime.now(timezone.utc)
    head = SignedTreeHead(tree_size=tree_size, root_hash=root_hash, timestamp=timestamp, signature=b"", key_id=key_id)
    signature = private_key.sign(head._signed_bytes())
    return SignedTreeHead(tree_size=tree_size, root_hash=root_hash, timestamp=timestamp, signature=signature, key_id=key_id)


class MerkleAuditLog:
    """Wraps an AuditLog, rebuilding the tree and re-signing the head on every append.

    Rebuilding from scratch on each append is O(n) but trivial at demo scale
    (tens to low hundreds of entries) -- not something a production
    transparency log would do, and not worth optimizing here.
    """

    def __init__(self, audit_log: AuditLog, private_key: Ed25519PrivateKey, key_id: str):
        self._audit_log = audit_log
        self._private_key = private_key
        self._key_id = key_id

    @property
    def audit_log(self) -> AuditLog:
        return self._audit_log

    def _tree(self) -> MerkleTree:
        entries = self._audit_log.all_entries()
        return MerkleTree([leaf_hash(e) for e in entries])

    def current_head(self) -> SignedTreeHead:
        entries = self._audit_log.all_entries()
        if not entries:
            raise ValueError("Cannot sign a tree head for an empty audit log.")
        tree = self._tree()
        return sign_tree_head(len(entries), tree.root, self._private_key, self._key_id)

    def prove_inclusion(self, seq: int) -> tuple[AuditEntry, list[tuple[bytes, Side]], SignedTreeHead]:
        entries = self._audit_log.all_entries()
        matches = [e for e in entries if e.seq == seq]
        if not matches:
            raise ValueError(f"No audit entry with seq={seq}")
        index = entries.index(matches[0])
        tree = self._tree()
        proof = tree.inclusion_proof(index)
        head = sign_tree_head(len(entries), tree.root, self._private_key, self._key_id)
        return matches[0], proof, head


def verify_inclusion(
    entry: AuditEntry,
    proof: list[tuple[bytes, Side]],
    head: SignedTreeHead,
    trusted_public_key: Ed25519PublicKey,
) -> bool:
    """Standalone verification: takes no live log, just the three artifacts a
    third party would actually be handed. Both checks must hold:
      1. The signed head's signature is valid under the trusted public key.
      2. Folding `entry`'s leaf hash up through `proof` reproduces the head's root.
    """
    if not head.verify_signature(trusted_public_key):
        return False
    computed_root = _fold_proof(leaf_hash(entry), proof)
    return computed_root == head.root_hash


def _proof_to_json(proof: list[tuple[bytes, Side]]) -> list[dict]:
    return [{"hash": h.hex(), "side": s} for h, s in proof]


def _proof_from_json(data: list[dict]) -> list[tuple[bytes, Side]]:
    return [(bytes.fromhex(d["hash"]), d["side"]) for d in data]


def export_receipt(entry: AuditEntry, proof: list[tuple[bytes, Side]], head: SignedTreeHead) -> dict:
    """What a third party would actually be handed and would pin/hold onto."""
    return {"entry": entry.to_dict(), "proof": _proof_to_json(proof), "head": head.to_dict()}


def import_receipt(data: dict) -> tuple[AuditEntry, list[tuple[bytes, Side]], SignedTreeHead]:
    return AuditEntry.from_dict(data["entry"]), _proof_from_json(data["proof"]), SignedTreeHead.from_dict(data["head"])


def main() -> None:
    """CLI with two subcommands, because tamper-evidence only means something
    when verification is checked against a PREVIOUSLY PINNED receipt, not one
    freshly recomputed from whatever is currently on disk (recomputing fresh
    would just re-sign over the tampered data and "verify" trivially):

      covenant-verify prove <seq> <receipt.json>
          Generates entry/proof/signed-head for entry #seq and saves it --
          this is the artifact a third party would receive and hold onto.

      covenant-verify check <seq> <receipt.json>
          Re-reads entry #seq FRESH from the current on-disk audit log, and
          checks it against the PINNED proof/head from receipt.json. If the
          log has been tampered with since the receipt was issued, this
          fails -- the whole point of the demo's tamper step.
    """
    import json
    import sys

    from covenant import config

    if len(sys.argv) != 4 or sys.argv[1] not in ("prove", "check"):
        print("usage: covenant-verify prove|check <seq> <receipt.json>")
        raise SystemExit(2)
    subcommand, seq_arg, receipt_path = sys.argv[1], sys.argv[2], sys.argv[3]
    seq = int(seq_arg)

    private_key = config.load_or_create_issuer_key()
    trusted_public_key = config.load_trusted_public_key(config.ISSUER_KEY_ID)

    if subcommand == "prove":
        audit_log = AuditLog(config.AUDIT_LOG_PATH)
        merkle_log = MerkleAuditLog(audit_log, private_key, config.ISSUER_KEY_ID)
        entry, proof, head = merkle_log.prove_inclusion(seq)

        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(export_receipt(entry, proof, head), f, indent=2)

        print(f"Audit entry #{entry.seq}: {entry.event_type} decision={entry.decision} reason={entry.reason!r}")
        print(f"Inclusion proof: {len(proof)} sibling hash(es)")
        print(f"Signed Merkle root: {head.root_hash.hex()} (tree_size={head.tree_size})")
        ok = verify_inclusion(entry, proof, head, trusted_public_key)
        print("INCLUSION PROOF VERIFIED" if ok else "INCLUSION PROOF FAILED")
        print(f"Receipt saved to {receipt_path}")
        raise SystemExit(0 if ok else 1)

    # subcommand == "check"
    with open(receipt_path, "r", encoding="utf-8") as f:
        pinned_entry, proof, head = import_receipt(json.load(f))

    audit_log = AuditLog(config.AUDIT_LOG_PATH)
    current_entries = {e.seq: e for e in audit_log.all_entries()}
    if seq not in current_entries:
        print(f"No audit entry with seq={seq} in the current log.")
        raise SystemExit(1)
    current_entry = current_entries[seq]

    if current_entry != pinned_entry:
        print(f"NOTE: entry #{seq} on disk differs from the pinned receipt (reason={current_entry.reason!r}).")

    ok = verify_inclusion(current_entry, proof, head, trusted_public_key)
    print("INCLUSION PROOF VERIFIED" if ok else "INCLUSION PROOF FAILED -- entry does not match the pinned receipt")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
