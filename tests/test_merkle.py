import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from covenant.audit import AuditEntry, AuditLog
from covenant.merkle import MerkleAuditLog, MerkleTree, export_receipt, import_receipt, leaf_hash, verify_inclusion


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _seed_log(tmp_path, n=5):
    log = AuditLog(tmp_path / "audit.log")
    for i in range(n):
        log.append(event_type="tool_call", grant_id="grant-1", tool_name=f"tool_{i}", decision="allow")
    return log


def test_inclusion_proof_verifies_for_every_leaf(tmp_path, key):
    log = _seed_log(tmp_path, n=7)  # odd count exercises the duplicate-last-node path
    merkle_log = MerkleAuditLog(log, key, "key-1")

    for entry in log.all_entries():
        entry, proof, head = merkle_log.prove_inclusion(entry.seq)
        assert verify_inclusion(entry, proof, head, key.public_key())


def test_tampered_entry_fails_inclusion_proof(tmp_path, key):
    log = _seed_log(tmp_path, n=4)
    merkle_log = MerkleAuditLog(log, key, "key-1")
    entry, proof, head = merkle_log.prove_inclusion(2)

    tampered_entry = AuditEntry(**{**entry.__dict__, "decision": "deny"})
    assert not verify_inclusion(tampered_entry, proof, head, key.public_key())


def test_flipped_signature_byte_fails_verification(tmp_path, key):
    log = _seed_log(tmp_path, n=3)
    merkle_log = MerkleAuditLog(log, key, "key-1")
    entry, proof, head = merkle_log.prove_inclusion(1)

    bad_sig = bytearray(head.signature)
    bad_sig[0] ^= 0xFF
    tampered_head = head.__class__(**{**head.__dict__, "signature": bytes(bad_sig)})
    assert not verify_inclusion(entry, proof, tampered_head, key.public_key())


def test_wrong_public_key_fails_verification(tmp_path, key):
    log = _seed_log(tmp_path, n=3)
    merkle_log = MerkleAuditLog(log, key, "key-1")
    entry, proof, head = merkle_log.prove_inclusion(1)

    other_key = Ed25519PrivateKey.generate()
    assert not verify_inclusion(entry, proof, head, other_key.public_key())


def test_receipt_round_trip_survives_json(tmp_path, key):
    log = _seed_log(tmp_path, n=4)
    merkle_log = MerkleAuditLog(log, key, "key-1")
    entry, proof, head = merkle_log.prove_inclusion(3)

    receipt = import_receipt(export_receipt(entry, proof, head))
    restored_entry, restored_proof, restored_head = receipt
    assert restored_entry == entry
    assert restored_proof == proof
    assert restored_head == head
    assert verify_inclusion(restored_entry, restored_proof, restored_head, key.public_key())


def test_pinned_receipt_catches_later_tampering(tmp_path, key):
    """The scenario the demo relies on: a receipt taken BEFORE a tamper still
    fails when checked against the entry's state AFTER the tamper -- proving
    the tamper, rather than a freshly-recomputed root papering over it."""
    log = _seed_log(tmp_path, n=4)
    merkle_log = MerkleAuditLog(log, key, "key-1")
    entry, proof, head = merkle_log.prove_inclusion(2)  # the pinned receipt, taken before any tampering

    assert entry.decision == "allow"
    tampered_entry = AuditEntry(**{**entry.__dict__, "decision": "deny"})  # what's "on disk" now
    assert not verify_inclusion(tampered_entry, proof, head, key.public_key())


def test_single_leaf_tree_root_is_its_own_leaf_hash():
    log_entries = [AuditEntry(seq=1, timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                               event_type="tool_call", grant_id="g", subject=None, tool_name="t",
                               decision="allow", reason=None, prev_hash="0" * 64)]
    tree = MerkleTree([leaf_hash(e) for e in log_entries])
    assert tree.root == leaf_hash(log_entries[0])
    assert tree.inclusion_proof(0) == []
