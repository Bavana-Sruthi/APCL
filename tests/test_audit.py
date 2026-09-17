import json

from covenant.audit import AuditLog


def test_append_and_chain_intact(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.append(event_type="grant_issued", grant_id="grant-1", subject="demo-agent", reason="tools=[...]")
    log.append(event_type="tool_call", grant_id="grant-1", tool_name="read_thread", decision="allow", reason="Allowed.")
    log.append(event_type="tool_call", grant_id="grant-1", tool_name="send_reply", decision="deny", reason="Capability does not permit this action.")

    ok, bad_seq = log.verify_chain()
    assert ok
    assert bad_seq is None


def test_log_reloads_and_continues_chain(tmp_path):
    path = tmp_path / "audit.log"
    log1 = AuditLog(path)
    log1.append(event_type="grant_issued", grant_id="grant-1", subject="demo-agent")

    log2 = AuditLog(path)  # simulate process restart
    entry = log2.append(event_type="tool_call", grant_id="grant-1", tool_name="read_thread", decision="allow")
    assert entry.seq == 2
    ok, _ = log2.verify_chain()
    assert ok


def test_hash_chain_detects_tamper(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append(event_type="grant_issued", grant_id="grant-1", subject="demo-agent")
    log.append(event_type="tool_call", grant_id="grant-1", tool_name="read_thread", decision="allow")
    log.append(event_type="tool_call", grant_id="grant-1", tool_name="send_reply", decision="deny")

    # Tamper with the on-disk record of entry #2 (change what tool it names).
    # A middle entry's tamper is caught because it breaks the *next* entry's
    # prev_hash link -- tampering the last entry instead needs a signed
    # Merkle head over it, which is what test_merkle.py covers.
    lines = path.read_text(encoding="utf-8").splitlines()
    entry2 = json.loads(lines[1])
    assert entry2["tool_name"] == "read_thread"
    entry2["tool_name"] = "send_reply"
    lines[1] = json.dumps(entry2, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tampered_log = AuditLog(path)
    ok, bad_seq = tampered_log.verify_chain()
    assert not ok
    assert bad_seq == 3  # entry #2's hash changed, so entry #3's prev_hash no longer matches
