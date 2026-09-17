#!/usr/bin/env bash
# The full ~90-second Covenant demo, unattended:
#   1. Live proxy grants a capability (auto-consent: read+draft yes, send no).
#   2. read_thread / draft_reply succeed; send_reply is denied with a reason.
#   3. The capability's short TTL expires for real; replaying send_reply is
#      denied because it's dead, not because of scope.
#   4. Three attacker scenarios (expired replay, audience swap, scope
#      widening) run against the same Broker/Issuer the live proxy uses.
#   5. A Merkle inclusion proof is pinned as a receipt, verified, then shown
#      to fail once the underlying audit log is tampered with.
#
# Everything here drives real code paths -- nothing is mocked at the
# enforcement layer. Only the "agent"'s actions and the human's consent are
# pre-scripted, exactly as covenant/README.md documents.
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="python3"
if [ -x ".venv/Scripts/python.exe" ]; then PYTHON=".venv/Scripts/python.exe"; fi
if [ -x ".venv/bin/python" ]; then PYTHON=".venv/bin/python"; fi

rm -rf .covenant-data
RECEIPT=".covenant-data/receipt-entry-1.json"

echo "############################################################"
echo "# Covenant demo"
echo "############################################################"

echo
echo ">>> [1/5] Live proxy: grant, allowed read/draft, denied send, expiry replay"
"$PYTHON" demo/scripted_client.py 5

echo
echo ">>> [2/5] Attacker mode: expired replay / audience swap / scope widening"
"$PYTHON" demo/attacker_mode.py

echo
echo ">>> [3/5] Pinning a Merkle inclusion receipt for audit entry #1 (the first grant)"
"$PYTHON" -m covenant.merkle prove 1 "$RECEIPT"

echo
echo ">>> [4/5] Re-checking the pinned receipt against the current (untampered) log"
"$PYTHON" -m covenant.merkle check 1 "$RECEIPT"

echo
echo ">>> [5/5] Tampering with the on-disk audit log, then re-checking the SAME pinned receipt"
"$PYTHON" - ".covenant-data/audit.log" <<'PYEOF'
import json
import sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
entry = json.loads(lines[0])
entry["reason"] = "TAMPERED: " + str(entry.get("reason"))
lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("(tampered entry #1's on-disk 'reason' field)")
PYEOF

set +e
"$PYTHON" -m covenant.merkle check 1 "$RECEIPT"
STATUS=$?
set -e

echo
if [ "$STATUS" -ne 0 ]; then
    echo "(expected) tamper detected -- the pinned receipt no longer verifies against the mutated entry."
else
    echo "UNEXPECTED: tamper was not detected. This is a bug."
    exit 1
fi

echo
echo "Demo complete."
