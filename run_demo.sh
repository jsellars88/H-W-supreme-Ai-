#!/usr/bin/env bash

# Holmes & Watson Supreme AI™ — 5-Minute Governance Demo
# WhiteSwan OS | Cornerstone v2.0
#
# This script runs the full closed-loop demo end-to-end.
# Requires: Python 3.9+, uvicorn, fastapi, cryptography
#
# Usage: bash run_demo.sh

set -euo pipefail
BASE="http://localhost:8080"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Holmes & Watson Supreme AI™ — Closed-Loop Governance Demo"
echo "  WhiteSwan OS | Cornerstone v2.0"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "  [STEP 0] Starting governance kernel…"
uvicorn cornerstone:app --port 8080 --log-level error &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true' EXIT
sleep 2

PUBKEY=$(curl -s "$BASE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['public_key_b64'])")
echo "  Kernel online. Public key: ${PUBKEY:0:32}…"

echo ""
echo "  [STEP 1] Operator issues handshake (alice@bank.com, T3_HIGH)"
HS_RESP=$(curl -s -X POST "$BASE/handshake" \
  -H "Content-Type: application/json" \
  -d '{"operator_id":"alice@bank.com","tier":"T3_HIGH","ttl_minutes":10}')
echo "$HS_RESP" | python3 -m json.tool
TOKEN=$(echo "$HS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_id'])")
echo "  → Token issued: $TOKEN"

echo ""
echo "  [STEP 2] AI submits governed action — $50,000 loan approval"
ACTION_RESP=$(curl -s -X POST "$BASE/action" \
  -H "Content-Type: application/json" \
  -d "{
\"action_type\": \"loan_approval\",
\"tier\": \"T3_HIGH\",
\"operator_id\": \"alice@bank.com\",
\"payload\": {
\"amount\": 50000,
\"applicant_id\": \"CUST-12345\",
\"credit_score\": 720,
\"ai_recommendation\": \"approve\",
\"ai_model\": \"claude-sonnet-4\"
},
\"handshake_tokens\": [\"$TOKEN\"]
}")
echo "$ACTION_RESP" | python3 -m json.tool
DECISION_ID=$(echo "$ACTION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision_id'])")
echo "  → Decision ID: $DECISION_ID"

echo ""
echo "  [STEP 3] AI attempts action WITHOUT authorization"
curl -s -X POST "$BASE/action" \
  -H "Content-Type: application/json" \
  -d '{
"action_type": "wire_transfer",
"tier": "T3_HIGH",
"operator_id": "rogue_agent",
"payload": {"amount": 99999, "destination": "external"},
"handshake_tokens": []
}' | python3 -m json.tool

echo ""
echo "  [STEP 4] Export evidence packet for decision $DECISION_ID"
curl -s "$BASE/export/$DECISION_ID" > /tmp/evidence.json
echo "  Evidence saved to /tmp/evidence.json"
cat /tmp/evidence.json | python3 -c '
import sys, json
d = json.load(sys.stdin)
p = d["evidence_packet"]
print(f"  Decision: {p['"'"'decision_id'"'"']}")
print(f"  Outcome:  {p['"'"'outcome'"'"']}")
print(f"  Hash:     {p['"'"'entry_hash'"'"'][:40]}…")
print(f"  Sig:      {p['"'"'signature'"'"'][:40]}…")
'

echo ""
echo "  [STEP 5] Third-party verification (no server trust required)"
python3 verify_evidence.py /tmp/evidence.json "$PUBKEY"

echo ""
echo "  [STEP 6] Full chain integrity audit"
curl -s "$BASE/verify" | python3 -m json.tool

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Demo complete."
echo "  Every decision: authorized, signed, chained, verifiable."
echo "  This is ‘AI decisions you can prove to regulators.’"
echo "═══════════════════════════════════════════════════════════"
echo ""
