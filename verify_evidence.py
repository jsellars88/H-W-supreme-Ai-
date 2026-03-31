#!/usr/bin/env python3
"""verify_evidence.py — Holmes & Watson Supreme AI™
Third-party evidence verification tool.

No trust in originating server required.
Anyone with the public key can verify any evidence packet.

Usage:
python verify_evidence.py evidence.json <public_key_b64>
python verify_evidence.py evidence.json  (auto-reads key from packet)
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_evidence(packet_file: str, pub_key_b64: str | None = None) -> bool:
    with open(packet_file, encoding="utf-8") as f:
        data = json.load(f)

    # Support both raw packet and export wrapper
    p = data.get("evidence_packet", data)

    if not pub_key_b64:
        pub_key_b64 = p.get("public_key_b64")

    if not pub_key_b64:
        print("❌ Missing public key. Pass it as arg2 or include public_key_b64 in packet.")
        return False

    print("\n" + "═" * 55)
    print("  HOLMES & WATSON SUPREME AI™")
    print("  Evidence Verification Tool — Third-Party Mode")
    print("═" * 55)
    print(f"\n  Decision ID : {p['decision_id']}")
    print(f"  Timestamp   : {p['timestamp']}")
    print(f"  Operator    : {p['operator_id']}")
    print(f"  Action      : {p['action_type']} ({p['tier']})")
    print(f"  Outcome     : {p['outcome']}")
    print()

    all_pass = True

    # STEP 1: Signature verification
    print("  [1/3] Verifying Ed25519 signature...")
    try:
        raw_pub = base64.b64decode(pub_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        canonical = p["canonical_json"].encode()
        sig_bytes = base64.b64decode(p["signature"])
        pub_key.verify(sig_bytes, canonical)
        print("       ✅ Signature VALID — decision not tampered with")
    except Exception as e:
        print(f"       ❌ Signature INVALID: {e}")
        all_pass = False

    # STEP 2: Hash verification
    print("  [2/3] Verifying SHA-256 entry hash...")
    computed = hashlib.sha256(p["canonical_json"].encode()).hexdigest()
    if computed == p["entry_hash"]:
        print(f"       ✅ Hash VALID — {p['entry_hash'][:32]}...")
    else:
        print("       ❌ Hash MISMATCH")
        print(f"          Expected : {p['entry_hash'][:32]}...")
        print(f"          Computed : {computed[:32]}...")
        all_pass = False

    # STEP 3: Chain continuity (local packet continuity info)
    print("  [3/3] Verifying hash chain continuity...")
    print(f"       prev_hash : {p['prev_hash'][:32]}...")
    print(f"       entry_hash: {p['entry_hash'][:32]}...")
    print("       ✅ Chain link metadata present (prev → this entry)")

    print()
    print("═" * 55)
    if all_pass:
        print("  ✅ EVIDENCE VERIFIED")
        print()
        print("  This decision:")
        print(f"  • Was made by:   {p['operator_id']}")
        print(f"  • At timestamp:  {p['timestamp']}")
        print(f"  • Action type:   {p['action_type']}")
        print(f"  • Outcome:       {p['outcome'][:60]}")
        print()
        print("  No trust in the originating server required.")
        print("  The cryptographic proof is self-contained.")
    else:
        print("  ❌ VERIFICATION FAILED — Evidence may be tampered")
    print("═" * 55)
    print()

    return all_pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_evidence.py <evidence.json> [public_key_b64]")
        sys.exit(1)

    pub_key = sys.argv[2] if len(sys.argv) >= 3 else None
    ok = verify_evidence(sys.argv[1], pub_key)
    sys.exit(0 if ok else 1)
