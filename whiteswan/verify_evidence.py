#!/usr/bin/env python3
"""
verify_evidence.py - Third-party verifier for evidence_packet.json

Verifies:
- record_hash recomputation (tamper detection on fields)
- Ed25519 signature verification (third-party check)

Note: full chain verification requires the full ledger export (or a chain proof).
"""

import json
import hashlib
import sys
from typing import Any, Dict

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder


def canonical_record_dict(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reconstruct the exact dict used to compute record_hash in decision_ledger.py.
    Must match the ledger's record_dict fields and names.
    """
    return {
        "decision_id": record["decision_id"],
        "input_hash": record["input_hash"],
        "model_version": record["model_version"],
        "model_fingerprint": record["model_fingerprint"],
        "policy_version": record["policy_version"],
        "operator_id": record["operator_id"],
        "risk_tier": record["risk_tier"],
        "timestamp": record["timestamp"],
        "nonce": record["nonce"],
        "nonce_scope": record["nonce_scope"],
        "prev_hash": record["prev_hash"],
        "schema_version": record.get("schema_version", "v0.2"),
    }


def sha256_hex_canonical(d: Dict[str, Any]) -> str:
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_record(packet: Dict[str, Any],
                  pubkey_override: str = None) -> Dict[str, Any]:
    """
    Verify a single evidence packet. Returns structured result.
    Usable both from CLI and as an importable function.
    """
    record = packet["record"]

    pubkey_hex = pubkey_override or packet["verification"]["ledger_pubkey"]
    signature_hex = record["signature"]
    record_hash_claimed = record["record_hash"]

    # 1) Recompute record_hash
    rd = canonical_record_dict(record)
    record_hash_computed = sha256_hex_canonical(rd)
    hash_ok = (record_hash_computed == record_hash_claimed)

    # 2) Verify signature over record_hash (Ed25519)
    sig_ok = False
    sig_error = None
    try:
        vk = VerifyKey(pubkey_hex, encoder=HexEncoder)
        vk.verify(record_hash_claimed.encode(), bytes.fromhex(signature_hex))
        sig_ok = True
    except Exception as e:
        sig_error = str(e)

    return {
        "record_hash_matches": hash_ok,
        "signature_valid": sig_ok,
        "signature_error": sig_error,
        "pubkey_used": pubkey_hex,
        "decision_id": record["decision_id"],
    }


def verify_chain_export(export: Dict[str, Any],
                        pubkey_override: str = None) -> Dict[str, Any]:
    """
    Verify a full ledger export end-to-end:
    - Every record_hash recomputes correctly
    - Every prev_hash links to the prior record_hash
    - Every Ed25519 signature is valid
    """
    records = export.get("records", [])
    pubkey_hex = pubkey_override or export.get("ledger_pubkey", "")

    if not records:
        return {"valid": True, "message": "Empty chain", "record_count": 0}

    if not pubkey_hex:
        return {"valid": False, "message": "No public key provided or found in export"}

    prev_hash = "0" * 64
    for i, record in enumerate(records):
        # Check prev_hash linkage
        if record["prev_hash"] != prev_hash:
            return {
                "valid": False,
                "broken_at_index": i,
                "decision_id": record["decision_id"],
                "expected_prev": prev_hash,
                "actual_prev": record["prev_hash"],
                "message": f"Hash chain broken at index {i}",
            }

        # Recompute record_hash
        rd = canonical_record_dict(record)
        computed_hash = sha256_hex_canonical(rd)
        if computed_hash != record["record_hash"]:
            return {
                "valid": False,
                "broken_at_index": i,
                "decision_id": record["decision_id"],
                "message": f"Record hash mismatch at index {i} (tampering detected)",
            }

        # Verify signature
        try:
            vk = VerifyKey(pubkey_hex, encoder=HexEncoder)
            vk.verify(
                record["record_hash"].encode(),
                bytes.fromhex(record["signature"]),
            )
        except Exception as e:
            return {
                "valid": False,
                "broken_at_index": i,
                "decision_id": record["decision_id"],
                "message": f"Signature invalid at index {i}: {e}",
            }

        prev_hash = computed_hash

    return {
        "valid": True,
        "record_count": len(records),
        "chain_head": prev_hash,
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage:")
        print("  verify_evidence.py evidence_packet.json [pubkey_hex]")
        print("  verify_evidence.py --chain full_ledger_export.json [pubkey_hex]")
        return 2

    # Full chain mode
    if sys.argv[1] == "--chain":
        if len(sys.argv) < 3:
            print("Usage: verify_evidence.py --chain full_ledger_export.json [pubkey_hex]")
            return 2
        export_path = sys.argv[2]
        pubkey_override = sys.argv[3] if len(sys.argv) > 3 else None

        export = json.load(open(export_path, "r", encoding="utf-8"))
        result = verify_chain_export(export, pubkey_override)

        print("=== Full Chain Verification ===")
        print(f"chain_valid:  {result.get('valid', False)}")
        print(f"record_count: {result.get('record_count', 0)}")
        if result.get("chain_head"):
            print(f"chain_head:   {result['chain_head'][:32]}...")
        if result.get("message"):
            print(f"message:      {result['message']}")
        if result.get("broken_at_index") is not None:
            print(f"broken_at:    index {result['broken_at_index']}"
                  f" (decision {result.get('decision_id', '?')})")

        return 0 if result.get("valid", False) else 1

    # Single record mode
    packet_path = sys.argv[1]
    pubkey_override = sys.argv[2] if len(sys.argv) > 2 else None

    packet = json.load(open(packet_path, "r", encoding="utf-8"))
    result = verify_record(packet, pubkey_override)

    print("=== Evidence Verification ===")
    print(f"decision_id:         {result['decision_id']}")
    print(f"record_hash_matches: {result['record_hash_matches']}")
    print(f"signature_valid:     {result['signature_valid']}")
    if result["signature_error"]:
        print(f"signature_error:     {result['signature_error']}")

    # Chain note (honest + precise)
    print("\nNote: Full chain verification requires the full ledger export.")
    print("      Run with --chain flag on a full_ledger_export.json.")
    chain_claim = packet.get("verification", {}).get("chain_valid", None)
    if chain_claim is not None:
        print(f"chain_valid_claimed_in_packet: {chain_claim}")

    return 0 if (result["record_hash_matches"] and result["signature_valid"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
