#!/usr/bin/env python3
"""verify_evidence.py — WhiteSwan Forensic Ledger Evidence Verifier."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:
    print("❌  PyNaCl required: pip install pynacl")
    sys.exit(2)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


CANONICAL_FIELDS = [
    "decision_id",
    "key_id",
    "input_hash",
    "model_version",
    "model_fingerprint",
    "policy_version",
    "operator_id",
    "risk_tier",
    "timestamp",
    "nonce",
    "nonce_scope",
    "prev_hash",
    "schema_version",
]


def extract_canonical(record: dict[str, Any]) -> bytes:
    return canonical_json({k: record[k] for k in CANONICAL_FIELDS if k in record})


def check_hash(record: dict[str, Any]) -> tuple[bool, str]:
    signed_payload = extract_canonical(record)
    computed_hash = hashlib.sha256(signed_payload).hexdigest()
    stored_hash = record.get("record_hash", "")
    if computed_hash == stored_hash:
        return True, f"sha256 match: {computed_hash[:32]}..."
    return False, f"hash MISMATCH\n  computed: {computed_hash}\n  stored:   {stored_hash}"


def check_signature(record: dict[str, Any], pubkey_hex: str) -> tuple[bool, str]:
    signed_payload = extract_canonical(record)
    sig_hex = record.get("signature", "")
    key_id = record.get("key_id", "unknown")

    try:
        vk = VerifyKey(bytes.fromhex(pubkey_hex))
        vk.verify(signed_payload, bytes.fromhex(sig_hex))
        return True, f"Ed25519 valid (key_id={key_id[:8]}...)"
    except BadSignatureError:
        return False, f"Ed25519 signature INVALID (key_id={key_id[:8]}...)"
    except Exception as e:
        return False, f"Signature check error: {e}"


def check_predecessor(
    record: dict[str, Any], predecessor: dict[str, Any] | None
) -> tuple[bool, str]:
    prev_hash = record.get("prev_hash", "")
    if predecessor:
        expected = predecessor.get("record_hash", "")
        if prev_hash == expected:
            return True, f"prev_hash links to predecessor {expected[:16]}..."
        return (
            False,
            "prev_hash MISMATCH\n"
            f"  record.prev_hash:          {prev_hash}\n"
            f"  predecessor.record_hash:   {expected}",
        )

    if len(prev_hash) == 64 and all(c in "0123456789abcdef" for c in prev_hash):
        return (
            True,
            f"prev_hash present: {prev_hash[:16]}... (predecessor not provided for chain check)",
        )
    return False, f"prev_hash malformed or missing: {prev_hash!r}"


def check_rekor(record: dict[str, Any], rekor_receipt: dict[str, Any] | None, pubkey_hex: str):
    del pubkey_hex
    if not rekor_receipt:
        return None, "no Rekor receipt in packet (anchoring may not have been enabled)"

    entry_uuid = rekor_receipt.get("entry_uuid") or rekor_receipt.get("rekor_uuid")
    if not entry_uuid or entry_uuid.startswith("offline"):
        return None, f"Rekor receipt is in offline/mock mode (uuid={entry_uuid})"

    try:
        import requests
    except ImportError:
        return None, "requests not installed — pip install requests to enable Rekor check"

    fetch_url = f"https://rekor.sigstore.dev/api/v1/log/entries/{entry_uuid}"

    try:
        response = requests.get(fetch_url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return False, f"Rekor fetch failed: {e}\n  URL: {fetch_url}"

    entry_data = next(iter(data.values()), {})
    body_b64 = entry_data.get("body", "")
    try:
        body = json.loads(base64.b64decode(body_b64 + "==").decode())
    except Exception as e:
        return False, f"Failed to decode Rekor entry body: {e}"

    stored_hash = body.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
    stored_sig_b64 = body.get("spec", {}).get("signature", {}).get("content", "")
    stored_sig_hex = bytes(base64.b64decode(stored_sig_b64 + "==")).hex()

    record_hash = record.get("record_hash", "")
    signature = record.get("signature", "")

    if stored_hash.lower() != record_hash.lower():
        return False, f"Rekor entry hash MISMATCH\n  rekor:  {stored_hash}\n  record: {record_hash}"
    if stored_sig_hex.lower() != signature.lower():
        return False, "Rekor entry signature does not match record.signature"

    log_index = entry_data.get("logIndex", "?")
    int_time = rekor_receipt.get("integrated_time", "?")
    return True, (
        "Rekor VERIFIED\n"
        f"  logIndex:       {log_index}\n"
        f"  integratedTime: {int_time}\n"
        f"  entry URL:      {fetch_url}"
    )


def verify(
    packet_path: str,
    pubkey_hex: str,
    predecessor_path: str | None = None,
    check_rekor_flag: bool = False,
    quiet: bool = False,
) -> bool:
    def pr(*args, **kwargs):
        if not quiet:
            print(*args, **kwargs)

    try:
        with open(packet_path, encoding="utf-8") as f:
            packet = json.load(f)
    except Exception as e:
        print(f"❌  Cannot load packet: {e}")
        return False

    record = packet.get("record", packet)

    predecessor = None
    if predecessor_path:
        try:
            with open(predecessor_path, encoding="utf-8") as f:
                pred_packet = json.load(f)
            predecessor = pred_packet.get("record", pred_packet)
        except Exception as e:
            print(f"❌  Cannot load predecessor: {e}")
            return False

    rekor_receipt = packet.get("evidence", {}).get("rekor") or packet.get("rekor")

    all_pass = True
    checks = [
        ("Hash integrity", *check_hash(record)),
        ("Ed25519 signature", *check_signature(record, pubkey_hex)),
        ("Chain ordering", *check_predecessor(record, predecessor)),
    ]
    if check_rekor_flag:
        checks.append(("Rekor inclusion", *check_rekor(record, rekor_receipt, pubkey_hex)))

    for label, ok, msg in checks:
        sym = "✓" if ok is True else ("✗" if ok is False else "⚠")
        if ok is False:
            all_pass = False
        pr(f"{sym} {label:<20} {msg}")

    return all_pass


def main():
    parser = argparse.ArgumentParser(description="Verify a WhiteSwan evidence packet.")
    parser.add_argument("packet", help="Path to evidence packet JSON")
    parser.add_argument("--pubkey", required=True, help="Ed25519 public key hex")
    parser.add_argument("--predecessor", help="Path to predecessor evidence packet JSON (optional)")
    parser.add_argument("--rekor", action="store_true", help="Confirm Rekor inclusion")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    args = parser.parse_args()

    ok = verify(
        packet_path=args.packet,
        pubkey_hex=args.pubkey,
        predecessor_path=args.predecessor,
        check_rekor_flag=args.rekor,
        quiet=args.quiet,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
