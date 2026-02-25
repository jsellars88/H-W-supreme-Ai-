#!/usr/bin/env python3
"""
decision_ledger.py - High-Risk AI Decision Ledger v0.2
Forensic-grade: Ed25519 signatures + hash chaining.
One file. One invariant. One exportable proof.
"""

import hashlib
import json
import secrets
import sqlite3
import time
import sys
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple

# Ed25519 signatures - REQUIRED, no fallback
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
except ImportError:
    print("\nERROR: PyNaCl is required for production use.")
    print("   Install: pip install pynacl")
    print("   This ledger uses Ed25519 signatures for third-party verification.")
    print("   HMAC fallback would break the forensic chain.\n")
    sys.exit(1)


@dataclass
class DecisionRecord:
    """The atomic unit of governance proof - now with hash chaining."""
    # Core identifiers
    decision_id: str
    input_hash: str

    # Context
    model_version: str
    model_fingerprint: str
    policy_version: str
    operator_id: str
    risk_tier: str

    # Temporal
    timestamp: str
    nonce: str
    nonce_scope: str  # What action this nonce authorizes

    # Chain integrity
    prev_hash: str
    record_hash: str

    # Cryptographic binding
    signature: str

    # Schema evolution
    schema_version: str = "v0.2"


class DecisionLedger:
    """
    One responsibility: cryptographically bind decisions with exportable proof.
    Now with:
    - Ed25519 signatures (public-key verification)
    - Hash chaining (append-only integrity)
    - Schema versioning
    - Sequence-guaranteed ordering
    - Atomic transactions
    """

    def __init__(self, db_path: str = "decisions.db",
                 signing_key_hex: Optional[str] = None,
                 pubkey_anchor: Optional[str] = None):
        """
        Initialize with Ed25519 keypair.
        In production: load from HSM or secure storage.
        """
        self.db_path = db_path
        self.db = sqlite3.connect(db_path)

        # Enable foreign keys and transactions
        self.db.execute("PRAGMA foreign_keys = ON")

        # Ed25519 setup - REQUIRED
        if signing_key_hex:
            self.signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)
        else:
            self.signing_key = SigningKey.generate()

        self.verify_key = self.signing_key.verify_key
        self.pubkey_hex = self.verify_key.encode(encoder=HexEncoder).decode()

        # External anchor (e.g., published in DNS, blockchain, GitHub commit)
        self.pubkey_anchor = pubkey_anchor or self.pubkey_hex

        self._init_db()

    def _init_db(self):
        """Schema v0.2 with hash chain, Ed25519, and sequence guarantee."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT UNIQUE NOT NULL,
                input_hash TEXT NOT NULL,
                model_version TEXT NOT NULL,
                model_fingerprint TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                nonce_scope TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                schema_version TEXT NOT NULL
            )
        """)

        # Track chain head for quick access (optimization only - not trusted)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS chain_head (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_record_hash TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        self.db.commit()

    def _get_chain_head(self) -> Tuple[str, int]:
        """
        Get the last record hash and total count.
        chain_head is an optimization cache only - we verify from decisions if inconsistent.
        """
        # First, get actual count from decisions
        count_row = self.db.execute("SELECT COUNT(*) FROM decisions").fetchone()
        actual_count = count_row[0] if count_row else 0

        # Get last record hash from decisions (source of truth)
        last_row = self.db.execute("""
            SELECT record_hash FROM decisions
            ORDER BY seq DESC LIMIT 1
        """).fetchone()
        actual_last_hash = last_row[0] if last_row else "0" * 64

        # Try to get cached head
        cached = self.db.execute(
            "SELECT last_record_hash, record_count FROM chain_head WHERE id = 1"
        ).fetchone()

        if cached:
            cached_hash, cached_count = cached
            # If cache matches reality, use it
            if cached_hash == actual_last_hash and cached_count == actual_count:
                return cached_hash, cached_count

        # Cache is stale or missing - return actual values
        return actual_last_hash, actual_count

    def _update_chain_head(self, record_hash: str, count: int):
        """Update chain head cache after successful insert."""
        self.db.execute("""
            INSERT OR REPLACE INTO chain_head (id, last_record_hash, record_count, updated_at)
            VALUES (1, ?, ?, ?)
        """, (record_hash, count, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        # Note: no commit here - caller manages transaction

    def _hash_input(self, decision_input: Dict[str, Any]) -> str:
        """Canonical JSON hash of the decision being governed."""
        canonical = json.dumps(decision_input, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _sign(self, data: bytes) -> str:
        """Sign with Ed25519 - no fallback."""
        sig = self.signing_key.sign(data).signature
        return sig.hex()

    def record(self, decision_input: Dict[str, Any],
               model_version: str, model_fingerprint: str,
               policy_version: str, operator_id: str,
               risk_tier: str, nonce_scope: str = "authorization") -> DecisionRecord:
        """
        Record a high-risk AI decision with:
        - Hash chaining (prev_hash -> record_hash)
        - Ed25519 signature over the record hash
        - Sequence-guaranteed ordering (AUTOINCREMENT)
        - Atomic transaction
        """
        # Start transaction
        self.db.execute("BEGIN")

        try:
            # Get chain state
            prev_hash, count = self._get_chain_head()
            new_count = count + 1

            # Generate components
            input_hash = self._hash_input(decision_input)
            nonce = secrets.token_hex(16)
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            decision_id = hashlib.sha256(
                f"{input_hash}:{nonce}:{timestamp}".encode()
            ).hexdigest()[:16]

            # Build record without signature first
            record_dict = {
                "decision_id": decision_id,
                "input_hash": input_hash,
                "model_version": model_version,
                "model_fingerprint": model_fingerprint,
                "policy_version": policy_version,
                "operator_id": operator_id,
                "risk_tier": risk_tier,
                "timestamp": timestamp,
                "nonce": nonce,
                "nonce_scope": nonce_scope,
                "prev_hash": prev_hash,
                "schema_version": "v0.2"
            }

            # Compute record hash (includes everything except signature)
            canonical = json.dumps(record_dict, sort_keys=True, separators=(',', ':'))
            record_hash = hashlib.sha256(canonical.encode()).hexdigest()

            # Sign the record hash
            signature = self._sign(record_hash.encode())

            # Create full record
            record = DecisionRecord(
                decision_id=decision_id,
                input_hash=input_hash,
                model_version=model_version,
                model_fingerprint=model_fingerprint,
                policy_version=policy_version,
                operator_id=operator_id,
                risk_tier=risk_tier,
                timestamp=timestamp,
                nonce=nonce,
                nonce_scope=nonce_scope,
                prev_hash=prev_hash,
                record_hash=record_hash,
                signature=signature,
                schema_version="v0.2"
            )

            # Store immutably (seq autoincrements)
            self.db.execute("""
                INSERT INTO decisions (
                    decision_id, input_hash, model_version, model_fingerprint,
                    policy_version, operator_id, risk_tier, timestamp,
                    nonce, nonce_scope, prev_hash, record_hash, signature,
                    schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.decision_id, record.input_hash,
                record.model_version, record.model_fingerprint,
                record.policy_version, record.operator_id,
                record.risk_tier, record.timestamp,
                record.nonce, record.nonce_scope,
                record.prev_hash, record.record_hash,
                record.signature, record.schema_version
            ))

            # Update chain head cache
            self._update_chain_head(record_hash, new_count)

            # Commit transaction
            self.db.commit()

            return record

        except Exception as e:
            # Rollback on any error
            self.db.rollback()
            raise RuntimeError(f"Failed to record decision: {e}") from e

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the entire hash chain from genesis to head.
        Uses sequence order (AUTOINCREMENT) - not timestamp.
        Returns verification status and first broken link if any.
        """
        # Use sequence order - this is the source of truth
        rows = self.db.execute("""
            SELECT * FROM decisions
            ORDER BY seq ASC
        """).fetchall()

        if not rows:
            return {"valid": True, "message": "Empty chain", "record_count": 0}

        prev_hash = "0" * 64
        for row in rows:
            # Reconstruct record dict without signature
            record_dict = {
                "decision_id": row[1],
                "input_hash": row[2],
                "model_version": row[3],
                "model_fingerprint": row[4],
                "policy_version": row[5],
                "operator_id": row[6],
                "risk_tier": row[7],
                "timestamp": row[8],
                "nonce": row[9],
                "nonce_scope": row[10],
                "prev_hash": row[11],
                "schema_version": row[14]
            }

            # Check prev_hash matches
            if record_dict["prev_hash"] != prev_hash:
                return {
                    "valid": False,
                    "broken_at": row[1],
                    "expected_prev": prev_hash,
                    "actual_prev": record_dict["prev_hash"],
                    "message": f"Hash chain broken at seq {row[0]}"
                }

            # Verify record hash
            canonical = json.dumps(record_dict, sort_keys=True, separators=(',', ':'))
            computed_hash = hashlib.sha256(canonical.encode()).hexdigest()
            if computed_hash != row[12]:
                return {
                    "valid": False,
                    "broken_at": row[1],
                    "message": f"Record hash mismatch at seq {row[0]} (tampering detected)"
                }

            prev_hash = computed_hash

        return {"valid": True, "record_count": len(rows), "chain_head": prev_hash}

    def export_proof(self, decision_id: str) -> Dict[str, Any]:
        """Export a complete evidence packet with chain verification."""
        row = self.db.execute(
            "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if not row:
            return {"error": "Decision not found"}

        # Reconstruct record
        record = DecisionRecord(
            decision_id=row[1],
            input_hash=row[2],
            model_version=row[3],
            model_fingerprint=row[4],
            policy_version=row[5],
            operator_id=row[6],
            risk_tier=row[7],
            timestamp=row[8],
            nonce=row[9],
            nonce_scope=row[10],
            prev_hash=row[11],
            record_hash=row[12],
            signature=row[13],
            schema_version=row[14]
        )

        # Verify signature using the ledger's public key
        sig_valid = False
        sig_error = None
        try:
            vk = VerifyKey(self.pubkey_hex, encoder=HexEncoder)
            vk.verify(record.record_hash.encode(), bytes.fromhex(record.signature))
            sig_valid = True
        except Exception as e:
            sig_error = str(e)[:120]

        # Verify entire chain (not just this record)
        chain_verification = self.verify_chain()

        return {
            "record": asdict(record),
            "verification": {
                "signature_valid": sig_valid,
                "signature_error": sig_error,
                "chain_valid": chain_verification.get("valid", False),
                "chain_details": chain_verification,
                "ledger_pubkey": self.pubkey_hex,
                "pubkey_anchor": self.pubkey_anchor,
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            "human_readable": (
                f"Decision {record.decision_id} by {record.operator_id} "
                f"under policy {record.policy_version} at {record.timestamp}"
            )
        }

    def export_full_ledger(self) -> Dict[str, Any]:
        """
        Export the entire ledger for third-party chain verification.
        Contains all records in sequence order + public key.
        No private key material is included.
        """
        rows = self.db.execute("""
            SELECT * FROM decisions ORDER BY seq ASC
        """).fetchall()

        records = []
        for row in rows:
            records.append({
                "decision_id": row[1],
                "input_hash": row[2],
                "model_version": row[3],
                "model_fingerprint": row[4],
                "policy_version": row[5],
                "operator_id": row[6],
                "risk_tier": row[7],
                "timestamp": row[8],
                "nonce": row[9],
                "nonce_scope": row[10],
                "prev_hash": row[11],
                "record_hash": row[12],
                "signature": row[13],
                "schema_version": row[14],
            })

        return {
            "ledger_pubkey": self.pubkey_hex,
            "pubkey_anchor": self.pubkey_anchor,
            "record_count": len(records),
            "records": records,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def close(self):
        """Clean up database connection."""
        if self.db:
            self.db.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure DB is closed."""
        self.close()


# Demo (runs if you execute this file directly)
if __name__ == "__main__":
    print("\nHIGH-RISK AI DECISION LEDGER v0.2")
    print("   Ed25519 Signatures + Hash Chaining + Sequence Ordering")
    print("=" * 60)

    # Capture pubkey before context manager closes
    pubkey_for_display = None
    anchor_for_display = None

    with DecisionLedger("test_ledger.db") as ledger:
        pubkey_for_display = ledger.pubkey_hex
        anchor_for_display = ledger.pubkey_anchor

        print(f"Ledger Public Key: {pubkey_for_display[:32]}...")
        print(f"Public Key Anchor: {anchor_for_display[:32]}...")

        # Record a decision
        decision = {
            "action": "approve_loan",
            "amount": 50000,
            "applicant_risk_score": 0.72,
            "explanation": "Applicant meets threshold despite elevated risk due to collateral"
        }

        record = ledger.record(
            decision_input=decision,
            model_version="credit-scoring-v2.1",
            model_fingerprint=hashlib.sha256(b"credit-scoring-v2.1-weights").hexdigest(),
            policy_version="lending-policy-2026-02",
            operator_id="operator-8372",
            risk_tier="T3_HIGH",
            nonce_scope="loan_approval"
        )

        print(f"\nRECORDED: {record.decision_id}")
        print(f"   Input hash:  {record.input_hash[:16]}...")
        print(f"   Prev hash:   {record.prev_hash[:16]}...")
        print(f"   Record hash: {record.record_hash[:16]}...")

        # Get chain position
        count = ledger._get_chain_head()[1]
        print(f"   Chain position: {count}")

        # Export proof
        proof = ledger.export_proof(record.decision_id)
        print(f"\nEXPORT PROOF:")
        print(f"   Signature valid: {proof['verification']['signature_valid']}")
        if proof['verification'].get('signature_error'):
            print(f"   Signature error: {proof['verification']['signature_error']}")
        print(f"   Chain valid: {proof['verification']['chain_valid']}")
        print(f"   {proof['human_readable']}")

        # Save to file
        with open("evidence_packet.json", "w") as f:
            json.dump(proof, f, indent=2)
        print("\nEvidence saved to evidence_packet.json")

        # Verify entire chain
        chain = ledger.verify_chain()
        print(f"\nChain verification: {'PASS' if chain['valid'] else 'FAIL'}")
        if chain['valid']:
            print(f"   Records: {chain['record_count']}")
            print(f"   Head: {chain['chain_head'][:16]}...")

        # Export full ledger for third-party chain verification
        full_export = ledger.export_full_ledger()
        with open("full_ledger_export.json", "w") as f:
            json.dump(full_export, f, indent=2)
        print(f"\nFull ledger exported to full_ledger_export.json"
              f" ({full_export['record_count']} records)")

    # Now outside the context manager, using captured values
    print("\n" + "=" * 60)
    print("\nEXTERNAL VERIFICATION INSTRUCTIONS:")
    print("   1. Publish this public key in advance:")
    print(f"      {pubkey_for_display}")
    print("   2. Hand a third party:")
    print("      - evidence_packet.json      (single record proof)")
    print("      - full_ledger_export.json   (full chain proof)")
    print("      - verify_evidence.py        (verifier script)")
    print("   3. They run:")
    print("      python verify_evidence.py evidence_packet.json")
    print("      python verify_evidence.py --chain full_ledger_export.json")
    print("=" * 60)
