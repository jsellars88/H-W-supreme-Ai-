#!/usr/bin/env python3
"""decision_ledger.py — Forensic AI Decision Ledger v0.4."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("\n❌  PyNaCl is required: pip install pynacl")
    sys.exit(1)

SCHEMA_VERSION = "v0.4"
GENESIS_HASH = "0" * 64


@dataclass
class DecisionRecord:
    """Atomic unit of governance proof."""

    decision_id: str
    key_id: str
    input_hash: str
    model_version: str
    model_fingerprint: str
    policy_version: str
    operator_id: str
    risk_tier: str
    timestamp: str
    nonce: str
    nonce_scope: str
    prev_hash: str
    record_hash: str
    signature: str
    schema_version: str = SCHEMA_VERSION


@dataclass
class KeyRecord:
    """Tracks signing key lifecycle for rotation."""

    key_id: str
    pubkey_hex: str
    created_at: str
    retired_at: Optional[str] = None
    notes: str = ""


class KeyCustody:
    """Loads or generates signing keys with strict file permissions."""

    def __init__(self, key_path: Optional[str] = None):
        self._sk: SigningKey
        self._key_id: str
        self._pubkey_hex: str

        if key_path:
            self._load_from_file(key_path)
        else:
            self._generate_ephemeral()

    def _load_from_file(self, path: str):
        p = Path(path)
        if not p.exists():
            sk = SigningKey.generate()
            hex_bytes = sk.encode(encoder=HexEncoder)
            p.write_bytes(hex_bytes)
            os.chmod(path, 0o600)
        else:
            mode = oct(os.stat(path).st_mode)[-3:]
            if mode not in ("600", "400"):
                raise PermissionError(
                    f"Key file {path} has permissions {mode}. "
                    "Must be 600 or 400 to prevent key exposure."
                )
            hex_bytes = p.read_bytes().strip()
            sk = SigningKey(hex_bytes, encoder=HexEncoder)

        self._sk = sk
        self._pubkey_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
        self._key_id = hashlib.sha256(sk.verify_key.encode()).hexdigest()[:16]

    def _generate_ephemeral(self):
        sk = SigningKey.generate()
        self._sk = sk
        self._pubkey_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
        self._key_id = hashlib.sha256(sk.verify_key.encode()).hexdigest()[:16]

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def pubkey_hex(self) -> str:
        return self._pubkey_hex

    def sign(self, payload_bytes: bytes) -> str:
        return self._sk.sign(payload_bytes).signature.hex()

    def verify(self, payload_bytes: bytes, signature_hex: str) -> bool:
        try:
            self._sk.verify_key.verify(payload_bytes, bytes.fromhex(signature_hex))
            return True
        except BadSignatureError:
            return False

    @classmethod
    def verify_external(
        cls,
        pubkey_hex: str,
        payload_bytes: bytes,
        signature_hex: str,
    ) -> bool:
        try:
            vk = VerifyKey(bytes.fromhex(pubkey_hex))
            vk.verify(payload_bytes, bytes.fromhex(signature_hex))
            return True
        except BadSignatureError:
            return False


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_canonical_fields(r: DecisionRecord) -> Dict[str, Any]:
    """Fields included in the signed payload (everything except `signature`)."""

    return {
        "decision_id": r.decision_id,
        "key_id": r.key_id,
        "input_hash": r.input_hash,
        "model_version": r.model_version,
        "model_fingerprint": r.model_fingerprint,
        "policy_version": r.policy_version,
        "operator_id": r.operator_id,
        "risk_tier": r.risk_tier,
        "timestamp": r.timestamp,
        "nonce": r.nonce,
        "nonce_scope": r.nonce_scope,
        "prev_hash": r.prev_hash,
        "schema_version": r.schema_version,
    }


class DecisionLedger:
    """Single-writer forensic ledger."""

    def __init__(
        self,
        db_path: str = "decisions.db",
        key_path: Optional[str] = None,
        key_custody: Optional[KeyCustody] = None,
    ):
        self._owner_thread_id = threading.get_ident()
        self._custody = key_custody or KeyCustody(key_path)

        self.db_path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode = WAL;")
        self.db.execute("PRAGMA synchronous  = FULL;")
        self.db.execute("PRAGMA temp_store   = MEMORY;")
        self.db.execute("PRAGMA foreign_keys = ON;")
        self._init_schema()

    @property
    def pubkey_hex(self) -> str:
        return self._custody.pubkey_hex

    @property
    def key_id(self) -> str:
        return self._custody.key_id

    def _init_schema(self):
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                seq               INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id       TEXT UNIQUE  NOT NULL,
                key_id            TEXT         NOT NULL,
                input_hash        TEXT         NOT NULL,
                model_version     TEXT         NOT NULL,
                model_fingerprint TEXT         NOT NULL,
                policy_version    TEXT         NOT NULL,
                operator_id       TEXT         NOT NULL,
                risk_tier         TEXT         NOT NULL,
                timestamp         TEXT         NOT NULL,
                nonce             TEXT UNIQUE  NOT NULL,
                nonce_scope       TEXT         NOT NULL,
                prev_hash         TEXT         NOT NULL,
                record_hash       TEXT UNIQUE  NOT NULL,
                signature         TEXT         NOT NULL,
                schema_version    TEXT         NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chain_head (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                last_record_hash TEXT    NOT NULL,
                record_count     INTEGER NOT NULL,
                key_id           TEXT    NOT NULL,
                updated_at       TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_registry (
                key_id     TEXT PRIMARY KEY,
                pubkey_hex TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retired_at TEXT,
                notes      TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp
                ON decisions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_decisions_operator
                ON decisions(operator_id);
            """
        )
        self.db.commit()
        self._register_current_key()

    def _register_current_key(self):
        existing = self.db.execute(
            "SELECT key_id FROM key_registry WHERE key_id=?", (self._custody.key_id,)
        ).fetchone()
        if not existing:
            self.db.execute(
                "INSERT INTO key_registry VALUES (?,?,?,NULL,?)",
                (
                    self._custody.key_id,
                    self._custody.pubkey_hex,
                    _now_z(),
                    "auto-registered on first use",
                ),
            )
            self.db.commit()

    def _assert_owner_thread(self):
        if threading.get_ident() != self._owner_thread_id:
            raise RuntimeError(
                "DecisionLedger.record() called from a non-owner thread. "
                "This ledger is single-writer by design. Use LedgerWriter.submit()."
            )

    def _get_chain_head(self) -> Tuple[str, int]:
        actual_count = self.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        last_row = self.db.execute(
            "SELECT record_hash FROM decisions ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        actual_last = last_row[0] if last_row else GENESIS_HASH

        cached = self.db.execute(
            "SELECT last_record_hash, record_count FROM chain_head WHERE id=1"
        ).fetchone()

        if cached:
            cached_hash, cached_count = cached
            if cached_hash == actual_last and cached_count == actual_count:
                return cached_hash, cached_count

        return actual_last, actual_count

    def _update_chain_head(self, record_hash: str, count: int):
        self.db.execute(
            """
            INSERT OR REPLACE INTO chain_head
            VALUES (1, ?, ?, ?, ?)
            """,
            (record_hash, count, self._custody.key_id, _now_z()),
        )

    def record(
        self,
        decision_input: Dict[str, Any],
        model_version: str,
        model_fingerprint: str,
        policy_version: str,
        operator_id: str,
        risk_tier: str,
        nonce_scope: str = "authorization",
    ) -> DecisionRecord:
        self._assert_owner_thread()

        self.db.execute("BEGIN IMMEDIATE")
        try:
            prev_hash, count = self._get_chain_head()
            new_count = count + 1

            input_hash = hashlib.sha256(canonical_json(decision_input)).hexdigest()
            nonce = secrets.token_hex(16)
            ts = _now_z()
            decision_id = secrets.token_hex(16)

            partial = DecisionRecord(
                decision_id=decision_id,
                key_id=self._custody.key_id,
                input_hash=input_hash,
                model_version=model_version,
                model_fingerprint=model_fingerprint,
                policy_version=policy_version,
                operator_id=operator_id,
                risk_tier=risk_tier,
                timestamp=ts,
                nonce=nonce,
                nonce_scope=nonce_scope,
                prev_hash=prev_hash,
                record_hash="",
                signature="",
            )

            signed_payload = canonical_json(record_canonical_fields(partial))
            record_hash = hashlib.sha256(signed_payload).hexdigest()
            signature = self._custody.sign(signed_payload)

            partial.record_hash = record_hash
            partial.signature = signature

            self.db.execute(
                """
                INSERT INTO decisions VALUES
                (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    partial.decision_id,
                    partial.key_id,
                    partial.input_hash,
                    partial.model_version,
                    partial.model_fingerprint,
                    partial.policy_version,
                    partial.operator_id,
                    partial.risk_tier,
                    partial.timestamp,
                    partial.nonce,
                    partial.nonce_scope,
                    partial.prev_hash,
                    partial.record_hash,
                    partial.signature,
                    partial.schema_version,
                ),
            )

            self._update_chain_head(record_hash, new_count)
            self.db.commit()
            return partial
        except Exception as e:
            self.db.rollback()
            raise RuntimeError(f"DecisionLedger.record() failed: {e}") from e

    def verify_chain(self) -> Dict[str, Any]:
        rows = self.db.execute(
            "SELECT seq, decision_id, key_id, input_hash, model_version, "
            "model_fingerprint, policy_version, operator_id, risk_tier, "
            "timestamp, nonce, nonce_scope, prev_hash, record_hash, "
            "signature, schema_version FROM decisions ORDER BY seq ASC"
        ).fetchall()

        if not rows:
            return {"valid": True, "record_count": 0, "message": "empty chain"}

        head = self.db.execute(
            "SELECT record_count FROM chain_head WHERE id=1"
        ).fetchone()
        if head and int(head[0]) != len(rows):
            return {
                "valid": False,
                "message": f"chain_head.record_count={head[0]} != COUNT(*)={len(rows)}",
                "record_count": len(rows),
            }

        prev_hash = GENESIS_HASH
        for row in rows:
            (seq, did, kid, ih, mv, mf, pv, oid, rt, ts, nonce, ns, ph, rh, _sig, sv) = row

            if ph != prev_hash:
                return {
                    "valid": False,
                    "broken_at_seq": seq,
                    "broken_at_id": did,
                    "message": f"prev_hash mismatch at seq {seq}",
                }

            partial = DecisionRecord(
                decision_id=did,
                key_id=kid,
                input_hash=ih,
                model_version=mv,
                model_fingerprint=mf,
                policy_version=pv,
                operator_id=oid,
                risk_tier=rt,
                timestamp=ts,
                nonce=nonce,
                nonce_scope=ns,
                prev_hash=ph,
                record_hash="",
                signature="",
                schema_version=sv,
            )
            computed_bytes = canonical_json(record_canonical_fields(partial))
            computed_hash = hashlib.sha256(computed_bytes).hexdigest()

            if computed_hash != rh:
                return {
                    "valid": False,
                    "broken_at_seq": seq,
                    "broken_at_id": did,
                    "message": f"record_hash mismatch at seq {seq}",
                }

            prev_hash = rh

        return {
            "valid": True,
            "record_count": len(rows),
            "chain_head": prev_hash,
            "key_ids_seen": list({r[2] for r in rows}),
        }

    def export_proof(self, decision_id: str) -> Dict[str, Any]:
        row = self.db.execute(
            "SELECT seq, decision_id, key_id, input_hash, model_version, "
            "model_fingerprint, policy_version, operator_id, risk_tier, "
            "timestamp, nonce, nonce_scope, prev_hash, record_hash, "
            "signature, schema_version FROM decisions WHERE decision_id=?",
            (decision_id,),
        ).fetchone()
        if not row:
            return {"error": "decision_not_found", "decision_id": decision_id}

        rec = DecisionRecord(
            decision_id=row[1],
            key_id=row[2],
            input_hash=row[3],
            model_version=row[4],
            model_fingerprint=row[5],
            policy_version=row[6],
            operator_id=row[7],
            risk_tier=row[8],
            timestamp=row[9],
            nonce=row[10],
            nonce_scope=row[11],
            prev_hash=row[12],
            record_hash=row[13],
            signature=row[14],
            schema_version=row[15],
        )
        seq = row[0]

        signed_payload = canonical_json(record_canonical_fields(rec))
        computed_hash = hashlib.sha256(signed_payload).hexdigest()
        hash_match = computed_hash == rec.record_hash

        kr = self.db.execute(
            "SELECT pubkey_hex FROM key_registry WHERE key_id=?", (rec.key_id,)
        ).fetchone()
        pubkey_hex = kr[0] if kr else self._custody.pubkey_hex

        sig_valid = KeyCustody.verify_external(pubkey_hex, signed_payload, rec.signature)

        return {
            "record": asdict(rec),
            "seq": seq,
            "verification": {
                "hash_recomputed": computed_hash,
                "hash_match": hash_match,
                "signature_valid": sig_valid,
                "pubkey_hex": pubkey_hex,
                "key_id": rec.key_id,
                "signed_payload_schema": "sha256(canonical_json(record_fields_without_signature))",
            },
            "how_to_verify": (
                "Recompute sha256(canonical_json(record_canonical_fields)) "
                "and verify ed25519_verify(signed_payload, signature, pubkey_hex). "
                "Then confirm prev_hash matches the record_hash of the predecessor."
            ),
        }

    def list_keys(self) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT key_id, pubkey_hex, created_at, retired_at, notes "
            "FROM key_registry ORDER BY created_at ASC"
        ).fetchall()
        return [
            {
                "key_id": r[0],
                "pubkey_hex": r[1],
                "created_at": r[2],
                "retired_at": r[3],
                "notes": r[4],
            }
            for r in rows
        ]

    def close(self):
        if self.db:
            self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
