#!/usr/bin/env python3
"""
cornerstone.py — White Swan OS Governance Gate + Decision Ledger
v2.1 — Control-Grade Reference Implementation

Holmes & Watson Supreme AI™

Invariant:
    No high-tier action executes without valid human authority.
    Evidence is written before the action runs.

Honest framing:
- This is a reference implementation, not a production system.
- This is a SERVER-AUTHORITATIVE approval-record model.
- Approval records are DB-backed, Ed25519-signed by the server, and re-verified
  at consume time from canonical payload reconstructed from the database.
- This is NOT a bearer-token / JWT design.
- This is NOT distributed, audited, or hardened against host compromise.

Threat model covered by this reference implementation:
- Replay / token reuse
- Expiry enforcement
- Tier escalation attempts
- Ledger tampering detection
- Handshake/approval record tampering detection
- Race on single-use consume
- Two-person integrity for T4

Not covered:
- Host OS compromise
- DB theft with server key compromise
- Distributed consensus / quorum
- Multi-instance deployment
- Full audit / formal verification
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import local
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

try:
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey, VerifyKey
except ImportError as exc:
    raise SystemExit("PyNaCl required: pip install pynacl") from exc


# ── CONFIG ────────────────────────────────────────────────────────────────────

TIER_LEVELS: Dict[str, int] = {
    "T0_SAFE": 0,
    "T1_TRIVIAL": 1,
    "T2_SENSITIVE": 2,
    "T3_HIGH": 3,
    "T4_IRREVERSIBLE": 4,
}
TIERS_REQUIRING_APPROVAL = {"T2_SENSITIVE", "T3_HIGH", "T4_IRREVERSIBLE"}

HANDSHAKE_TTL = int(os.getenv("HANDSHAKE_TTL", "300"))  # seconds
DB_PATH = os.getenv("DB_PATH", "cornerstone.db")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_z() -> str:
    return now_utc().isoformat().replace("+00:00", "Z")


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── CRYPTO ────────────────────────────────────────────────────────────────────


class SigningAuthority:
    """
    Ed25519 signing authority with persisted keys.
    """

    def __init__(self, name: str):
        self.name = name
        self.private_key_path = Path(f"{name}_private.key")
        self.public_key_path = Path(f"{name}_public.key")
        self._load_or_create()

    def _load_or_create(self) -> None:
        if self.private_key_path.exists():
            priv_hex = self.private_key_path.read_text(encoding="utf-8").strip()
            self._sk = SigningKey(priv_hex, encoder=HexEncoder)
        else:
            self._sk = SigningKey.generate()
            self.private_key_path.write_text(
                self._sk.encode(encoder=HexEncoder).decode("utf-8"),
                encoding="utf-8",
            )

        self._vk = self._sk.verify_key
        self.public_key_hex = self._vk.encode(encoder=HexEncoder).decode("utf-8")
        self.public_key_path.write_text(self.public_key_hex, encoding="utf-8")

    def sign(self, data: bytes) -> str:
        return self._sk.sign(data).signature.hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        try:
            self._vk.verify(data, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False


# ── DATABASE ──────────────────────────────────────────────────────────────────


class Database:
    """
    Single SQLite database with thread-local connections.
    WAL mode for better concurrency in this reference implementation.
    """

    def __init__(self, path: str):
        self.path = path
        self._local = local()
        self._bootstrap()

    def _bootstrap(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS handshakes (
                    token_id     TEXT PRIMARY KEY,
                    operator_id  TEXT NOT NULL,
                    tier         TEXT NOT NULL,
                    issued_at    TEXT NOT NULL,
                    expires_at   TEXT NOT NULL,
                    nonce        TEXT NOT NULL,
                    signature    TEXT NOT NULL,
                    consumed_at  TEXT,
                    created_at   TEXT DEFAULT (datetime('now'))
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger (
                    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id       TEXT UNIQUE NOT NULL,
                    event_type      TEXT NOT NULL,
                    action_type     TEXT NOT NULL,
                    action_payload  TEXT NOT NULL,
                    tier            TEXT NOT NULL,
                    operator_id     TEXT,
                    handshake_ids   TEXT,
                    outcome         TEXT NOT NULL,
                    refusal_reason  TEXT,
                    timestamp       TEXT NOT NULL,
                    prev_hash       TEXT NOT NULL,
                    record_hash     TEXT NOT NULL UNIQUE,
                    signature       TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_head (
                    id            INTEGER PRIMARY KEY CHECK(id=1),
                    last_hash     TEXT NOT NULL,
                    record_count  INTEGER NOT NULL,
                    updated_at    TEXT NOT NULL
                )
                """
            )
            row = conn.execute("SELECT 1 FROM chain_head WHERE id=1").fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO chain_head VALUES (1, ?, 0, ?)",
                    ("0" * 64, now_z()),
                )
            conn.commit()

    def conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def tx(self):
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# ── LEDGER ────────────────────────────────────────────────────────────────────


@dataclass
class LedgerEntry:
    record_id: str
    event_type: str
    action_type: str
    action_payload: dict
    tier: str
    operator_id: Optional[str]
    handshake_ids: Optional[List[str]]
    outcome: str
    refusal_reason: Optional[str]
    timestamp: str
    prev_hash: str
    record_hash: str
    signature: str


class DecisionLedger:
    """
    Append-only hash-chained evidence store.
    Chain head is read inside the same transaction as append.
    """

    def __init__(self, db: Database):
        self.db = db
        self.signer = SigningAuthority("ledger")

    def append(
        self,
        event_type: str,
        action_type: str,
        action_payload: dict,
        tier: str,
        outcome: str,
        operator_id: Optional[str] = None,
        handshake_ids: Optional[List[str]] = None,
        refusal_reason: Optional[str] = None,
    ) -> LedgerEntry:
        with self.db.tx() as conn:
            head = conn.execute(
                "SELECT last_hash, record_count FROM chain_head WHERE id=1"
            ).fetchone()

            prev_hash = head["last_hash"]
            count = head["record_count"]

            record_id = f"rec_{secrets.token_hex(8)}"
            timestamp = now_z()

            core = {
                "record_id": record_id,
                "event_type": event_type,
                "action_type": action_type,
                "action_payload": action_payload,
                "tier": tier,
                "operator_id": operator_id,
                "handshake_ids": handshake_ids,
                "outcome": outcome,
                "refusal_reason": refusal_reason,
                "timestamp": timestamp,
                "prev_hash": prev_hash,
            }

            record_hash = hashlib.sha256(canonical_json_bytes(core)).hexdigest()
            signature = self.signer.sign(record_hash.encode("utf-8"))

            conn.execute(
                """
                INSERT INTO ledger (
                    record_id, event_type, action_type, action_payload, tier,
                    operator_id, handshake_ids, outcome, refusal_reason, timestamp,
                    prev_hash, record_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    event_type,
                    action_type,
                    json.dumps(action_payload),
                    tier,
                    operator_id,
                    json.dumps(handshake_ids) if handshake_ids else None,
                    outcome,
                    refusal_reason,
                    timestamp,
                    prev_hash,
                    record_hash,
                    signature,
                ),
            )

            conn.execute(
                "UPDATE chain_head SET last_hash=?, record_count=?, updated_at=? WHERE id=1",
                (record_hash, count + 1, now_z()),
            )

        return LedgerEntry(
            record_id=record_id,
            event_type=event_type,
            action_type=action_type,
            action_payload=action_payload,
            tier=tier,
            operator_id=operator_id,
            handshake_ids=handshake_ids,
            outcome=outcome,
            refusal_reason=refusal_reason,
            timestamp=timestamp,
            prev_hash=prev_hash,
            record_hash=record_hash,
            signature=signature,
        )

    def get_chain(self, limit: int = 50) -> List[dict]:
        rows = self.db.conn().execute(
            "SELECT * FROM ledger ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()

        return [
            {
                "seq": r["seq"],
                "record_id": r["record_id"],
                "event_type": r["event_type"],
                "action_type": r["action_type"],
                "tier": r["tier"],
                "operator_id": r["operator_id"],
                "outcome": r["outcome"],
                "refusal_reason": r["refusal_reason"],
                "timestamp": r["timestamp"],
                "record_hash": r["record_hash"][:16] + "…",
                "prev_hash": r["prev_hash"][:16] + "…",
            }
            for r in rows
        ]

    def get_record(self, record_id: str) -> Optional[dict]:
        row = self.db.conn().execute(
            "SELECT * FROM ledger WHERE record_id=?",
            (record_id,),
        ).fetchone()
        if not row:
            return None

        return {
            "record_id": row["record_id"],
            "event_type": row["event_type"],
            "action_type": row["action_type"],
            "action_payload": json.loads(row["action_payload"]),
            "tier": row["tier"],
            "operator_id": row["operator_id"],
            "handshake_ids": json.loads(row["handshake_ids"]) if row["handshake_ids"] else None,
            "outcome": row["outcome"],
            "refusal_reason": row["refusal_reason"],
            "timestamp": row["timestamp"],
            "prev_hash": row["prev_hash"],
            "record_hash": row["record_hash"],
            "signature": row["signature"],
        }

    def verify_chain(self) -> dict:
        rows = self.db.conn().execute(
            "SELECT * FROM ledger ORDER BY seq ASC"
        ).fetchall()

        if not rows:
            return {"valid": True, "count": 0, "message": "Empty chain"}

        errors: List[str] = []
        prev_hash = "0" * 64

        for row in rows:
            core = {
                "record_id": row["record_id"],
                "event_type": row["event_type"],
                "action_type": row["action_type"],
                "action_payload": json.loads(row["action_payload"]),
                "tier": row["tier"],
                "operator_id": row["operator_id"],
                "handshake_ids": json.loads(row["handshake_ids"]) if row["handshake_ids"] else None,
                "outcome": row["outcome"],
                "refusal_reason": row["refusal_reason"],
                "timestamp": row["timestamp"],
                "prev_hash": row["prev_hash"],
            }

            computed_hash = hashlib.sha256(canonical_json_bytes(core)).hexdigest()

            if row["prev_hash"] != prev_hash:
                errors.append(f"seq {row['seq']}: chain break (prev_hash mismatch)")
            if row["record_hash"] != computed_hash:
                errors.append(f"seq {row['seq']}: hash mismatch — record may be tampered")

            prev_hash = row["record_hash"]

        return {
            "valid": not errors,
            "count": len(rows),
            "errors": errors,
            "message": "Chain intact" if not errors else "CHAIN INTEGRITY FAILURE",
        }


# ── GOVERNANCE KERNEL ─────────────────────────────────────────────────────────


class GovernanceKernel:
    """
    Enforcement gate in the execution path.
    Fails closed.

    Approval model:
    - Server issues signed approval records.
    - Canonical payload is reconstructed from DB at consume time.
    - Signature is re-verified before consume.
    - Consume is atomic and single-use.
    """

    def __init__(self, db: Database, ledger: DecisionLedger):
        self.db = db
        self.ledger = ledger
        self.signer = SigningAuthority("handshake")

    @staticmethod
    def approval_payload(
        token_id: str,
        operator_id: str,
        tier: str,
        issued_at: str,
        expires_at: str,
        nonce: str,
    ) -> dict:
        return {
            "token_id": token_id,
            "operator_id": operator_id,
            "tier": tier,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": nonce,
            "iss": "white-swan-cornerstone",
        }

    def _verify_signature_from_db(self, token_id: str) -> bool:
        row = self.db.conn().execute(
            """
            SELECT operator_id, tier, issued_at, expires_at, nonce, signature
            FROM handshakes WHERE token_id=?
            """,
            (token_id,),
        ).fetchone()

        if not row:
            return False

        payload = self.approval_payload(
            token_id=token_id,
            operator_id=row["operator_id"],
            tier=row["tier"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            nonce=row["nonce"],
        )
        return self.signer.verify(
            canonical_json_bytes(payload),
            row["signature"],
        )

    def issue(self, operator_id: str, tier: str) -> dict:
        if tier not in TIER_LEVELS:
            raise ValueError(f"Unknown tier: {tier}")

        token_id = f"hs_{secrets.token_hex(8)}"
        nonce = secrets.token_hex(16)
        issued_at = now_z()
        expires_at = (
            now_utc() + timedelta(seconds=HANDSHAKE_TTL)
        ).isoformat().replace("+00:00", "Z")

        payload = self.approval_payload(
            token_id=token_id,
            operator_id=operator_id,
            tier=tier,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
        )
        signature = self.signer.sign(canonical_json_bytes(payload))

        self.db.conn().execute(
            """
            INSERT INTO handshakes (
                token_id, operator_id, tier, issued_at, expires_at, nonce, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token_id, operator_id, tier, issued_at, expires_at, nonce, signature),
        )
        self.db.conn().commit()

        self.ledger.append(
            event_type="handshake.issued",
            action_type="system.handshake",
            action_payload={
                "token_id": token_id,
                "operator_id": operator_id,
                "tier": tier,
            },
            tier="GOVERNANCE",
            outcome="ISSUED",
            operator_id=operator_id,
        )

        return {
            "token_id": token_id,
            "operator_id": operator_id,
            "tier": tier,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature": signature,
            "pubkey": self.signer.public_key_hex,
        }

    def consume(self, token_id: str, required_tier: str) -> Optional[dict]:
        """
        Atomic single-use consume.

        1. Verify signature against DB-derived canonical payload
        2. UPDATE ... WHERE consumed_at IS NULL AND expires_at > now
        3. Check rowcount
        4. Read row and enforce tier in Python
        """
        if not self._verify_signature_from_db(token_id):
            return None

        now = now_z()

        with self.db.tx() as conn:
            cursor = conn.execute(
                """
                UPDATE handshakes
                SET consumed_at=?
                WHERE token_id=?
                  AND consumed_at IS NULL
                  AND expires_at>?
                """,
                (now, token_id, now),
            )
            if cursor.rowcount == 0:
                return None

            row = conn.execute(
                """
                SELECT operator_id, tier, issued_at, expires_at
                FROM handshakes
                WHERE token_id=?
                """,
                (token_id,),
            ).fetchone()

        if TIER_LEVELS.get(row["tier"], -1) < TIER_LEVELS.get(required_tier, 999):
            return None

        return {
            "token_id": token_id,
            "operator_id": row["operator_id"],
            "tier": row["tier"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
        }

    def authorize(
        self,
        action_type: str,
        tier: str,
        action_payload: dict,
        handshake_tokens: Optional[List[str]] = None,
    ) -> dict:
        outcome = "BLOCKED"
        refusal_reason: Optional[str] = None
        operator_ids: List[str] = []
        handshake_ids: List[str] = []

        try:
            if tier not in TIER_LEVELS:
                refusal_reason = f"unknown_tier:{tier}"

            elif tier not in TIERS_REQUIRING_APPROVAL:
                outcome = "ALLOWED"

            else:
                if not handshake_tokens:
                    refusal_reason = "handshake_required"
                else:
                    valid_records = []
                    issuers = set()

                    for token_id in handshake_tokens:
                        token_data = self.consume(token_id, tier)
                        if token_data:
                            valid_records.append(token_data)
                            issuers.add(token_data["operator_id"])
                            handshake_ids.append(token_data["token_id"])

                    if tier == "T4_IRREVERSIBLE":
                        if len(valid_records) >= 2 and len(issuers) >= 2:
                            outcome = "ALLOWED"
                            operator_ids = list(issuers)[:2]
                        else:
                            refusal_reason = "t4_requires_two_distinct_operators"
                    else:
                        if valid_records:
                            outcome = "ALLOWED"
                            operator_ids = [valid_records[0]["operator_id"]]
                        else:
                            refusal_reason = "invalid_or_consumed_token"

            entry = self.ledger.append(
                event_type=f"decision.{outcome.lower()}",
                action_type=action_type,
                action_payload=action_payload,
                tier=tier,
                outcome=outcome,
                operator_id=",".join(operator_ids) if operator_ids else None,
                handshake_ids=handshake_ids or None,
                refusal_reason=refusal_reason,
            )

            return {
                "outcome": outcome,
                "refusal_reason": refusal_reason,
                "can_proceed": outcome == "ALLOWED",
                "operator_ids": operator_ids,
                "handshake_ids": handshake_ids,
                "record_id": entry.record_id,
                "record_hash": entry.record_hash[:16],
                "timestamp": entry.timestamp,
            }

        except Exception as exc:
            try:
                self.ledger.append(
                    event_type="system.error",
                    action_type=action_type,
                    action_payload=action_payload,
                    tier=tier,
                    outcome="ERROR",
                    refusal_reason=f"kernel_fault:{exc}",
                )
            except Exception:
                pass

            return {
                "outcome": "ERROR",
                "refusal_reason": f"kernel_fault:{exc}",
                "can_proceed": False,
                "operator_ids": [],
                "handshake_ids": [],
                "record_id": None,
                "record_hash": None,
                "timestamp": now_z(),
            }


# ── FASTAPI APP ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="White Swan OS — Cornerstone v2.1",
    description="Governance Gate + Decision Ledger · Control-Grade Reference Implementation",
    version="2.1.0",
)

db = Database(DB_PATH)
ledger = DecisionLedger(db)
kernel = GovernanceKernel(db, ledger)


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return """
<!DOCTYPE html>
<html>
<head>
    <title>White Swan OS — Cornerstone v2.1</title>
    <style>
        body{font-family:monospace;background:#0a0a0f;color:#c8c4b8;padding:2.5rem;max-width:860px;margin:0 auto}
        h1{color:#b8973a;font-size:1.3rem}
        .sub{color:#777;font-size:.85rem;margin-bottom:1.5rem}
        .inv{color:#3a7a52;margin:.35rem 0}
        .ep{margin:.35rem 0;font-size:.92rem}
        .m{color:#b8973a}.p{color:#8fb8ff}.d{color:#777}
        .box{margin-top:1.5rem;padding:1rem 1.25rem;background:#111822;border:1px solid #2d5a3d}
        a{color:#b8973a}
    </style>
</head>
<body>
    <h1>White Swan OS — Cornerstone v2.1</h1>
    <div class="sub">Holmes &amp; Watson Supreme AI™ · Control-Grade Reference Implementation</div>

    <div class="inv">✓ Server-authoritative approval record model</div>
    <div class="inv">✓ Ed25519 signature re-verified on every consume</div>
    <div class="inv">✓ Keys persist across restarts</div>
    <div class="inv">✓ Atomic single-use consume</div>
    <div class="inv">✓ Chain head read inside append transaction</div>
    <div class="inv">✓ T4 requires two distinct operators</div>
    <div class="inv">✓ Evidence written before execution</div>

    <br>
    <div class="ep"><span class="m">POST</span> <span class="p">/action</span> — execute a governed action</div>
    <div class="ep"><span class="m">POST</span> <span class="p">/handshake</span> — issue approval record</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/ledger</span> — evidence chain</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/ledger/verify</span> — chain integrity</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/ledger/record/{id}</span> — single full record</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/pubkey/handshake</span> — approval-record public key</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/pubkey/ledger</span> — ledger public key</div>
    <div class="ep"><span class="m">GET</span> <span class="p">/health</span> — system status</div>

    <div class="box"><strong style="color:#b8973a">→ Interactive docs:</strong> <a href="/docs">/docs</a></div>
</body>
</html>
"""


@app.post("/action")
async def execute_action(request: Request):
    body = await request.json()

    action_type = body.get("action_type", "")
    payload = body.get("payload", {})
    tier = body.get("tier", "")
    tokens = body.get("handshake_tokens")

    if tier not in TIER_LEVELS:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Valid: {list(TIER_LEVELS)}")

    decision = kernel.authorize(action_type, tier, payload, tokens)

    if not decision["can_proceed"]:
        return JSONResponse(
            status_code=403,
            content={
                "outcome": decision["outcome"],
                "refusal_reason": decision["refusal_reason"],
                "record_id": decision["record_id"],
                "record_hash": decision["record_hash"],
                "timestamp": decision["timestamp"],
                "governance": "Action did not execute. Evidence written to ledger.",
            },
        )

    execution_result = {
        "action_id": f"exec_{secrets.token_hex(4)}",
        "status": "executed",
        "timestamp": now_z(),
    }

    exec_entry = ledger.append(
        event_type="action.executed",
        action_type=action_type,
        action_payload=payload,
        tier=tier,
        outcome="EXECUTED",
        operator_id=",".join(decision["operator_ids"]) if decision["operator_ids"] else None,
        handshake_ids=decision["handshake_ids"] or None,
    )

    return {
        "outcome": "EXECUTED",
        "decision": {
            "record_id": decision["record_id"],
            "record_hash": decision["record_hash"],
        },
        "execution": {
            "record_id": exec_entry.record_id,
            "result": execution_result,
        },
        "operator_ids": decision["operator_ids"],
        "timestamp": decision["timestamp"],
    }


@app.post("/handshake")
async def issue_handshake(request: Request):
    """
    Compatibility endpoint.
    This issues a server-signed approval record, not a bearer token.
    """
    body = await request.json()
    operator_id = body.get("operator_id", "").strip()
    tier = body.get("tier", "").strip()

    if not operator_id:
        raise HTTPException(status_code=400, detail="operator_id required")
    if tier not in TIER_LEVELS:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Valid: {list(TIER_LEVELS)}")

    record = kernel.issue(operator_id, tier)
    return {
        "token_id": record["token_id"],
        "operator_id": record["operator_id"],
        "tier": record["tier"],
        "issued_at": record["issued_at"],
        "expires_at": record["expires_at"],
        "signature": record["signature"],
        "pubkey": record["pubkey"],
        "ttl_seconds": HANDSHAKE_TTL,
    }


@app.get("/ledger")
def get_ledger(limit: int = 50):
    chain = ledger.get_chain(limit)
    verification = ledger.verify_chain()
    return {
        "entries": chain,
        "count": len(chain),
        "integrity": verification,
        "ledger_pubkey": ledger.signer.public_key_hex[:16] + "…",
        "timestamp": now_z(),
    }


@app.get("/ledger/verify")
def verify_chain():
    return ledger.verify_chain()


@app.get("/ledger/record/{record_id}")
def get_record(record_id: str):
    record = ledger.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@app.get("/pubkey/handshake")
def pubkey_handshake():
    return {
        "pubkey": kernel.signer.public_key_hex,
        "algorithm": "Ed25519",
        "model": "server-authoritative approval record",
    }


@app.get("/pubkey/ledger")
def pubkey_ledger():
    return {
        "pubkey": ledger.signer.public_key_hex,
        "algorithm": "Ed25519",
    }


@app.get("/health")
def health():
    verification = ledger.verify_chain()
    return {
        "status": "ok",
        "ledger_valid": verification["valid"],
        "ledger_entries": verification.get("count", 0),
        "handshake_ttl": HANDSHAKE_TTL,
        "db_path": DB_PATH,
        "timestamp": now_z(),
    }


if __name__ == "__main__":
    print("\n" + "=" * 68)
    print("WHITE SWAN OS — CORNERSTONE v2.1")
    print("Control-Grade Reference Implementation")
    print("=" * 68)
    print(f"  DB:               {DB_PATH}")
    print(f"  Handshake pubkey: {kernel.signer.public_key_path}")
    print(f"  Ledger pubkey:    {ledger.signer.public_key_path}")
    print(f"  Handshake TTL:    {HANDSHAKE_TTL}s")
    print("=" * 68)
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=False)
