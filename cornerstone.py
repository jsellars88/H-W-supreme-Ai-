#!/usr/bin/env python3
"""
cornerstone.py — White Swan OS Governance Gate + Decision Ledger
v2.0 — Control-Grade Reference Implementation

Invariant: No high-tier action executes without valid human authority.
Violation → hard stop. Evidence logged before execution.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

try:
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: PyNaCl required. pip install pynacl")
    raise SystemExit(1)

TIER_LEVELS: Dict[str, int] = {
    "T0_SAFE": 0,
    "T1_TRIVIAL": 1,
    "T2_SENSITIVE": 2,
    "T3_HIGH": 3,
    "T4_IRREVERSIBLE": 4,
}
TIERS_REQUIRING_TOKEN = {"T2_SENSITIVE", "T3_HIGH", "T4_IRREVERSIBLE"}

HANDSHAKE_TTL = int(os.getenv("HANDSHAKE_TTL", "300"))
DB_PATH = os.getenv("DB_PATH", "cornerstone.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SigningAuthority:
    """Ed25519 key pair persisted to disk."""

    def __init__(self, name: str):
        self.name = name
        self._priv_path = Path(f"{name}_private.key")
        self._pub_path = Path(f"{name}_public.key")
        self._load_or_create()

    @property
    def pubkey_path(self) -> str:
        return str(self._pub_path)

    def _load_or_create(self) -> None:
        if self._priv_path.exists():
            priv_hex = self._priv_path.read_text().strip()
            self._sk = SigningKey(priv_hex, encoder=HexEncoder)
        else:
            self._sk = SigningKey.generate()
            self._priv_path.write_text(self._sk.encode(encoder=HexEncoder).decode())

        self._vk = self._sk.verify_key
        self.pubkey_hex = self._vk.encode(encoder=HexEncoder).decode()
        self._pub_path.write_text(self.pubkey_hex)

    def sign(self, data: bytes) -> str:
        return self._sk.sign(data).signature.hex()

    def verify(self, data: bytes, sig_hex: str) -> bool:
        try:
            self._vk.verify(data, bytes.fromhex(sig_hex))
            return True
        except Exception:
            return False

    @staticmethod
    def canonical(obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Database:
    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()
        self._bootstrap()

    def _bootstrap(self) -> None:
        with sqlite3.connect(self.path) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")

            c.execute(
                """
                CREATE TABLE IF NOT EXISTS handshakes (
                    token_id    TEXT PRIMARY KEY,
                    operator_id TEXT NOT NULL,
                    tier        TEXT NOT NULL,
                    issued_at   TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    nonce       TEXT NOT NULL,
                    signature   TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at  TEXT DEFAULT (datetime('now'))
                )
                """
            )

            c.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger (
                    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id      TEXT UNIQUE NOT NULL,
                    event_type     TEXT NOT NULL,
                    action_type    TEXT NOT NULL,
                    action_payload TEXT NOT NULL,
                    tier           TEXT NOT NULL,
                    operator_id    TEXT,
                    handshake_ids  TEXT,
                    outcome        TEXT NOT NULL,
                    refusal_reason TEXT,
                    timestamp      TEXT NOT NULL,
                    prev_hash      TEXT NOT NULL,
                    record_hash    TEXT NOT NULL UNIQUE,
                    signature      TEXT NOT NULL
                )
                """
            )

            c.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_head (
                    id           INTEGER PRIMARY KEY CHECK(id=1),
                    last_hash    TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    updated_at   TEXT NOT NULL
                )
                """
            )

            if not c.execute("SELECT 1 FROM chain_head WHERE id=1").fetchone():
                c.execute("INSERT INTO chain_head VALUES (1, ?, 0, ?)", ("0" * 64, _now()))
            c.commit()

    def conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "c", None):
            self._local.c = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
            self._local.c.row_factory = sqlite3.Row
            self._local.c.execute("PRAGMA journal_mode=WAL")
            self._local.c.execute("PRAGMA synchronous=NORMAL")
            self._local.c.execute("PRAGMA busy_timeout=5000")
        return self._local.c

    @contextmanager
    def tx(self):
        c = self.conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise


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
        with self.db.tx() as c:
            row = c.execute("SELECT last_hash, record_count FROM chain_head WHERE id=1").fetchone()
            prev_hash, count = row["last_hash"], row["record_count"]

            record_id = f"rec_{secrets.token_hex(8)}"
            timestamp = _now()
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
            record_hash = hashlib.sha256(SigningAuthority.canonical(core)).hexdigest()
            signature = self.signer.sign(record_hash.encode())

            c.execute(
                """
                INSERT INTO ledger
                (record_id,event_type,action_type,action_payload,tier,
                 operator_id,handshake_ids,outcome,refusal_reason,timestamp,
                 prev_hash,record_hash,signature)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
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
            c.execute(
                "UPDATE chain_head SET last_hash=?, record_count=?, updated_at=? WHERE id=1",
                (record_hash, count + 1, _now()),
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
        rows = self.db.conn().execute("SELECT * FROM ledger ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
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
        r = self.db.conn().execute("SELECT * FROM ledger WHERE record_id=?", (record_id,)).fetchone()
        if not r:
            return None
        return {
            "record_id": r["record_id"],
            "event_type": r["event_type"],
            "action_type": r["action_type"],
            "action_payload": json.loads(r["action_payload"]),
            "tier": r["tier"],
            "operator_id": r["operator_id"],
            "handshake_ids": json.loads(r["handshake_ids"]) if r["handshake_ids"] else None,
            "outcome": r["outcome"],
            "refusal_reason": r["refusal_reason"],
            "timestamp": r["timestamp"],
            "prev_hash": r["prev_hash"],
            "record_hash": r["record_hash"],
            "signature": r["signature"],
        }

    def verify_chain(self) -> dict:
        rows = self.db.conn().execute("SELECT * FROM ledger ORDER BY seq ASC").fetchall()
        if not rows:
            return {"valid": True, "count": 0, "message": "Empty chain"}

        errors = []
        prev_hash = "0" * 64
        for r in rows:
            core = {
                "record_id": r["record_id"],
                "event_type": r["event_type"],
                "action_type": r["action_type"],
                "action_payload": json.loads(r["action_payload"]),
                "tier": r["tier"],
                "operator_id": r["operator_id"],
                "handshake_ids": json.loads(r["handshake_ids"]) if r["handshake_ids"] else None,
                "outcome": r["outcome"],
                "refusal_reason": r["refusal_reason"],
                "timestamp": r["timestamp"],
                "prev_hash": r["prev_hash"],
            }
            computed = hashlib.sha256(SigningAuthority.canonical(core)).hexdigest()

            if r["prev_hash"] != prev_hash:
                errors.append(f"seq {r['seq']}: chain break (prev_hash mismatch)")
            if r["record_hash"] != computed:
                errors.append(f"seq {r['seq']}: hash mismatch — record may be tampered")
            prev_hash = r["record_hash"]

        return {
            "valid": not errors,
            "count": len(rows),
            "errors": errors,
            "message": "Chain intact" if not errors else "CHAIN INTEGRITY FAILURE",
        }


class GovernanceKernel:
    def __init__(self, db: Database, ledger: DecisionLedger):
        self.db = db
        self.ledger = ledger
        self.signer = SigningAuthority("handshake")

    @staticmethod
    def _payload(token_id, operator_id, tier, issued_at, expires_at, nonce) -> dict:
        return {
            "token_id": token_id,
            "operator_id": operator_id,
            "tier": tier,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": nonce,
            "iss": "white-swan-cornerstone",
        }

    def _verify_sig(self, token_id: str) -> bool:
        r = self.db.conn().execute(
            "SELECT operator_id,tier,issued_at,expires_at,nonce,signature FROM handshakes WHERE token_id=?",
            (token_id,),
        ).fetchone()
        if not r:
            return False
        payload = self._payload(token_id, r["operator_id"], r["tier"], r["issued_at"], r["expires_at"], r["nonce"])
        return self.signer.verify(SigningAuthority.canonical(payload), r["signature"])

    def issue(self, operator_id: str, tier: str) -> dict:
        if tier not in TIER_LEVELS:
            raise ValueError(f"Unknown tier: {tier}")

        token_id = f"hs_{secrets.token_hex(8)}"
        nonce = secrets.token_hex(16)
        issued_at = _now()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=HANDSHAKE_TTL)).isoformat().replace("+00:00", "Z")

        payload = self._payload(token_id, operator_id, tier, issued_at, expires_at, nonce)
        signature = self.signer.sign(SigningAuthority.canonical(payload))

        self.db.conn().execute(
            """
            INSERT INTO handshakes
            (token_id,operator_id,tier,issued_at,expires_at,nonce,signature)
            VALUES (?,?,?,?,?,?,?)
            """,
            (token_id, operator_id, tier, issued_at, expires_at, nonce, signature),
        )
        self.db.conn().commit()

        self.ledger.append(
            event_type="handshake.issued",
            action_type="system.handshake",
            action_payload={"token_id": token_id, "operator_id": operator_id, "tier": tier},
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
            "pubkey": self.signer.pubkey_hex,
        }

    def consume(self, token_id: str, required_tier: str) -> Optional[dict]:
        if not self._verify_sig(token_id):
            return None

        now = _now()
        with self.db.tx() as c:
            cursor = c.execute(
                "UPDATE handshakes SET consumed_at=? WHERE token_id=? AND consumed_at IS NULL AND expires_at>?",
                (now, token_id, now),
            )
            if cursor.rowcount == 0:
                return None

            row = c.execute(
                "SELECT operator_id,tier,issued_at,expires_at FROM handshakes WHERE token_id=?",
                (token_id,),
            ).fetchone()

        if TIER_LEVELS.get(row["tier"], -1) < TIER_LEVELS.get(required_tier, 99):
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
        refusal_reason = None
        operator_ids = []
        handshake_ids = []

        try:
            if tier not in TIER_LEVELS:
                refusal_reason = f"unknown_tier:{tier}"
            elif tier not in TIERS_REQUIRING_TOKEN:
                outcome = "ALLOWED"
            else:
                if not handshake_tokens:
                    refusal_reason = "handshake_required"
                else:
                    valid, issuers = [], set()
                    for tid in handshake_tokens:
                        td = self.consume(tid, tier)
                        if td:
                            valid.append(td)
                            issuers.add(td["operator_id"])
                            handshake_ids.append(td["token_id"])

                    if tier == "T4_IRREVERSIBLE":
                        if len(valid) >= 2 and len(issuers) >= 2:
                            outcome = "ALLOWED"
                            operator_ids = list(issuers)[:2]
                        else:
                            refusal_reason = "t4_requires_two_distinct_operators"
                    else:
                        if valid:
                            outcome = "ALLOWED"
                            operator_ids = [valid[0]["operator_id"]]
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
        except Exception as e:
            try:
                self.ledger.append(
                    event_type="system.error",
                    action_type=action_type,
                    action_payload=action_payload,
                    tier=tier,
                    outcome="ERROR",
                    refusal_reason=f"kernel_fault:{e}",
                )
            except Exception:
                pass
            return {
                "outcome": "ERROR",
                "refusal_reason": f"kernel_fault:{e}",
                "can_proceed": False,
                "operator_ids": [],
                "handshake_ids": [],
                "record_id": None,
                "record_hash": None,
                "timestamp": _now(),
            }


app = FastAPI(
    title="White Swan OS — Cornerstone v2.0",
    description="Governance Gate + Decision Ledger · Control-Grade Reference Implementation",
    version="2.0.0",
)

_db = Database(DB_PATH)
_ledger = DecisionLedger(_db)
_kernel = GovernanceKernel(_db, _ledger)


@app.get("/", response_class=HTMLResponse)
def root():
    return """<!DOCTYPE html><html><head><title>WhiteSwan OS — Cornerstone v2.0</title></head>
<body style='font-family:monospace;background:#0a0a0f;color:#c8c4b8;padding:2rem;max-width:900px;margin:auto'>
<h1 style='color:#b8973a'>White Swan OS — Cornerstone v2.0</h1>
<p>Governance Gate + Decision Ledger</p>
<ul>
<li>✓ Ed25519 signature verified on every token consume</li>
<li>✓ Atomic consume with single UPDATE rowcount check</li>
<li>✓ T4 requires two distinct operators</li>
</ul>
<p><a href='/docs'>/docs</a></p>
</body></html>"""


@app.post("/action")
async def execute_action(request: Request):
    body = await request.json()
    action_type = body.get("action_type", "")
    payload = body.get("payload", {})
    tier = body.get("tier", "")
    tokens = body.get("handshake_tokens")

    if tier not in TIER_LEVELS:
        raise HTTPException(400, f"Invalid tier. Valid: {list(TIER_LEVELS)}")

    decision = _kernel.authorize(action_type, tier, payload, tokens)
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

    exec_result = {
        "action_id": f"exec_{secrets.token_hex(4)}",
        "status": "executed",
        "timestamp": _now(),
    }
    exec_entry = _ledger.append(
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
        "decision": {"record_id": decision["record_id"], "record_hash": decision["record_hash"]},
        "execution": {"record_id": exec_entry.record_id, "result": exec_result},
        "operator_ids": decision["operator_ids"],
        "timestamp": decision["timestamp"],
    }


@app.post("/handshake")
async def issue_handshake(request: Request):
    body = await request.json()
    operator_id = body.get("operator_id", "").strip()
    tier = body.get("tier", "").strip()

    if not operator_id:
        raise HTTPException(400, "operator_id required")
    if tier not in TIER_LEVELS:
        raise HTTPException(400, f"Invalid tier. Valid: {list(TIER_LEVELS)}")

    t = _kernel.issue(operator_id, tier)
    return {
        "token_id": t["token_id"],
        "operator_id": t["operator_id"],
        "tier": t["tier"],
        "issued_at": t["issued_at"],
        "expires_at": t["expires_at"],
        "signature": t["signature"],
        "pubkey": t["pubkey"],
        "ttl_seconds": HANDSHAKE_TTL,
    }


@app.get("/ledger")
def get_ledger(limit: int = 50):
    chain = _ledger.get_chain(limit)
    verification = _ledger.verify_chain()
    return {
        "entries": chain,
        "count": len(chain),
        "integrity": verification,
        "ledger_pubkey": _ledger.signer.pubkey_hex[:16] + "…",
        "timestamp": _now(),
    }


@app.get("/ledger/verify")
def verify_chain():
    return _ledger.verify_chain()


@app.get("/ledger/record/{record_id}")
def get_record(record_id: str):
    r = _ledger.get_record(record_id)
    if not r:
        raise HTTPException(404, "Record not found")
    return r


@app.get("/pubkey/handshake")
def pubkey_handshake():
    return {"pubkey": _kernel.signer.pubkey_hex, "algorithm": "Ed25519"}


@app.get("/pubkey/ledger")
def pubkey_ledger():
    return {"pubkey": _ledger.signer.pubkey_hex, "algorithm": "Ed25519"}


@app.get("/health")
def health():
    v = _ledger.verify_chain()
    return {
        "status": "ok",
        "ledger_valid": v["valid"],
        "ledger_entries": v.get("count", 0),
        "handshake_ttl": HANDSHAKE_TTL,
        "db_path": DB_PATH,
        "timestamp": _now(),
    }


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("WHITE SWAN OS — CORNERSTONE v2.0")
    print("=" * 65)
    print(f"  DB:               {DB_PATH}")
    print(f"  Handshake pubkey: {_kernel.signer.pubkey_path}")
    print(f"  Ledger pubkey:    {_ledger.signer.pubkey_path}")
    print(f"  Handshake TTL:    {HANDSHAKE_TTL}s")
    print("=" * 65)
    uvicorn.run("cornerstone:app", host="0.0.0.0", port=8080, reload=False)
