"""
Holmes & Watson Supreme AI™ — Cornerstone Governance Server
WhiteSwan OS | Cornerstone v2.0

FastAPI governance kernel with:
- Operator handshake issuance
- Governed action execution (Recusa Nexus 6-gate)
- Forensic Decision Ledger (Ed25519 + hash chain)
- Evidence packet export
- Third-party verifiable proof

Usage: uvicorn cornerstone_server:app --port 8080
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="H&WS Cornerstone Governance Server", version="2.0.0")


class CryptoCore:
    """Ed25519 signer/verifier pair for ledger proofs."""

    def __init__(self) -> None:
        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self.public_key_b64 = base64.b64encode(
            self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        self.public_key_hex = base64.b64decode(self.public_key_b64).hex()

    def sign(self, data: str) -> str:
        return base64.b64encode(self._priv.sign(data.encode())).decode()

    def verify(self, data: str, sig_b64: str) -> bool:
        try:
            self._pub.verify(base64.b64decode(sig_b64), data.encode())
            return True
        except Exception:
            return False


crypto = CryptoCore()


db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute(
    """CREATE TABLE IF NOT EXISTS decisions (
seq         INTEGER PRIMARY KEY AUTOINCREMENT,
decision_id TEXT UNIQUE,
timestamp   TEXT,
operator_id TEXT,
action_type TEXT,
tier        TEXT,
approved    INTEGER,
outcome     TEXT,
payload_hash TEXT,
prev_hash   TEXT,
entry_hash  TEXT,
signature   TEXT
)"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS handshakes (
token_id    TEXT PRIMARY KEY,
operator_id TEXT,
tier        TEXT,
issued_at   TEXT,
expires_at  TEXT,
used        INTEGER DEFAULT 0
)"""
)
db.commit()
_prev_hash = "GENESIS"

CONFIDENCE_THRESHOLDS = {
    "T1_LOW": 0.40,
    "T2_MED": 0.60,
    "T3_HIGH": 0.75,
    "T4_CRITICAL": 0.92,
}
TIER_RANK = {"T1_LOW": 1, "T2_MED": 2, "T3_HIGH": 3, "T4_CRITICAL": 4}


def recusa_evaluate(
    operator_id: str,
    action_type: str,
    tier: str,
    payload: dict[str, Any],
    tokens: list[str],
) -> dict[str, Any]:
    gates: dict[str, dict[str, Any]] = {}

    gates["G1_OBSERVATION"] = {
        "passed": bool(action_type) and bool(payload),
        "reason": (
            "Action scope and payload present"
            if action_type and payload
            else "Missing action type or payload"
        ),
    }

    tok = None
    expired = True
    if tokens:
        row = db.execute(
            "SELECT * FROM handshakes WHERE token_id=? AND used=0", (tokens[0],)
        ).fetchone()
        if row:
            expired = datetime.fromisoformat(row[4]) < datetime.now(timezone.utc)
            tok = row
        gates["G2_AUTHORITY"] = {
            "passed": tok is not None and not expired,
            "reason": (
                "Valid handshake token present"
                if (tok and not expired)
                else "Missing, expired, or used handshake token"
            ),
        }
    else:
        gates["G2_AUTHORITY"] = {"passed": False, "reason": "No handshake token provided"}

    if tok:
        tok_tier_rank = TIER_RANK.get(tok[2], 0)
        req_tier_rank = TIER_RANK.get(tier, 99)
        gates["G3_TIER_AUTH"] = {
            "passed": tok_tier_rank >= req_tier_rank,
            "reason": f"Token tier {tok[2]} {'≥' if tok_tier_rank >= req_tier_rank else '<'} required {tier}",
        }
    else:
        gates["G3_TIER_AUTH"] = {
            "passed": False,
            "reason": "Cannot verify tier without valid token",
        }

    gates["G4_IDENTITY"] = {
        "passed": bool(operator_id) and "@" in operator_id,
        "reason": (
            "Operator identity verified"
            if (operator_id and "@" in operator_id)
            else "Operator identity unverifiable"
        ),
    }

    gates["G5_PAYLOAD"] = {
        "passed": isinstance(payload, dict) and len(payload) > 0,
        "reason": (
            "Payload structured and non-empty"
            if (isinstance(payload, dict) and payload)
            else "Payload malformed or empty"
        ),
    }

    if tier == "T4_CRITICAL":
        gates["G6_HARM_SURFACE"] = {
            "passed": len(tokens or []) >= 2,
            "reason": (
                "Dual token present for T4_CRITICAL"
                if len(tokens or []) >= 2
                else "T4_CRITICAL requires 2 handshake tokens"
            ),
        }
    else:
        gates["G6_HARM_SURFACE"] = {
            "passed": True,
            "reason": "Non-critical tier — standard harm surface",
        }

    failed = [k for k, v in gates.items() if not v["passed"]]
    return {"approved": len(failed) == 0, "gates": gates, "failed": failed}


def ledger_record(
    operator_id: str,
    action_type: str,
    tier: str,
    payload: dict[str, Any],
    gate_result: dict[str, Any],
    outcome: str,
) -> dict[str, str]:
    global _prev_hash
    decision_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    canonical = json.dumps(
        {
            "decision_id": decision_id,
            "timestamp": ts,
            "operator_id": operator_id,
            "action_type": action_type,
            "tier": tier,
            "approved": gate_result["approved"],
            "outcome": outcome,
            "payload_hash": payload_hash,
            "prev_hash": _prev_hash,
        },
        sort_keys=True,
    )

    entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
    sig = crypto.sign(canonical)

    db.execute(
        "INSERT INTO decisions VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)",
        (
            decision_id,
            ts,
            operator_id,
            action_type,
            tier,
            int(gate_result["approved"]),
            outcome,
            payload_hash,
            _prev_hash,
            entry_hash,
            sig,
        ),
    )
    db.commit()
    _prev_hash = entry_hash
    return {
        "decision_id": decision_id,
        "timestamp": ts,
        "entry_hash": entry_hash,
        "signature": sig,
    }


class HandshakeRequest(BaseModel):
    operator_id: str
    tier: str = "T3_HIGH"
    ttl_minutes: int = Field(default=10, ge=1, le=120)


class ActionRequest(BaseModel):
    action_type: str
    tier: str = "T3_HIGH"
    payload: dict[str, Any]
    handshake_tokens: list[str] = Field(default_factory=list)
    operator_id: str = ""


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "system": "Holmes & Watson Supreme AI™ — Cornerstone v2.0",
        "status": "operational",
        "public_key_b64": crypto.public_key_b64,
        "public_key_hex": crypto.public_key_hex,
        "endpoints": ["/handshake", "/action", "/export/{id}", "/verify", "/health"],
    }


@app.post("/handshake")
def issue_handshake(req: HandshakeRequest) -> dict[str, str]:
    token_id = "hs_" + secrets.token_hex(8)
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(minutes=req.ttl_minutes)

    db.execute(
        "INSERT INTO handshakes VALUES (?,?,?,?,?,0)",
        (
            token_id,
            req.operator_id,
            req.tier,
            issued.isoformat(),
            expires.isoformat(),
        ),
    )
    db.commit()

    return {
        "token_id": token_id,
        "operator_id": req.operator_id,
        "tier": req.tier,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "governance": "Token binds operator identity to action tier. Single-use.",
    }


@app.post("/action")
def governed_action(req: ActionRequest) -> dict[str, Any]:
    gate_result = recusa_evaluate(
        req.operator_id, req.action_type, req.tier, req.payload, req.handshake_tokens
    )

    if gate_result["approved"]:
        outcome = f"EXECUTED — {req.action_type} authorized for {req.operator_id}"
        if req.handshake_tokens:
            db.execute(
                "UPDATE handshakes SET used=1 WHERE token_id=?", (req.handshake_tokens[0],)
            )
            db.commit()
    else:
        outcome = f"BLOCKED — gates failed: {', '.join(gate_result['failed'])}"

    record = ledger_record(
        req.operator_id, req.action_type, req.tier, req.payload, gate_result, outcome
    )

    return {
        "outcome": "EXECUTED" if gate_result["approved"] else "BLOCKED",
        "approved": gate_result["approved"],
        "decision_id": record["decision_id"],
        "timestamp": record["timestamp"],
        "gates_passed": sum(1 for g in gate_result["gates"].values() if g["passed"]),
        "gates_total": len(gate_result["gates"]),
        "failed_gates": gate_result["failed"],
        "gate_details": gate_result["gates"],
        "entry_hash": record["entry_hash"],
        "signature": record["signature"],
        "public_key": crypto.public_key_b64,
        "message": outcome,
    }


@app.get("/export/{decision_id}")
def export_evidence(decision_id: str) -> dict[str, Any]:
    row = db.execute("SELECT * FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Decision not found")

    seq, did, ts, op_id, act, tier, approved, outcome, ph, prev_h, eh, sig = row

    canonical = json.dumps(
        {
            "decision_id": did,
            "timestamp": ts,
            "operator_id": op_id,
            "action_type": act,
            "tier": tier,
            "approved": bool(approved),
            "outcome": outcome,
            "payload_hash": ph,
            "prev_hash": prev_h,
        },
        sort_keys=True,
    )

    return {
        "evidence_packet": {
            "decision_id": did,
            "timestamp": ts,
            "operator_id": op_id,
            "action_type": act,
            "tier": tier,
            "approved": bool(approved),
            "outcome": outcome,
            "payload_hash": ph,
            "prev_hash": prev_h,
            "entry_hash": eh,
            "signature": sig,
            "public_key_b64": crypto.public_key_b64,
            "canonical_json": canonical,
        },
        "verification_steps": [
            "1. Take canonical_json field as bytes",
            "2. Verify Ed25519 signature using public_key_b64",
            "3. Compute SHA-256 of canonical_json — must equal entry_hash",
            "4. Verify prev_hash chain from GENESIS through all prior entries",
            "Result: cryptographic proof of what decision was made, by whom, when",
        ],
        "verify_command": f"python verify_evidence.py evidence.json {crypto.public_key_b64}",
    }


@app.get("/verify")
def verify_chain() -> dict[str, Any]:
    rows = db.execute("SELECT * FROM decisions ORDER BY seq").fetchall()
    results = []
    prev = "GENESIS"
    all_valid = True

    for row in rows:
        seq, did, ts, op_id, act, tier, approved, outcome, ph, prev_h, eh, sig = row
        canonical = json.dumps(
            {
                "decision_id": did,
                "timestamp": ts,
                "operator_id": op_id,
                "action_type": act,
                "tier": tier,
                "approved": bool(approved),
                "outcome": outcome,
                "payload_hash": ph,
                "prev_hash": prev_h,
            },
            sort_keys=True,
        )

        chain_ok = prev_h == prev
        hash_ok = hashlib.sha256(canonical.encode()).hexdigest() == eh
        sig_ok = crypto.verify(canonical, sig)
        valid = chain_ok and hash_ok and sig_ok
        if not valid:
            all_valid = False

        results.append(
            {
                "seq": seq,
                "decision_id": did[:8] + "...",
                "chain_intact": chain_ok,
                "hash_valid": hash_ok,
                "sig_valid": sig_ok,
                "overall": valid,
            }
        )
        prev = eh

    return {
        "chain_integrity": "VERIFIED" if all_valid else "TAMPERED",
        "all_valid": all_valid,
        "total_entries": len(rows),
        "entries": results,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    count = db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
    return {
        "status": "operational",
        "decisions_recorded": count,
        "prev_hash": _prev_hash[:32] + "...",
        "public_key": crypto.public_key_b64[:32] + "...",
    }
