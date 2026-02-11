from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Set


class SASActiveError(Exception):
    pass


class InsufficientAuthorityError(Exception):
    pass


class OperatorNotAuthorizedError(Exception):
    pass


class GovernanceViolation(Exception):
    pass


class ActionScope(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class ActionTier(IntEnum):
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4


SCOPE_TIER_MAP = {
    ActionScope.READ: ActionTier.T1,
    ActionScope.WRITE: ActionTier.T2,
    ActionScope.ADMIN: ActionTier.T4,
}


def generate_nonce() -> str:
    return secrets.token_hex(16)


@dataclass
class GeoConstraint:
    allowed_regions: Set[str]
    denied_regions: Set[str]


@dataclass
class ModelContext:
    model_id: str = "default"
    temperature: float = 0.0


class _FakeVerifyKey:
    def __init__(self, raw: bytes):
        self._raw = raw

    def encode(self) -> bytes:
        return self._raw


class _FakeSigningKey:
    def __init__(self):
        self._seed = secrets.token_bytes(32)
        self.verify_key = _FakeVerifyKey(hashlib.sha256(self._seed).digest())

    def encode(self) -> bytes:
        return self._seed


@dataclass
class OperatorIdentity:
    kid: str
    name: str
    role: str
    signing_key: _FakeSigningKey
    verify_key: _FakeVerifyKey

    @classmethod
    def generate(cls, name: str, role: str) -> "OperatorIdentity":
        sk = _FakeSigningKey()
        vk = sk.verify_key
        kid = hashlib.sha256(vk.encode()).hexdigest()[:16]
        return cls(kid, name, role, sk, vk)


class GovernanceDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.execute("CREATE TABLE operators(pubkey_hex TEXT PRIMARY KEY, name TEXT, role TEXT, revoked INTEGER)")
        self.conn.execute("CREATE TABLE decisions(scope TEXT, nonce TEXT, envelope_json TEXT)")
        self._trustees: List[Dict[str, str]] = []

    def get_active_trustees(self):
        return self._trustees


class Telemetry:
    def export_dict(self):
        return {"events": 0, "status": "ok"}

    def export_prometheus(self):
        return "whiteswan_events_total 0\n"


class GovernanceCore:
    def __init__(self):
        self.telemetry = Telemetry()
        self.kernel_key_id = "kernel-dev"
        self.kernel_pubkey_hex = secrets.token_hex(32)
        self._policy_version = "3.5"
        self.sas_active = False
        self.db = GovernanceDB()
        self._km = SimpleNamespace(sign_hex=lambda msg: hashlib.sha256(msg.encode()).hexdigest())
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def register_operator(self, ident: OperatorIdentity, scope_enums, geo):
        pubkey_hex = ident.verify_key.encode().hex()
        self.db.conn.execute("INSERT OR REPLACE INTO operators(pubkey_hex,name,role,revoked) VALUES(?,?,?,0)", (pubkey_hex, ident.name, ident.role))
        self.db.conn.commit()
        return SimpleNamespace(pubkey_hex=pubkey_hex, name=ident.name)

    def list_operators(self):
        rows = self.db.conn.execute("SELECT pubkey_hex,name,role,revoked FROM operators").fetchall()
        return [{"pubkey_hex": r[0], "name": r[1], "role": r[2], "revoked": bool(r[3])} for r in rows]

    def revoke_operator(self, pubkey: str, reason: str):
        self.db.conn.execute("UPDATE operators SET revoked=1 WHERE pubkey_hex=?", (pubkey,))
        self.db.conn.commit()

    def create_session(self, ident: OperatorIdentity, max_tier):
        sid = f"sess_{generate_nonce()}"
        self._sessions[sid] = {"kid": ident.kid, "max_tier": int(max_tier)}
        return sid

    def revoke_session(self, sid: str):
        self._sessions.pop(sid, None)

    def issue(self, ident, session_id, scope, nonce, model_ctx=None):
        token_id = f"hs_{generate_nonce()}"
        return SimpleNamespace(token_id=token_id)

    def policy_history(self):
        return [{"version": self._policy_version, "ts": datetime.now(timezone.utc).isoformat()}]

    def enter_sas(self, reason: str):
        self.sas_active = True

    def initiate_emergency_override(self, reason: str, quorum_required: int):
        return f"emg_{generate_nonce()}"

    def approve_emergency_override(self, emergency_id: str, trustee_pubkey: str, signature: str):
        return True

    def register_trustee(self, pubkey_hex: str, name: str):
        self.db._trustees.append({"pubkey_hex": pubkey_hex, "name": name})

    def _get_operator_record(self, operator_pubkey: str):
        row = self.db.conn.execute("SELECT pubkey_hex,name,role,revoked FROM operators WHERE pubkey_hex=?", (operator_pubkey,)).fetchone()
        if not row:
            return None
        return SimpleNamespace(pubkey_hex=row[0], name=row[1], role=row[2], is_active=(row[3] == 0))
