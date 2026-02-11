#!/usr/bin/env python3
"""
WhiteSwan Governance Kernel v3.4 — Institution-Grade Reference (RUNNABLE)

Adds on top of your v3.4:
- MGI: Governance Envelope v2.0 (single canonical decision record)
- Remote Attestation bundle (kernel-signed)
- Decision persistence + replay (Governance Replay Simulator)
- Operator listing + policy history export
- Seal export (GuardianVaultX seals)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import secrets
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

# =============================================================================
# CONSTANTS
# =============================================================================

SCHEMA_VERSION = "ws-hs-v3.4"
DEFAULT_ALGORITHM = "ed25519"

DEFAULT_KERNEL_KEY_FILE = ".whiteswan_kernel_key"
DEFAULT_DB_FILE = ".whiteswan_kernel.db"

DEFAULT_HANDSHAKE_TTL_SECONDS = 300
DEFAULT_SESSION_TTL_SECONDS = 3600
DEFAULT_REPLAY_WINDOW = 50_000
DEFAULT_RATE_LIMIT_PER_MINUTE = 120
DEFAULT_REPLAY_SATURATION_PANIC_PCT = 95
DEFAULT_SEAL_INTERVAL = 100
DEFAULT_QUORUM_THRESHOLD = 0.5

# =============================================================================
# TIME UTILITIES
# =============================================================================

def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def iso_z(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

def now_z() -> str:
    return iso_z(now_utc())

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def generate_nonce() -> str:
    return secrets.token_hex(16)

def _json_canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)

# =============================================================================
# CRYPTO REGISTRY (extensible)
# =============================================================================

@dataclass
class CryptoAlgorithm:
    name: str
    sign: Callable[[bytes, Any], bytes]
    verify: Callable[[bytes, bytes, Any], bool]
    key_gen: Callable[[], Tuple[Any, Any]]
    deprecated: bool = False

class CryptoRegistry:
    def __init__(self):
        self._algorithms: Dict[str, CryptoAlgorithm] = {}
        self._default = DEFAULT_ALGORITHM
        self._register_ed25519()

    def _register_ed25519(self):
        def sign(msg: bytes, sk: SigningKey) -> bytes:
            return sk.sign(msg).signature

        def verify(msg: bytes, sig: bytes, vk: VerifyKey) -> bool:
            try:
                vk.verify(msg, sig)
                return True
            except BadSignatureError:
                return False

        def key_gen() -> Tuple[SigningKey, VerifyKey]:
            sk = SigningKey.generate()
            return sk, sk.verify_key

        self._algorithms["ed25519"] = CryptoAlgorithm("ed25519", sign, verify, key_gen)

    def get(self, name: str) -> Optional[CryptoAlgorithm]:
        return self._algorithms.get(name)

    def default(self) -> CryptoAlgorithm:
        return self._algorithms[self._default]

CRYPTO = CryptoRegistry()

# =============================================================================
# TIME AUTHORITY
# =============================================================================

@dataclass
class TimeHealth:
    ok: bool
    source: str
    drift_ms: int = 0
    note: str = ""

class TimeAuthority:
    def now(self) -> datetime.datetime:
        return now_utc()

    def health(self) -> TimeHealth:
        return TimeHealth(ok=True, source="system_clock", drift_ms=0, note="production")

# =============================================================================
# TIERS / SCOPES
# =============================================================================

class ActionTier(Enum):
    T0_KERNEL = 0
    T1_SAFE = 1
    T2_ESCALATION = 2
    T3_INTERVENTION = 3
    T4_IRREVERSIBLE = 4

class ActionScope(Enum):
    SENSING = "sensing"
    NAVIGATION = "navigation"
    ALERT_ESCALATION = "alert_escalation"
    DATA_EXPORT = "data_export"
    MEDICAL_INTERVENTION = "medical_intervention"
    KINETIC_DEFENSIVE = "kinetic_defensive"
    DIAGNOSTIC_INFERENCE = "diagnostic_inference"
    SAS_RECOVERY = "sas_recovery"
    KINETIC_LETHAL = "kinetic_lethal"
    IRREVERSIBLE_MEDICAL = "irreversible_medical"
    DELEGATE_AUTHORITY = "delegate_authority"

SCOPE_TIER_MAP: Dict[ActionScope, ActionTier] = {
    ActionScope.SENSING: ActionTier.T1_SAFE,
    ActionScope.NAVIGATION: ActionTier.T1_SAFE,
    ActionScope.ALERT_ESCALATION: ActionTier.T2_ESCALATION,
    ActionScope.DATA_EXPORT: ActionTier.T2_ESCALATION,
    ActionScope.MEDICAL_INTERVENTION: ActionTier.T3_INTERVENTION,
    ActionScope.KINETIC_DEFENSIVE: ActionTier.T3_INTERVENTION,
    ActionScope.DIAGNOSTIC_INFERENCE: ActionTier.T3_INTERVENTION,
    ActionScope.SAS_RECOVERY: ActionTier.T3_INTERVENTION,
    ActionScope.DELEGATE_AUTHORITY: ActionTier.T3_INTERVENTION,
    ActionScope.KINETIC_LETHAL: ActionTier.T4_IRREVERSIBLE,
    ActionScope.IRREVERSIBLE_MEDICAL: ActionTier.T4_IRREVERSIBLE,
}

# =============================================================================
# GEO CONSTRAINTS
# =============================================================================

@dataclass
class GeoConstraint:
    allowed_regions: Set[str] = field(default_factory=set)
    denied_regions: Set[str] = field(default_factory=set)
    max_radius_km: Optional[float] = None
    anchor_lat: Optional[float] = None
    anchor_lon: Optional[float] = None

    def check(self, region: Optional[str] = None, lat: Optional[float] = None, lon: Optional[float] = None) -> Tuple[bool, str]:
        if self.denied_regions and region in self.denied_regions:
            return False, f"region {region} denied"
        if self.allowed_regions and (region not in self.allowed_regions):
            return False, f"region {region} not in allowed set"
        if self.max_radius_km and self.anchor_lat is not None and lat is not None and lon is not None:
            import math
            R = 6371
            dlat = math.radians(lat - self.anchor_lat)
            dlon = math.radians(lon - (self.anchor_lon or 0))
            a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(self.anchor_lat)) * math.cos(math.radians(lat)) * math.sin(dlon / 2) ** 2
            dist = 2 * R * math.asin(math.sqrt(a))
            if dist > self.max_radius_km:
                return False, f"distance {dist:.1f}km exceeds max {self.max_radius_km}km"
        return True, "ok"

# =============================================================================
# REFUSALS
# =============================================================================

class RefusalTier(Enum):
    R1_POLICY = "R1_POLICY"
    R2_AUTH = "R2_AUTH"
    R3_SAS = "R3_SAS"
    R4_INTEGRITY = "R4_INTEGRITY"
    R5_UNKNOWN = "R5_UNKNOWN"

class RefusalReason(Enum):
    NOT_REGISTERED = "NOT_REGISTERED"
    KEY_REVOKED = "KEY_REVOKED"
    SCOPE_NOT_ALLOWED = "SCOPE_NOT_ALLOWED"
    NO_VALID_HANDSHAKE = "NO_VALID_HANDSHAKE"
    HANDSHAKE_EXPIRED = "HANDSHAKE_EXPIRED"
    KERNEL_SIG_INVALID = "KERNEL_SIG_INVALID"
    OPERATOR_SIG_INVALID = "OPERATOR_SIG_INVALID"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    SAS_ACTIVE = "SAS_ACTIVE"
    TIME_AUTH_DEGRADED = "TIME_AUTH_DEGRADED"
    DB_ERROR = "DB_ERROR"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    MODEL_CONTEXT_REQUIRED = "MODEL_CONTEXT_REQUIRED"
    MODEL_DRIFT_EXCEEDED = "MODEL_DRIFT_EXCEEDED"
    GEOFENCE_VIOLATION = "GEOFENCE_VIOLATION"
    DELEGATION_INVALID = "DELEGATION_INVALID"
    QUORUM_NOT_MET = "QUORUM_NOT_MET"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    NONCE_CONTEXT_MISMATCH = "NONCE_CONTEXT_MISMATCH"

# =============================================================================
# EXCEPTIONS
# =============================================================================

class GovernanceViolation(Exception): pass
class SASActiveError(GovernanceViolation): pass
class InsufficientAuthorityError(GovernanceViolation): pass
class OperatorNotAuthorizedError(GovernanceViolation): pass
class IntegrityError(GovernanceViolation): pass
class GeofenceViolation(GovernanceViolation): pass

# =============================================================================
# TELEMETRY (Prometheus-ish)
# =============================================================================

class Telemetry:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}

    def inc(self, name: str, labels: Dict[str, str] = None, value: int = 1):
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def _key(self, name: str, labels: Dict[str, str] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def export_prometheus(self) -> str:
        lines = []
        with self._lock:
            for k, v in self._counters.items():
                lines.append(f"# TYPE {k.split('{')[0]} counter")
                lines.append(f"{k} {v}")
            for k, v in self._gauges.items():
                lines.append(f"# TYPE {k.split('{')[0]} gauge")
                lines.append(f"{k} {v}")
        return "\n".join(lines)

    def export_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {"counters": dict(self._counters), "gauges": dict(self._gauges)}

# =============================================================================
# GUARDIAN VAULT X — Seals + Witness hooks
# =============================================================================

@dataclass
class AuditSeal:
    seal_id: str
    seq_start: int
    seq_end: int
    entries_hash: str
    sealed_at: str
    kernel_sig: str
    witness_sigs: Dict[str, str] = field(default_factory=dict)

class GuardianVaultX:
    def __init__(self, seal_interval: int = DEFAULT_SEAL_INTERVAL):
        self._entries: List[Dict[str, Any]] = []
        self._prev_hash: str = "0" * 64
        self._seals: List[AuditSeal] = []
        self._seal_interval = seal_interval
        self._last_sealed_seq = -1

    def log(self, stream: str, event: str, **details) -> Dict[str, Any]:
        entry = {"seq": len(self._entries), "ts": now_z(), "stream": stream, "event": event, "details": details, "prev_hash": self._prev_hash}
        entry_json = _json_canon(entry)
        entry["hash"] = hashlib.sha256(entry_json.encode()).hexdigest()
        self._entries.append(entry)
        self._prev_hash = entry["hash"]
        return entry

    def verify_chain(self) -> bool:
        prev_hash = "0" * 64
        for entry in self._entries:
            if entry.get("prev_hash") != prev_hash:
                return False
            check = {k: v for k, v in entry.items() if k != "hash"}
            check["prev_hash"] = prev_hash
            if hashlib.sha256(_json_canon(check).encode()).hexdigest() != entry.get("hash"):
                return False
            prev_hash = entry["hash"]
        return True

    def should_seal(self) -> bool:
        return len(self._entries) - self._last_sealed_seq - 1 >= self._seal_interval

    def create_seal(self, kernel_sign_hex: Callable[[bytes], str]) -> Optional[AuditSeal]:
        seq_start = self._last_sealed_seq + 1
        seq_end = len(self._entries) - 1
        if seq_end < seq_start:
            return None
        segment = self._entries[seq_start: seq_end + 1]
        entries_hash = sha256_bytes(_json_canon(segment).encode())

        seal_payload = _json_canon({
            "schema": SCHEMA_VERSION,
            "kind": "AUDIT_SEAL",
            "seq_start": seq_start,
            "seq_end": seq_end,
            "entries_hash": entries_hash,
            "sealed_at": now_z(),
        }).encode()

        seal = AuditSeal(
            seal_id=secrets.token_hex(8),
            seq_start=seq_start,
            seq_end=seq_end,
            entries_hash=entries_hash,
            sealed_at=now_z(),
            kernel_sig=kernel_sign_hex(seal_payload),
        )
        self._seals.append(seal)
        self._last_sealed_seq = seq_end
        self.log("VAULT", "SEAL_CREATED", seal_id=seal.seal_id, seq_start=seq_start, seq_end=seq_end)
        return seal

    def add_witness_signature(self, seal_id: str, witness_id: str, signature: str) -> bool:
        for seal in self._seals:
            if seal.seal_id == seal_id:
                seal.witness_sigs[witness_id] = signature
                self.log("VAULT", "WITNESS_ADDED", seal_id=seal_id, witness_id=witness_id)
                return True
        return False

    def export(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def export_seals(self) -> List[Dict[str, Any]]:
        return [asdict(s) for s in self._seals]

    def tail(self, n: int = 50) -> List[Dict[str, Any]]:
        return self._entries[-n:]

# =============================================================================
# PERSISTENCE
# =============================================================================

class KernelDB:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);

            CREATE TABLE IF NOT EXISTS operators(
              pubkey_hex TEXT PRIMARY KEY,
              key_id TEXT,
              name TEXT,
              role TEXT,
              scopes_json TEXT,
              geo_constraint_json TEXT,
              created TEXT,
              revoked TEXT,
              reason TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions(
              session_id TEXT PRIMARY KEY,
              operator_pubkey TEXT,
              operator_key_id TEXT,
              issued_at TEXT,
              expires_at TEXT,
              max_tier INT,
              delegator_session TEXT,
              valid INT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions ON sessions(operator_pubkey, valid);

            CREATE TABLE IF NOT EXISTS handshakes(
              token_id TEXT PRIMARY KEY,
              issuer_key_id TEXT,
              issuer_name TEXT,
              issuer_pubkey TEXT,
              scope TEXT,
              nonce TEXT,
              nonce_context_hash TEXT,
              issued TEXT,
              expires TEXT,
              session_id TEXT,
              policy_version TEXT,
              model_fp TEXT,
              op_hash TEXT,
              op_sig TEXT,
              k_key TEXT,
              k_sig TEXT,
              received TEXT,
              valid INT
            );
            CREATE INDEX IF NOT EXISTS idx_hs ON handshakes(scope, nonce, valid);

            CREATE TABLE IF NOT EXISTS replay(
              id INTEGER PRIMARY KEY,
              scope TEXT,
              nonce TEXT,
              consumed TEXT,
              UNIQUE(scope, nonce)
            );

            CREATE TABLE IF NOT EXISTS capsules(
              id TEXT PRIMARY KEY,
              created TEXT,
              kind TEXT,
              token TEXT,
              sha TEXT,
              data BLOB
            );

            CREATE TABLE IF NOT EXISTS policy_hist(
              id INTEGER PRIMARY KEY,
              version TEXT,
              changed TEXT,
              old TEXT,
              new TEXT,
              reason TEXT,
              rollback_allowed INT
            );

            CREATE TABLE IF NOT EXISTS sas(
              id INT PRIMARY KEY CHECK(id=1),
              active INT,
              reason TEXT
            );
            INSERT OR IGNORE INTO sas VALUES(1, 0, NULL);

            CREATE TABLE IF NOT EXISTS quorum_trustees(
              trustee_id TEXT PRIMARY KEY,
              pubkey_hex TEXT,
              name TEXT,
              active INT
            );

            CREATE TABLE IF NOT EXISTS emergency_overrides(
              override_id TEXT PRIMARY KEY,
              initiated_at TEXT,
              reason TEXT,
              required_sigs INT,
              collected_sigs TEXT,
              executed INT
            );

            CREATE TABLE IF NOT EXISTS rate_limits(
              key_id TEXT PRIMARY KEY,
              violations INT,
              last_violation TEXT,
              backoff_until TEXT
            );

            CREATE TABLE IF NOT EXISTS decisions(
              id TEXT PRIMARY KEY,
              decided_at TEXT,
              scope TEXT,
              nonce TEXT,
              outcome TEXT,
              envelope_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_decisions_scope_nonce ON decisions(scope, nonce);
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def integrity_check(self) -> bool:
        r = self.conn.execute("PRAGMA integrity_check;").fetchone()
        return r and r[0] == "ok"

    def get_meta(self, k: str, default: str = None) -> Optional[str]:
        r = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def set_meta(self, k: str, v: str):
        with self._lock:
            self.conn.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
            self.conn.commit()

    def upsert_op(self, r: dict):
        with self._lock:
            self.conn.execute("""
                INSERT INTO operators VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(pubkey_hex) DO UPDATE SET
                  revoked=excluded.revoked, reason=excluded.reason, geo_constraint_json=excluded.geo_constraint_json,
                  scopes_json=excluded.scopes_json
            """, (r["pk"], r["kid"], r["name"], r["role"], r["scopes"], r.get("geo"), r["created"], r.get("revoked"), r.get("reason")))
            self.conn.commit()

    def get_op(self, pk: str) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM operators WHERE pubkey_hex=?", (pk,)).fetchone()
        if not r:
            return None
        return {"pk": r[0], "kid": r[1], "name": r[2], "role": r[3], "scopes": r[4], "geo": r[5], "created": r[6], "revoked": r[7], "reason": r[8]}

    def list_ops(self) -> List[dict]:
        rows = self.conn.execute("SELECT pubkey_hex,key_id,name,role,scopes_json,geo_constraint_json,created,revoked,reason FROM operators ORDER BY created DESC").fetchall()
        out = []
        for r in rows:
            out.append({
                "pubkey_hex": r[0], "key_id": r[1], "name": r[2], "role": r[3],
                "scopes": json.loads(r[4]) if r[4] else [],
                "geo": json.loads(r[5]) if r[5] else None,
                "created": r[6], "revoked": r[7], "reason": r[8],
            })
        return out

    def create_session(self, s: dict):
        with self._lock:
            self.conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)",
                (s["session_id"], s["operator_pubkey"], s["operator_key_id"], s["issued_at"], s["expires_at"], s["max_tier"], s.get("delegator_session"), 1))
            self.conn.commit()

    def get_session(self, sid: str) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone()
        if not r:
            return None
        return {"session_id": r[0], "operator_pubkey": r[1], "operator_key_id": r[2], "issued_at": r[3],
                "expires_at": r[4], "max_tier": int(r[5]), "delegator_session": r[6], "valid": bool(r[7])}

    def invalidate_session(self, sid: str):
        with self._lock:
            self.conn.execute("UPDATE sessions SET valid=0 WHERE session_id=?", (sid,))
            self.conn.execute("UPDATE sessions SET valid=0 WHERE delegator_session=?", (sid,))
            self.conn.commit()

    def upsert_hs(self, h: dict):
        with self._lock:
            self.conn.execute("""
                INSERT INTO handshakes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(token_id) DO UPDATE SET valid=excluded.valid
            """, (h["tid"], h["ikid"], h["iname"], h["ipk"], h["scope"], h["nonce"], h.get("nonce_ctx"),
                  h["issued"], h["expires"], h["session_id"], h["policy_version"], h.get("model_fp"),
                  h["ophash"], h["opsig"], h["kkey"], h["ksig"], h["recv"], 1 if h["valid"] else 0))
            self.conn.commit()

    def revoke_all_hs(self):
        with self._lock:
            self.conn.execute("UPDATE handshakes SET valid=0")
            self.conn.commit()

    def find_hs(self, scope: str, nonce: str) -> List[dict]:
        rows = self.conn.execute("""
            SELECT * FROM handshakes WHERE scope=? AND nonce=? AND valid=1 ORDER BY received
        """, (scope, nonce)).fetchall()
        return [{"tid": r[0], "ikid": r[1], "iname": r[2], "ipk": r[3], "scope": r[4], "nonce": r[5],
                 "nonce_ctx": r[6], "issued": r[7], "expires": r[8], "session_id": r[9], "policy_version": r[10],
                 "model_fp": r[11], "ophash": r[12], "opsig": r[13], "kkey": r[14], "ksig": r[15],
                 "recv": r[16], "valid": bool(r[17])} for r in rows]

    def replay_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM replay").fetchone()[0]

    def replay_exists(self, scope: str, nonce: str) -> bool:
        return self.conn.execute("SELECT 1 FROM replay WHERE scope=? AND nonce=?", (scope, nonce)).fetchone() is not None

    def add_replay(self, scope: str, nonce: str):
        with self._lock:
            self.conn.execute("INSERT INTO replay(scope, nonce, consumed) VALUES(?,?,?)", (scope, nonce, now_z()))
            self.conn.commit()

    def capsule(self, cid: str, kind: str, tid: str, data: bytes):
        with self._lock:
            self.conn.execute("INSERT INTO capsules VALUES(?,?,?,?,?,?)", (cid, now_z(), kind, tid, sha256_bytes(data), data))
            self.conn.commit()

    def list_capsules(self, tid: str) -> List[dict]:
        return [{"capsule_id": r[0], "created_at": r[1], "kind": r[2], "token_id": r[3], "sha256": r[4]}
                for r in self.conn.execute("SELECT id, created, kind, token, sha FROM capsules WHERE token=?", (tid,)).fetchall()]

    def add_policy(self, version: str, old: str, new: str, reason: str, rollback_allowed: bool = True):
        with self._lock:
            self.conn.execute("INSERT INTO policy_hist(version, changed, old, new, reason, rollback_allowed) VALUES(?,?,?,?,?,?)",
                (version, now_z(), old, new, reason, 1 if rollback_allowed else 0))
            self.conn.commit()

    def get_policy_history(self) -> List[dict]:
        return [{"id": r[0], "version": r[1], "changed": r[2], "old": r[3], "new": r[4], "reason": r[5], "rollback_allowed": bool(r[6])}
                for r in self.conn.execute("SELECT * FROM policy_hist ORDER BY id DESC").fetchall()]

    def get_sas(self) -> Tuple[bool, Optional[str]]:
        r = self.conn.execute("SELECT active, reason FROM sas WHERE id=1").fetchone()
        return (bool(r[0]), r[1])

    def set_sas(self, active: bool, reason: Optional[str]):
        with self._lock:
            self.conn.execute("UPDATE sas SET active=?, reason=? WHERE id=1", (1 if active else 0, reason))
            self.conn.commit()

    def add_trustee(self, tid: str, pubkey: str, name: str):
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO quorum_trustees VALUES(?,?,?,1)", (tid, pubkey, name))
            self.conn.commit()

    def get_active_trustees(self) -> List[dict]:
        return [{"trustee_id": r[0], "pubkey_hex": r[1], "name": r[2]}
                for r in self.conn.execute("SELECT trustee_id, pubkey_hex, name FROM quorum_trustees WHERE active=1").fetchall()]

    def record_rate_violation(self, key_id: str) -> Tuple[int, str]:
        with self._lock:
            r = self.conn.execute("SELECT violations, backoff_until FROM rate_limits WHERE key_id=?", (key_id,)).fetchone()
            if r:
                violations = int(r[0]) + 1
                backoff_seconds = min(2 ** violations, 3600)
            else:
                violations = 1
                backoff_seconds = 2
            backoff_until = iso_z(now_utc() + datetime.timedelta(seconds=backoff_seconds))
            self.conn.execute(
                "INSERT INTO rate_limits VALUES(?,?,?,?) ON CONFLICT(key_id) DO UPDATE SET violations=?, last_violation=?, backoff_until=?",
                (key_id, violations, now_z(), backoff_until, violations, now_z(), backoff_until),
            )
            self.conn.commit()
            return violations, backoff_until

    def check_rate_backoff(self, key_id: str) -> Optional[str]:
        r = self.conn.execute("SELECT backoff_until FROM rate_limits WHERE key_id=?", (key_id,)).fetchone()
        if r and r[0]:
            backoff = datetime.datetime.fromisoformat(r[0].replace("Z", "+00:00"))
            if now_utc() < backoff:
                return r[0]
        return None

    def add_decision(self, decision_id: str, scope: str, nonce: str, outcome: str, envelope: Dict[str, Any]):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO decisions VALUES(?,?,?,?,?,?)",
                (decision_id, now_z(), scope, nonce, outcome, _json_canon(envelope)),
            )
            self.conn.commit()

    def get_decisions(self, scope: str, nonce: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,decided_at,scope,nonce,outcome,envelope_json FROM decisions WHERE scope=? AND nonce=? ORDER BY decided_at DESC",
            (scope, nonce),
        ).fetchall()
        return [{"id": r[0], "decided_at": r[1], "scope": r[2], "nonce": r[3], "outcome": r[4],
                 "envelope": json.loads(r[5]) if r[5] else None} for r in rows]

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class OperatorRecord:
    key_id: str
    name: str
    role: str
    pubkey_hex: str
    allowed_scopes: Set[ActionScope]
    geo_constraint: Optional[GeoConstraint]
    created_at: str
    revoked_at: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def can_authorize(self, scope: ActionScope) -> bool:
        return self.is_active and scope in self.allowed_scopes

@dataclass
class OperatorIdentity:
    key_id: str
    name: str
    role: str
    signing_key: SigningKey
    verify_key: VerifyKey

    @classmethod
    def generate(cls, name: str, role: str) -> "OperatorIdentity":
        sk = SigningKey.generate()
        vk = sk.verify_key
        return cls(hashlib.sha256(vk.encode()).hexdigest()[:16], name, role, sk, vk)

    @property
    def pubkey_hex(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode()

    def sign(self, msg: bytes) -> str:
        return self.signing_key.sign(msg).signature.hex()

    def export_private_hex(self) -> str:
        return self.signing_key.encode(encoder=HexEncoder).decode()

@dataclass
class ModelContext:
    model_provider: str
    model_id: str
    model_fingerprint_hash: str
    drift_score: float
    drift_threshold: float
    tier: str = "prod"

@dataclass
class HandshakePayload:
    schema: str
    alg: str
    token_id: str
    issuer_key_id: str
    issuer_name: str
    issuer_pubkey: str
    scope: str
    action_nonce: str
    nonce_context_hash: Optional[str]
    issued_at: str
    expires_at: str
    session_id: str
    policy_version: str
    model_fingerprint_hash: Optional[str] = None

    def to_bytes(self) -> bytes:
        return _json_canon(asdict(self)).encode()

    def sha256(self) -> str:
        return sha256_bytes(self.to_bytes())

@dataclass
class KernelAttestationPayload:
    schema: str
    alg: str
    kernel_key_id: str
    operator_payload_hash: str
    operator_sig: str
    verification_outcome: str
    received_at: str
    policy_version: str

    def to_bytes(self) -> bytes:
        return _json_canon(asdict(self)).encode()

@dataclass
class Handshake:
    token_id: str
    issuer_key_id: str
    issuer_name: str
    issuer_pubkey: str
    scope: ActionScope
    action_nonce: str
    nonce_context_hash: Optional[str]
    issued_at: str
    expires_at: str
    session_id: str
    policy_version: str
    model_fingerprint_hash: Optional[str]
    operator_payload_hash: str
    operator_sig: str
    kernel_key_id: str
    kernel_sig: str
    received_at: str
    valid: bool = True

    def is_expired(self) -> bool:
        try:
            return now_utc() > datetime.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except Exception:
            return True

    def operator_payload(self) -> HandshakePayload:
        return HandshakePayload(
            schema=SCHEMA_VERSION, alg=DEFAULT_ALGORITHM, token_id=self.token_id,
            issuer_key_id=self.issuer_key_id, issuer_name=self.issuer_name,
            issuer_pubkey=self.issuer_pubkey, scope=self.scope.value,
            action_nonce=self.action_nonce, nonce_context_hash=self.nonce_context_hash,
            issued_at=self.issued_at, expires_at=self.expires_at,
            session_id=self.session_id, policy_version=self.policy_version,
            model_fingerprint_hash=self.model_fingerprint_hash,
        )

# =============================================================================
# KERNEL KEY MANAGER
# =============================================================================

class KernelKeyManager:
    def __init__(self, key_file: str):
        self.key_file = Path(key_file)
        self._sk: Optional[SigningKey] = None
        self._vk: Optional[VerifyKey] = None
        self._kid: Optional[str] = None

    def initialize(self, vault: GuardianVaultX):
        if self.key_file.exists():
            self._sk = SigningKey(bytes.fromhex(self.key_file.read_text().strip()))
        else:
            self._sk = SigningKey.generate()
            self.key_file.write_text(self._sk.encode(encoder=HexEncoder).decode())
        self._vk = self._sk.verify_key
        self._kid = hashlib.sha256(self._vk.encode()).hexdigest()[:16]
        vault.log("KERNEL", "KEY_READY", key_id=self._kid)

    @property
    def key_id(self) -> str:
        return self._kid or ""

    @property
    def pubkey_hex(self) -> str:
        return self._vk.encode(encoder=HexEncoder).decode() if self._vk else ""

    @property
    def verify_key(self) -> VerifyKey:
        return self._vk

    def sign_hex(self, msg: bytes) -> str:
        return self._sk.sign(msg).signature.hex()

# =============================================================================
# GOVERNOR
# =============================================================================

class Governor:
    POLICY_VERSION = "1.0"

    def __init__(
        self,
        vault: GuardianVaultX,
        db_file: str = DEFAULT_DB_FILE,
        key_file: str = DEFAULT_KERNEL_KEY_FILE,
        time_authority: TimeAuthority = None,
        replay_window: int = DEFAULT_REPLAY_WINDOW,
        session_ttl: int = DEFAULT_SESSION_TTL_SECONDS,
        quorum_threshold: float = DEFAULT_QUORUM_THRESHOLD,
    ):
        self.vault = vault
        self.db = KernelDB(db_file)
        self.time = time_authority or TimeAuthority()
        self.replay_window = replay_window
        self.session_ttl = session_ttl
        self.quorum_threshold = quorum_threshold
        self.telemetry = Telemetry()

        self._km = KernelKeyManager(key_file)
        self._km.initialize(vault)

        self._sas_active, self._sas_reason = self.db.get_sas()
        pv = self.db.get_meta("policy_version")
        if not pv:
            self.db.set_meta("policy_version", self.POLICY_VERSION)
        self._policy_version = self.db.get_meta("policy_version") or self.POLICY_VERSION

        self._rate_counts: Dict[str, int] = defaultdict(int)
        self._rate_window = None

        self.vault.log("KERNEL", "INITIALIZED", kernel_key_id=self._km.key_id, policy_version=self._policy_version, schema=SCHEMA_VERSION)
        self._startup_continuity_test()

    def _startup_continuity_test(self):
        problems = []
        if not self.db.integrity_check():
            problems.append("db_integrity")
        if not self._km.key_id:
            problems.append("kernel_key_missing")
        if not self.time.health().ok:
            problems.append("time_degraded")
        if not self.vault.verify_chain():
            problems.append("audit_chain")
        if problems:
            self._panic_to_sas("BOOT_FAILURE", problems=problems)
            self.telemetry.inc("kernel_boots_total", {"status": "fail"})
        else:
            self.vault.log("KERNEL", "BOOT_OK")
            self.telemetry.inc("kernel_boots_total", {"status": "ok"})

    @property
    def sas_active(self) -> bool:
        return self._sas_active

    @property
    def kernel_key_id(self) -> str:
        return self._km.key_id

    @property
    def kernel_pubkey_hex(self) -> str:
        return self._km.pubkey_hex

    def _refuse(self, tier: RefusalTier, reason: RefusalReason, **d):
        self.vault.log("REFUSAL", tier.value, reason=reason.value, **d)
        self.telemetry.inc("refusals_total", {"tier": tier.value, "reason": reason.value})

    def _panic_to_sas(self, reason: str, **details):
        if not self._sas_active:
            self._sas_active = True
            self._sas_reason = reason
            self.db.set_sas(True, reason)
            self.db.revoke_all_hs()
            self.vault.log("KERNEL", "PANIC_TO_SAS", reason=reason, **details)
            self.telemetry.inc("sas_panics_total")

    def _check_operational(self, allow_sas_recovery: bool = False, scope: ActionScope = None):
        if not self.db.integrity_check():
            self._panic_to_sas("DB_CORRUPTION")
            raise IntegrityError("DB corrupt")
        if not self.time.health().ok:
            self._panic_to_sas("TIME_DEGRADED")
            raise IntegrityError("Time degraded")
        sat = (self.db.replay_count() / max(1, self.replay_window)) * 100
        if sat >= DEFAULT_REPLAY_SATURATION_PANIC_PCT:
            self._panic_to_sas("REPLAY_SATURATION", saturation_pct=sat)
            raise IntegrityError("Replay saturation")
        if self._sas_active:
            if allow_sas_recovery and scope == ActionScope.SAS_RECOVERY:
                return
            self._refuse(RefusalTier.R3_SAS, RefusalReason.SAS_ACTIVE)
            raise SASActiveError(f"SAS: {self._sas_reason}")

    def _check_rate_limit(self, key_id: str):
        backoff = self.db.check_rate_backoff(key_id)
        if backoff:
            self._refuse(RefusalTier.R4_INTEGRITY, RefusalReason.RATE_LIMIT_EXCEEDED, backoff_until=backoff)
            raise IntegrityError(f"Rate backoff until {backoff}")
        minute = now_utc().replace(second=0, microsecond=0)
        if self._rate_window != minute:
            self._rate_window = minute
            self._rate_counts.clear()
        self._rate_counts[key_id] += 1
        if self._rate_counts[key_id] > DEFAULT_RATE_LIMIT_PER_MINUTE:
            violations, backoff = self.db.record_rate_violation(key_id)
            self._refuse(RefusalTier.R4_INTEGRITY, RefusalReason.RATE_LIMIT_EXCEEDED, violations=violations, backoff_until=backoff)
            raise IntegrityError("Rate limit exceeded")

    def enter_sas(self, reason: str):
        self._sas_active = True
        self._sas_reason = reason
        self.db.set_sas(True, reason)
        self.db.revoke_all_hs()
        self.vault.log("KERNEL", "SAS_ENTERED", reason=reason)
        self.telemetry.inc("sas_entered_total")

    def initiate_emergency_override(self, reason: str) -> str:
        trustees = self.db.get_active_trustees()
        required = max(1, int(len(trustees) * self.quorum_threshold) + 1)
        oid = secrets.token_hex(8)
        with self.db._lock:
            self.db.conn.execute("INSERT INTO emergency_overrides VALUES(?,?,?,?,?,0)", (oid, now_z(), reason, required, json.dumps([])))
            self.db.conn.commit()
        self.vault.log("KERNEL", "EMERGENCY_INITIATED", override_id=oid, required_sigs=required, reason=reason)
        return oid

    def approve_emergency_override(self, override_id: str, trustee_id: str, signature: str) -> bool:
        r = self.db.conn.execute("SELECT required_sigs, collected_sigs, executed FROM emergency_overrides WHERE override_id=?", (override_id,)).fetchone()
        if not r or r[2]:
            return False
        required, collected = int(r[0]), json.loads(r[1])
        if trustee_id in [c["trustee_id"] for c in collected]:
            return False
        # Verify trustee signature against registered pubkey
        trustee = self.db.conn.execute("SELECT pubkey_hex FROM quorum_trustees WHERE trustee_id=? AND active=1", (trustee_id,)).fetchone()
        if trustee and trustee[0]:
            try:
                vk = VerifyKey(bytes.fromhex(trustee[0]))
                vk.verify(override_id.encode(), bytes.fromhex(signature))
            except Exception:
                self.vault.log("KERNEL", "EMERGENCY_APPROVAL_REJECTED", override_id=override_id, trustee_id=trustee_id, reason="bad_signature")
                return False
        collected.append({"trustee_id": trustee_id, "signature": signature, "at": now_z()})
        with self.db._lock:
            self.db.conn.execute("UPDATE emergency_overrides SET collected_sigs=? WHERE override_id=?", (json.dumps(collected), override_id))
            self.db.conn.commit()
        self.vault.log("KERNEL", "EMERGENCY_APPROVAL", override_id=override_id, trustee_id=trustee_id, count=len(collected), required=required)
        if len(collected) >= required:
            return self._execute_emergency_override(override_id)
        return True

    def _execute_emergency_override(self, override_id: str) -> bool:
        with self.db._lock:
            self.db.conn.execute("UPDATE emergency_overrides SET executed=1 WHERE override_id=?", (override_id,))
            self.db.conn.commit()
        if self._sas_active:
            self._sas_active = False
            self._sas_reason = None
            self.db.set_sas(False, None)
        self.vault.log("KERNEL", "EMERGENCY_EXECUTED", override_id=override_id)
        return True

    def _get_operator_record(self, pk: str) -> Optional[OperatorRecord]:
        r = self.db.get_op(pk)
        if not r:
            return None
        geo = None
        if r.get("geo"):
            gd = json.loads(r["geo"])
            geo = GeoConstraint(
                allowed_regions=set(gd.get("allowed_regions") or []),
                denied_regions=set(gd.get("denied_regions") or []),
                max_radius_km=gd.get("max_radius_km"),
                anchor_lat=gd.get("anchor_lat"),
                anchor_lon=gd.get("anchor_lon"),
            )
        scopes = set(ActionScope(s) for s in json.loads(r["scopes"])) if r.get("scopes") else set()
        return OperatorRecord(r["kid"], r["name"], r["role"], r["pk"], scopes, geo, r["created"], r.get("revoked"))

    def register_operator(self, op: OperatorIdentity, scopes: Set[ActionScope], geo: GeoConstraint = None) -> OperatorRecord:
        geo_json = None
        if geo:
            geo_json = _json_canon({
                "allowed_regions": list(geo.allowed_regions),
                "denied_regions": list(geo.denied_regions),
                "max_radius_km": geo.max_radius_km,
                "anchor_lat": geo.anchor_lat,
                "anchor_lon": geo.anchor_lon,
            })
        rec = OperatorRecord(op.key_id, op.name, op.role, op.pubkey_hex, set(scopes), geo, now_z())
        self.db.upsert_op({
            "pk": rec.pubkey_hex, "kid": rec.key_id, "name": rec.name, "role": rec.role,
            "scopes": json.dumps([s.value for s in rec.allowed_scopes]),
            "geo": geo_json, "created": rec.created_at,
        })
        self.vault.log("KERNEL", "OPERATOR_REGISTERED", key_id=rec.key_id, name=rec.name)
        self.telemetry.inc("operators_registered_total")
        return rec

    def revoke_operator(self, pubkey_hex: str, reason: str):
        rec = self.db.get_op(pubkey_hex)
        if rec:
            rec["revoked"] = now_z()
            rec["reason"] = reason
            self.db.upsert_op(rec)
            self.vault.log("KERNEL", "OPERATOR_REVOKED", pubkey_hex=pubkey_hex[:16], reason=reason)

    def create_session(self, op: OperatorIdentity, max_tier: ActionTier = ActionTier.T4_IRREVERSIBLE,
                       ttl_seconds: Optional[int] = None, delegator_session: Optional[str] = None) -> str:
        rec = self._get_operator_record(op.pubkey_hex)
        if not rec or not rec.is_active:
            raise OperatorNotAuthorizedError("Not registered/active")
        if delegator_session:
            ds = self.db.get_session(delegator_session)
            if not ds or not ds["valid"]:
                self._refuse(RefusalTier.R2_AUTH, RefusalReason.DELEGATION_INVALID)
                raise OperatorNotAuthorizedError("Delegator session invalid")
            if max_tier.value > ds["max_tier"]:
                max_tier = ActionTier(ds["max_tier"])
        ttl = ttl_seconds or self.session_ttl
        sid = secrets.token_hex(16)
        self.db.create_session({
            "session_id": sid, "operator_pubkey": op.pubkey_hex, "operator_key_id": op.key_id,
            "issued_at": now_z(), "expires_at": iso_z(now_utc() + datetime.timedelta(seconds=ttl)),
            "max_tier": max_tier.value, "delegator_session": delegator_session,
        })
        self.vault.log("KERNEL", "SESSION_CREATED", session_id=sid[:12], operator=op.name, max_tier=max_tier.name)
        self.telemetry.inc("sessions_created_total")
        return sid

    def revoke_session(self, session_id: str):
        self.db.invalidate_session(session_id)
        self.vault.log("KERNEL", "SESSION_REVOKED", session_id=session_id[:12], cascaded=True)

    def _validate_session(self, sid: str, pk: str, required_tier: ActionTier) -> Tuple[bool, Optional[RefusalReason], str]:
        s = self.db.get_session(sid)
        if not s or not s["valid"]:
            return False, RefusalReason.SESSION_INVALID, "invalid"
        if s["operator_pubkey"] != pk:
            return False, RefusalReason.SESSION_INVALID, "mismatch"
        if required_tier.value > s["max_tier"]:
            return False, RefusalReason.SESSION_INVALID, "tier insufficient"
        if now_utc() > datetime.datetime.fromisoformat(s["expires_at"].replace("Z", "+00:00")):
            return False, RefusalReason.SESSION_EXPIRED, "expired"
        return True, None, "ok"

    def _check_geofence(self, rec: OperatorRecord, region: str = None, lat: float = None, lon: float = None):
        if rec.geo_constraint:
            ok, msg = rec.geo_constraint.check(region, lat, lon)
            if not ok:
                self._refuse(RefusalTier.R1_POLICY, RefusalReason.GEOFENCE_VIOLATION, detail=msg)
                raise GeofenceViolation(msg)

    def _kernel_attestation_payload(self, hs: Handshake, outcome: str = "VALID") -> KernelAttestationPayload:
        return KernelAttestationPayload(
            schema=SCHEMA_VERSION, alg=DEFAULT_ALGORITHM, kernel_key_id=hs.kernel_key_id,
            operator_payload_hash=hs.operator_payload_hash, operator_sig=hs.operator_sig,
            verification_outcome=outcome, received_at=hs.received_at, policy_version=self._policy_version,
        )

    def _verify_operator_signature(self, hs: Handshake) -> Tuple[bool, Optional[RefusalReason]]:
        rec = self._get_operator_record(hs.issuer_pubkey)
        if not rec:
            return False, RefusalReason.NOT_REGISTERED
        if not rec.is_active:
            return False, RefusalReason.KEY_REVOKED
        if not rec.can_authorize(hs.scope):
            return False, RefusalReason.SCOPE_NOT_ALLOWED
        try:
            VerifyKey(bytes.fromhex(hs.issuer_pubkey)).verify(hs.operator_payload().to_bytes(), bytes.fromhex(hs.operator_sig))
            return True, None
        except Exception:
            return False, RefusalReason.OPERATOR_SIG_INVALID

    def _verify_kernel_signature(self, hs: Handshake) -> Tuple[bool, Optional[RefusalReason]]:
        try:
            self._km.verify_key.verify(self._kernel_attestation_payload(hs).to_bytes(), bytes.fromhex(hs.kernel_sig))
            return True, None
        except Exception:
            return False, RefusalReason.KERNEL_SIG_INVALID

    def _consume_nonce(self, scope: ActionScope, nonce: str):
        if self.db.replay_exists(scope.value, nonce):
            self._refuse(RefusalTier.R2_AUTH, RefusalReason.REPLAY_DETECTED)
            raise InsufficientAuthorityError("Replay detected")
        self.db.add_replay(scope.value, nonce)

    def issue(self, op: OperatorIdentity, session_id: str, scope: ActionScope, nonce: str,
              ttl_seconds: int = DEFAULT_HANDSHAKE_TTL_SECONDS, nonce_context: Dict[str, Any] = None,
              region: str = None, lat: float = None, lon: float = None, model_ctx: ModelContext = None) -> Handshake:
        self._check_operational(allow_sas_recovery=True, scope=scope)
        self._check_rate_limit(op.key_id)

        tier = SCOPE_TIER_MAP[scope]
        ok_sess, why, msg = self._validate_session(session_id, op.pubkey_hex, tier)
        if not ok_sess:
            self._refuse(RefusalTier.R2_AUTH, why or RefusalReason.SESSION_INVALID)
            raise OperatorNotAuthorizedError(msg)

        rec = self._get_operator_record(op.pubkey_hex)
        if not rec or not rec.is_active or not rec.can_authorize(scope):
            raise OperatorNotAuthorizedError("Not authorized")

        self._check_geofence(rec, region, lat, lon)

        if tier.value >= ActionTier.T3_INTERVENTION.value and scope != ActionScope.SAS_RECOVERY:
            if model_ctx is None:
                self._refuse(RefusalTier.R2_AUTH, RefusalReason.MODEL_CONTEXT_REQUIRED)
                raise OperatorNotAuthorizedError("Model context required for T3/T4")
            if float(model_ctx.drift_score) > float(model_ctx.drift_threshold):
                self._refuse(RefusalTier.R2_AUTH, RefusalReason.MODEL_DRIFT_EXCEEDED)
                raise OperatorNotAuthorizedError("Model drift exceeded")
            if model_ctx.tier == "experimental":
                self._refuse(RefusalTier.R1_POLICY, RefusalReason.MODEL_DRIFT_EXCEEDED, note="experimental_blocked")
                raise OperatorNotAuthorizedError("Experimental model tier blocked for T3/T4")

        nonce_ctx_hash = hashlib.sha256(_json_canon(nonce_context).encode()).hexdigest()[:16] if nonce_context else None
        model_fp = model_ctx.model_fingerprint_hash if model_ctx else None

        hs = Handshake(
            token_id=secrets.token_hex(16), issuer_key_id=op.key_id, issuer_name=op.name,
            issuer_pubkey=op.pubkey_hex, scope=scope, action_nonce=nonce,
            nonce_context_hash=nonce_ctx_hash, issued_at=now_z(),
            expires_at=iso_z(now_utc() + datetime.timedelta(seconds=ttl_seconds)),
            session_id=session_id, policy_version=self._policy_version,
            model_fingerprint_hash=model_fp, operator_payload_hash="", operator_sig="",
            kernel_key_id=self._km.key_id, kernel_sig="", received_at=now_z(), valid=True,
        )

        pb = hs.operator_payload().to_bytes()
        hs.operator_payload_hash = sha256_bytes(pb)
        hs.operator_sig = op.sign(pb)

        ab = self._kernel_attestation_payload(hs).to_bytes()
        hs.kernel_sig = self._km.sign_hex(ab)

        self.db.capsule(secrets.token_hex(8), "OPERATOR_PAYLOAD", hs.token_id, pb)
        self.db.capsule(secrets.token_hex(8), "KERNEL_ATTESTATION", hs.token_id, ab)

        self.db.upsert_hs({
            "tid": hs.token_id, "ikid": hs.issuer_key_id, "iname": hs.issuer_name, "ipk": hs.issuer_pubkey,
            "scope": hs.scope.value, "nonce": hs.action_nonce, "nonce_ctx": nonce_ctx_hash,
            "issued": hs.issued_at, "expires": hs.expires_at, "session_id": hs.session_id,
            "policy_version": hs.policy_version, "model_fp": model_fp,
            "ophash": hs.operator_payload_hash, "opsig": hs.operator_sig,
            "kkey": hs.kernel_key_id, "ksig": hs.kernel_sig, "recv": hs.received_at, "valid": True,
        })

        self.vault.log("GOVERNOR", "HANDSHAKE_ISSUED", token_id=hs.token_id[:12], issuer=hs.issuer_name, scope=scope.value, tier=tier.name)
        self.telemetry.inc("handshakes_issued_total", {"scope": scope.value, "tier": tier.name})

        if self.vault.should_seal():
            self.vault.create_seal(self._km.sign_hex)

        return hs

    def require_handshake(self, scope: ActionScope, nonce: str, expected_context: Dict[str, Any] = None) -> Handshake:
        self._check_operational()
        expected_ctx_hash = hashlib.sha256(_json_canon(expected_context).encode()).hexdigest()[:16] if expected_context else None

        for r in self.db.find_hs(scope.value, nonce):
            hs = Handshake(
                token_id=r["tid"], issuer_key_id=r["ikid"], issuer_name=r["iname"],
                issuer_pubkey=r["ipk"], scope=ActionScope(r["scope"]), action_nonce=r["nonce"],
                nonce_context_hash=r.get("nonce_ctx"), issued_at=r["issued"], expires_at=r["expires"],
                session_id=r["session_id"], policy_version=r["policy_version"],
                model_fingerprint_hash=r.get("model_fp"), operator_payload_hash=r["ophash"],
                operator_sig=r["opsig"], kernel_key_id=r["kkey"], kernel_sig=r["ksig"],
                received_at=r["recv"], valid=r["valid"],
            )
            if hs.is_expired():
                continue
            if expected_ctx_hash and hs.nonce_context_hash != expected_ctx_hash:
                self._refuse(RefusalTier.R2_AUTH, RefusalReason.NONCE_CONTEXT_MISMATCH)
                continue
            ok_op, _ = self._verify_operator_signature(hs)
            if not ok_op:
                continue
            ok_k, _ = self._verify_kernel_signature(hs)
            if not ok_k:
                continue
            self._consume_nonce(scope, nonce)
            self.vault.log("GOVERNOR", "HANDSHAKE_VERIFIED", token_id=hs.token_id[:12], issuer=hs.issuer_name)
            self.telemetry.inc("handshakes_verified_total", {"scope": scope.value})
            return hs

        self._refuse(RefusalTier.R2_AUTH, RefusalReason.NO_VALID_HANDSHAKE)
        raise InsufficientAuthorityError(f"No valid handshake for {scope.value}")

    def require_dual_handshake(self, scope: ActionScope, nonce: str) -> Tuple[Handshake, Handshake]:
        self._check_operational()
        valid: List[Handshake] = []
        keys_seen: Set[str] = set()

        for r in self.db.find_hs(scope.value, nonce):
            hs = Handshake(
                token_id=r["tid"], issuer_key_id=r["ikid"], issuer_name=r["iname"],
                issuer_pubkey=r["ipk"], scope=ActionScope(r["scope"]), action_nonce=r["nonce"],
                nonce_context_hash=r.get("nonce_ctx"), issued_at=r["issued"], expires_at=r["expires"],
                session_id=r["session_id"], policy_version=r["policy_version"],
                model_fingerprint_hash=r.get("model_fp"), operator_payload_hash=r["ophash"],
                operator_sig=r["opsig"], kernel_key_id=r["kkey"], kernel_sig=r["ksig"],
                received_at=r["recv"], valid=r["valid"],
            )
            if hs.issuer_pubkey in keys_seen or hs.is_expired():
                continue
            ok_op, _ = self._verify_operator_signature(hs)
            if not ok_op:
                continue
            ok_k, _ = self._verify_kernel_signature(hs)
            if not ok_k:
                continue
            valid.append(hs)
            keys_seen.add(hs.issuer_pubkey)
            if len(valid) >= 2:
                break

        if len(valid) < 2:
            self._refuse(RefusalTier.R2_AUTH, RefusalReason.NO_VALID_HANDSHAKE, found=len(valid))
            raise InsufficientAuthorityError("T4 requires dual handshake")

        self._consume_nonce(scope, nonce)
        self.vault.log("GOVERNOR", "DUAL_HANDSHAKE_VERIFIED", issuers=[valid[0].issuer_name, valid[1].issuer_name])
        return valid[0], valid[1]

    def governance_health(self) -> Dict[str, Any]:
        th = self.time.health()
        sas_active, sas_reason = self.db.get_sas()
        replay_count = self.db.replay_count()
        sat = int((replay_count / max(1, self.replay_window)) * 100)
        self.telemetry.set_gauge("replay_saturation_pct", sat)
        return {
            "ok": self.db.integrity_check() and th.ok and not sas_active and self.vault.verify_chain(),
            "kernel": {"key_id": self._km.key_id, "pubkey_hex": self._km.pubkey_hex, "schema": SCHEMA_VERSION, "policy": self._policy_version, "algorithm": DEFAULT_ALGORITHM},
            "sas": {"active": sas_active, "reason": sas_reason},
            "time": asdict(th),
            "replay": {"count": replay_count, "capacity": self.replay_window, "saturation_pct": sat},
            "audit": {"chain_ok": self.vault.verify_chain(), "seals": len(self.vault.export_seals())},
            "telemetry": self.telemetry.export_dict(),
        }

    def export_attestation_bundle(self, token_id: str) -> Dict[str, Any]:
        caps = self.db.list_capsules(token_id)
        return {
            "id": token_id, "kernel_key_id": self._km.key_id, "kernel_pubkey_hex": self._km.pubkey_hex,
            "policy_version": self._policy_version, "schema": SCHEMA_VERSION,
            "capsules": caps, "vault_chain_ok": self.vault.verify_chain(),
            "seals": self.vault.export_seals()[-3:],
        }

    def list_operators(self) -> List[Dict[str, Any]]:
        return self.db.list_ops()

    def policy_history(self) -> List[Dict[str, Any]]:
        return self.db.get_policy_history()

    def list_seals(self) -> List[Dict[str, Any]]:
        return self.vault.export_seals()

    def remote_attestation_bundle(self) -> Dict[str, Any]:
        health = self.governance_health()
        payload = {
            "schema": SCHEMA_VERSION, "kind": "REMOTE_ATTESTATION", "issued_at": now_z(),
            "kernel": health["kernel"], "sas": health["sas"], "time": health["time"],
            "replay": health["replay"], "audit": health["audit"],
        }
        b = _json_canon(payload).encode()
        sig = self._km.sign_hex(b)
        return {"payload": payload, "kernel_sig": sig}

    def replay_decisions(self, scope: ActionScope, nonce: str) -> List[Dict[str, Any]]:
        return self.db.get_decisions(scope.value, nonce)

    def _persist_decision(self, scope: ActionScope, nonce: str, outcome: str, envelope: Dict[str, Any]):
        did = secrets.token_hex(16)
        self.db.add_decision(did, scope.value, nonce, outcome, envelope)

    def close(self):
        self.db.close()

# =============================================================================
# MGI — Governance Envelope v2.0
# =============================================================================

class MGI:
    def __init__(self, gov: Governor):
        self.gov = gov

    def authorize(self, scope: ActionScope, nonce: str, required_tier: Optional[ActionTier] = None,
                  expected_context: Optional[Dict[str, Any]] = None, model_ctx: Optional[ModelContext] = None,
                  t4_requires_dual: bool = True) -> Dict[str, Any]:
        decided_at = now_z()
        tier = SCOPE_TIER_MAP[scope]
        if required_tier and tier.value < required_tier.value:
            env = self._deny(scope, nonce, decided_at, tier, RefusalTier.R1_POLICY, RefusalReason.SCOPE_NOT_ALLOWED, note="required_tier_exceeds_scope_tier")
            self.gov._persist_decision(scope, nonce, "DENY", env)
            return env

        model_block_reason = None
        if tier.value >= ActionTier.T3_INTERVENTION.value and scope != ActionScope.SAS_RECOVERY:
            if model_ctx is None:
                model_block_reason = (RefusalTier.R2_AUTH, RefusalReason.MODEL_CONTEXT_REQUIRED)
            elif float(model_ctx.drift_score) > float(model_ctx.drift_threshold):
                model_block_reason = (RefusalTier.R2_AUTH, RefusalReason.MODEL_DRIFT_EXCEEDED)
            elif model_ctx.tier == "experimental":
                model_block_reason = (RefusalTier.R1_POLICY, RefusalReason.MODEL_DRIFT_EXCEEDED)

        if model_block_reason:
            rt, rr = model_block_reason
            env = self._deny(scope, nonce, decided_at, tier, rt, rr, model_ctx=model_ctx)
            self.gov._persist_decision(scope, nonce, "DENY", env)
            return env

        try:
            evidence = {}
            if tier == ActionTier.T4_IRREVERSIBLE and t4_requires_dual:
                hs1, hs2 = self.gov.require_dual_handshake(scope, nonce)
                evidence["handshakes"] = [
                    self.gov.export_attestation_bundle(hs1.token_id),
                    self.gov.export_attestation_bundle(hs2.token_id),
                ]
                issuers = [hs1.issuer_name, hs2.issuer_name]
            else:
                hs = self.gov.require_handshake(scope, nonce, expected_context=expected_context)
                evidence["handshakes"] = [self.gov.export_attestation_bundle(hs.token_id)]
                issuers = [hs.issuer_name]

            health = self.gov.governance_health()
            env = {
                "schema": SCHEMA_VERSION, "kind": "GOVERNANCE_ENVELOPE_V2",
                "decided_at": decided_at, "outcome": "ALLOW", "scope": scope.value,
                "tier": tier.name, "nonce": nonce, "issuers": issuers, "health": health,
                "model_context": asdict(model_ctx) if model_ctx else None,
                "evidence": evidence, "refusal": None,
            }
            payload_bytes = _json_canon(env).encode()
            env["decision_sig"] = self.gov._km.sign_hex(payload_bytes)
            self.gov._persist_decision(scope, nonce, "ALLOW", env)
            return env

        except SASActiveError:
            env = self._deny(scope, nonce, decided_at, tier, RefusalTier.R3_SAS, RefusalReason.SAS_ACTIVE, model_ctx=model_ctx)
        except IntegrityError:
            env = self._deny(scope, nonce, decided_at, tier, RefusalTier.R4_INTEGRITY, RefusalReason.DB_ERROR, model_ctx=model_ctx)
        except GeofenceViolation:
            env = self._deny(scope, nonce, decided_at, tier, RefusalTier.R1_POLICY, RefusalReason.GEOFENCE_VIOLATION, model_ctx=model_ctx)
        except Exception:
            env = self._deny(scope, nonce, decided_at, tier, RefusalTier.R5_UNKNOWN, RefusalReason.NO_VALID_HANDSHAKE, model_ctx=model_ctx)

        self.gov._persist_decision(scope, nonce, "DENY", env)
        return env

    def _deny(self, scope: ActionScope, nonce: str, decided_at: str, tier: ActionTier,
              refusal_tier: RefusalTier, refusal_reason: RefusalReason, note: str = None,
              model_ctx: ModelContext = None) -> Dict[str, Any]:
        health = self.gov.governance_health()
        env = {
            "schema": SCHEMA_VERSION, "kind": "GOVERNANCE_ENVELOPE_V2",
            "decided_at": decided_at, "outcome": "DENY", "scope": scope.value,
            "tier": tier.name, "nonce": nonce, "issuers": [], "health": health,
            "model_context": asdict(model_ctx) if model_ctx else None,
            "evidence": {"handshakes": []},
            "refusal": {"tier": refusal_tier.value, "reason": refusal_reason.value, "note": note},
        }
        payload_bytes = _json_canon(env).encode()
        env["decision_sig"] = self.gov._km.sign_hex(payload_bytes)
        return env
