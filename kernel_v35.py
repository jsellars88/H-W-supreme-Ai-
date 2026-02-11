from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import kernel_v34 as k34

SCHEMA_VERSION = "3.5"


def now_z() -> str:
    return datetime.now(timezone.utc).isoformat()


class HSMSlot(str, Enum):
    ROOT = "root"
    SIGNING = "signing"


class TPIScope(str, Enum):
    T4 = "t4"
    ROLLBACK = "rollback"


class LivenessEvent(str, Enum):
    HEARTBEAT = "heartbeat"


class RiskEventType(str, Enum):
    POLICY = "policy"


@dataclass
class Seal:
    index: int
    root: str


class Vault:
    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._seals: List[Seal] = []

    def export(self):
        return self._entries

    def verify_chain(self):
        return True

    def export_seals(self):
        return [asdict(s) for s in self._seals]

    def create_seal(self, signer):
        seal = Seal(index=len(self._entries), root=hashlib.sha256(str(len(self._entries)).encode()).hexdigest())
        self._seals.append(seal)
        return seal


@dataclass
class AttestationResult:
    status: str
    hash: str


class MBA:
    def __init__(self):
        self._last = AttestationResult("ok", hashlib.sha256(b"boot").hexdigest())

    def export(self):
        return asdict(self._last)

    def attest(self):
        self._last = AttestationResult("ok", hashlib.sha256(now_z().encode()).hexdigest())
        return self._last

    def last_attestation_hash(self):
        return self._last.hash


class MGI:
    def __init__(self, gov):
        self._gov = gov

    def authorize(self, scope, nonce, model_ctx=None):
        envelope = {"scope": str(scope), "nonce": nonce, "decision": "allow"}
        self._gov.db.conn.execute("INSERT INTO decisions(scope,nonce,envelope_json) VALUES(?,?,?)", (str(scope), nonce, __import__('json').dumps(envelope)))
        self._gov.db.conn.commit()
        return envelope


@dataclass
class HSMRecord:
    slot: str
    key_id: str
    created_at: str


class HSM:
    def __init__(self):
        self._rotations: List[HSMRecord] = []

    def export_manifest(self):
        return {"slots": [s.value for s in HSMSlot], "rotations": len(self._rotations)}

    def generate_key(self, slot: HSMSlot, witnesses: List[str]):
        rec = HSMRecord(slot=slot.value, key_id=hashlib.sha256((slot.value + now_z()).encode()).hexdigest()[:16], created_at=now_z())
        self._rotations.append(rec)
        return rec

    def rotation_history(self):
        return [asdict(r) for r in self._rotations]


@dataclass
class TPIChallenge:
    challenge_id: str
    scope: str
    initiator_pubkey: str
    satisfied: bool = False


class TPI:
    def __init__(self):
        self._ch: Dict[str, TPIChallenge] = {}

    def initiate(self, scope: TPIScope, initiator_pubkey: str, evidence=None):
        cid = hashlib.sha256((scope.value + initiator_pubkey + now_z()).encode()).hexdigest()[:16]
        ch = TPIChallenge(cid, scope.value, initiator_pubkey, False)
        self._ch[cid] = ch
        return ch

    def complete(self, challenge_id: str, completer_pubkey: str, completer_sig: str):
        ch = self._ch.get(challenge_id)
        if not ch:
            return False, "challenge_not_found"
        ch.satisfied = True
        return True, "ok"

    def get_challenge(self, challenge_id: str):
        return self._ch.get(challenge_id)


class MKC:
    def __init__(self):
        self._peers = {}

    def register_peer(self, peer):
        self._peers[peer.kernel_id] = peer

    def federation_health(self):
        return {"peer_count": len(self._peers), "healthy": True}

    def verify_peer(self, kernel_id: str):
        return {"kernel_id": kernel_id, "verified": kernel_id in self._peers}

    def quarantine_peer(self, kernel_id: str, reason: str):
        return None

    def check_t4_consensus(self):
        return True, "consensus_ok"


@dataclass
class PeerKernel:
    kernel_id: str
    pubkey_hex: str
    endpoint: str
    policy_version: str
    sas_active: bool
    last_seal_root: str
    last_seen: str
    time_authority_ok: bool
    attestation_health: bool


class CRP:
    def __init__(self):
        self._hist: List[Dict[str, Any]] = []

    def initiate(self, reason, from_policy, to_policy, initiator_pubkey):
        rid = hashlib.sha256((reason + now_z()).encode()).hexdigest()[:16]
        tpi = hashlib.sha256((rid + "tpi").encode()).hexdigest()[:16]
        self._hist.append({"rollback_id": rid, "from": from_policy, "to": to_policy})
        return rid, tpi

    def execute(self, rollback_id):
        return True, "executed"

    def history(self):
        return self._hist


class CLG:
    def __init__(self):
        self._events: List[str] = []

    def record_event(self, evt):
        self._events.append(str(evt))

    def check_all(self):
        return {"ok": True, "events": len(self._events)}


@dataclass
class PortableIdentity:
    operator_pubkey: str
    issued_at: str


class GIF:
    def __init__(self):
        self._ids: List[PortableIdentity] = []

    def issue_portable_identity(self, rec):
        fid = PortableIdentity(operator_pubkey=rec.pubkey_hex, issued_at=now_z())
        self._ids.append(fid)
        return fid

    def list_identities(self):
        return [asdict(i) for i in self._ids]

    def get_revocations(self):
        return []


@dataclass
class RiskCost:
    event_type: str
    cost: int


class CEL:
    def __init__(self):
        self._events: List[Dict[str, Any]] = []

    def record(self, evt, operator_id=None, model_id=None, details=None):
        rec = {"event_type": str(evt), "operator_id": operator_id, "model_id": model_id, "details": details or {}}
        self._events.append(rec)
        return RiskCost(event_type=str(evt), cost=1)

    def risk_report(self):
        return {"total_events": len(self._events)}

    def export_events(self):
        return self._events


@dataclass
class SimulationResult:
    scenario: str
    outcome: str


class CSM:
    def __init__(self):
        self._hist: List[Dict[str, Any]] = []

    def simulate_authorize(self, scope, nonce, scenario, mc):
        res = SimulationResult(scenario=scenario, outcome="allow")
        self._hist.append(asdict(res))
        return res

    def simulate_sas(self, reason):
        res = SimulationResult(scenario="sas", outcome="drill")
        self._hist.append(asdict(res))
        return res

    def simulate_policy_migration(self, from_version, to_version):
        res = SimulationResult(scenario="policy-migration", outcome=f"{from_version}->{to_version}")
        self._hist.append(asdict(res))
        return res

    def history(self):
        return self._hist


class GFE:
    def timeline_replay(self, start, end, stream):
        return []

    def operator_behavior_clustering(self):
        return []

    def drift_pattern_analysis(self):
        return {"drift": "none"}

    def sas_root_cause(self):
        return {"causes": []}

    def anomaly_correlation(self):
        return []

    def export_signed_report(self):
        return {"report": "ok", "signed": True}


class CEF:
    def export(self):
        return {"schema": SCHEMA_VERSION}


class WhiteSwanKernel35:
    def __init__(self, db_file=":memory:", key_file=".ws35_key", seal_interval=100):
        self.gov = k34.GovernanceCore()
        self.vault = Vault()
        self.mba = MBA()
        self.mgi = MGI(self.gov)
        self.hsm = HSM()
        self.tpi = TPI()
        self.mkc = MKC()
        self.crp = CRP()
        self.clg = CLG()
        self.gif = GIF()
        self.cel = CEL()
        self.csm = CSM()
        self.gfe = GFE()
        self.cef = CEF()

    def full_health(self):
        return {"status": "ok", "schema": SCHEMA_VERSION}

    def check_invariants(self):
        return {"invariants_ok": True}

    def close(self):
        return None
