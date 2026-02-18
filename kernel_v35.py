#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 Kernel — Unified Governance Kernel
Holmes & Watson Supreme AI™

Extends v3.4 Governor with 11 subsystem modules for constitutional governance.

Subsystems implemented:
  §3  HSM Key Custody
  §4  Measured Boot & Attestation
  §5  Two-Person Integrity (TPI)
  §6  Multi-Kernel Consensus (MKC)
  §7  Constitutional Rollback Protocol (CRP)
  §8  Constitutional Liveness Guarantees (CLG)
  §9  Governance Identity Federation (GIF)
  §10 Constitutional Economics Layer (CEL)
  §11 Constitutional Simulation Mode (CSM)
  §12 Governance Forensics Engine (GFE)
  §13 Constitutional Export Format (CEF)
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import kernel_v34 as k34

# ── Schema version ───────────────────────────────────────────────────

SCHEMA_VERSION = "ws-hs-v3.5"


def now_z() -> str:
    return k34.now_z()


# ═════════════════════════════════════════════════════════════════════
# §3 — HSM KEY CUSTODY
# ═════════════════════════════════════════════════════════════════════

class HSMSlot(Enum):
    kernel_signing = "kernel_signing"
    audit_sealing = "audit_sealing"
    operator_root = "operator_root"
    federation_tls = "federation_tls"


@dataclass
class HSMKeyRecord:
    slot: str
    epoch: int
    pubkey_hex: str
    created_at: str
    witnesses: List[str]


class HSMKeyCustody:
    """Software-simulated HSM key custody."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._slots: Dict[str, HSMKeyRecord] = {}
        self._rotations: List[Dict[str, Any]] = []
        for slot in HSMSlot:
            self._slots[slot.value] = HSMKeyRecord(
                slot=slot.value, epoch=1,
                pubkey_hex=secrets.token_hex(32),
                created_at=now_z(), witnesses=[],
            )
        self._vault.log("HSM", "INITIALIZED", slots=list(self._slots.keys()))

    def export_manifest(self) -> Dict[str, Any]:
        return {
            "slots": {s: asdict(r) for s, r in self._slots.items()},
            "slot_count": len(self._slots),
        }

    def generate_key(self, slot: HSMSlot, witnesses: List[str]) -> HSMKeyRecord:
        current = self._slots.get(slot.value)
        new_epoch = (current.epoch + 1) if current else 1
        rec = HSMKeyRecord(
            slot=slot.value, epoch=new_epoch,
            pubkey_hex=secrets.token_hex(32),
            created_at=now_z(), witnesses=witnesses,
        )
        self._slots[slot.value] = rec
        self._rotations.append({
            "slot": slot.value, "old_epoch": new_epoch - 1,
            "new_epoch": new_epoch, "rotated_at": now_z(),
            "witnesses": witnesses,
        })
        self._vault.log("HSM", "KEY_ROTATED", slot=slot.value, epoch=new_epoch)
        return rec

    def rotation_history(self) -> List[Dict[str, Any]]:
        return list(self._rotations)


# ═════════════════════════════════════════════════════════════════════
# §4 — MEASURED BOOT & ATTESTATION
# ═════════════════════════════════════════════════════════════════════

@dataclass
class AttestationResult:
    ok: bool
    drift_from_baseline: float
    measurements: Dict[str, str]
    attested_at: str


class MeasuredBootAttestation:
    """Collects system measurements at boot and verifies them on re-attestation."""

    def __init__(self, vault: k34.GuardianVaultX, gov: k34.Governor):
        self._vault = vault
        self._gov = gov
        self._baseline: Dict[str, str] = {}
        self._last_hash: Optional[str] = None
        self._degraded = False
        self._attest_initial()

    def _attest_initial(self):
        measurements = self._collect_measurements()
        self._baseline = measurements
        h = hashlib.sha256(k34._json_canon(measurements).encode()).hexdigest()
        self._last_hash = h
        self._vault.log("MBA", "BASELINE_SET", hash=h)

    def _collect_measurements(self) -> Dict[str, str]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kernel_key_id": self._gov.kernel_key_id,
            "policy_version": self._gov._policy_version,
            "db_integrity": str(self._gov.db.integrity_check()),
            "vault_chain": str(self._gov.vault.verify_chain()),
        }

    def export(self) -> Dict[str, Any]:
        return {
            "baseline": self._baseline,
            "last_attestation_hash": self._last_hash,
            "degraded": self._degraded,
            "attested_at": now_z(),
        }

    def attest(self) -> AttestationResult:
        current = self._collect_measurements()
        drift = sum(
            1 for k in self._baseline if current.get(k) != self._baseline.get(k)
        )
        drift_pct = drift / max(1, len(self._baseline))
        h = hashlib.sha256(k34._json_canon(current).encode()).hexdigest()
        self._last_hash = h
        ok = drift_pct == 0.0
        self._degraded = not ok
        self._vault.log("MBA", "REATTEST", ok=ok, drift=drift_pct)
        return AttestationResult(
            ok=ok, drift_from_baseline=drift_pct,
            measurements=current, attested_at=now_z(),
        )

    def last_attestation_hash(self) -> Optional[str]:
        return self._last_hash


# ═════════════════════════════════════════════════════════════════════
# §5 — TWO-PERSON INTEGRITY (TPI)
# ═════════════════════════════════════════════════════════════════════

class TPIScope(Enum):
    T4_ACTION = "T4_ACTION"
    POLICY_CHANGE = "POLICY_CHANGE"
    ROLLBACK = "ROLLBACK"
    EMERGENCY = "EMERGENCY"


@dataclass
class TPIChallenge:
    challenge_id: str
    scope: str
    initiator_pubkey: str
    evidence: Optional[Dict[str, Any]]
    created_at: str
    completed_by: Optional[str] = None
    completed_at: Optional[str] = None
    expired: bool = False


class TwoPersonIntegrity:
    """Enforces two-person rule for critical actions."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._challenges: Dict[str, TPIChallenge] = {}

    def initiate(self, scope: TPIScope, initiator_pubkey: str,
                 evidence: Optional[Dict[str, Any]] = None) -> TPIChallenge:
        cid = secrets.token_hex(12)
        ch = TPIChallenge(
            challenge_id=cid, scope=scope.value,
            initiator_pubkey=initiator_pubkey,
            evidence=evidence, created_at=now_z(),
        )
        self._challenges[cid] = ch
        self._vault.log("TPI", "CHALLENGE_CREATED", challenge_id=cid, scope=scope.value)
        return ch

    def complete(self, challenge_id: str, completer_pubkey: str,
                 completer_sig: str = "") -> Tuple[bool, str]:
        ch = self._challenges.get(challenge_id)
        if not ch:
            return False, "challenge_not_found"
        if ch.completed_by:
            return False, "already_completed"
        if ch.expired:
            return False, "challenge_expired"
        if completer_pubkey == ch.initiator_pubkey:
            self._vault.log("TPI", "SAME_IDENTITY_REJECTED",
                            challenge_id=challenge_id)
            return False, "same_identity"
        ch.completed_by = completer_pubkey
        ch.completed_at = now_z()
        self._vault.log("TPI", "CHALLENGE_COMPLETED",
                        challenge_id=challenge_id, completer=completer_pubkey)
        return True, "tpi_satisfied"

    def get_challenge(self, challenge_id: str) -> Optional[TPIChallenge]:
        return self._challenges.get(challenge_id)

    def is_satisfied(self, challenge_id: str) -> bool:
        ch = self._challenges.get(challenge_id)
        return ch is not None and ch.completed_by is not None


# ═════════════════════════════════════════════════════════════════════
# §6 — MULTI-KERNEL CONSENSUS (MKC)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class PeerKernel:
    kernel_id: str
    pubkey_hex: str
    endpoint: str
    policy_version: str = "1.0"
    sas_active: bool = False
    last_seal_root: str = ""
    last_seen: str = ""
    time_authority_ok: bool = True
    attestation_health: bool = True
    quarantined: bool = False
    quarantine_reason: Optional[str] = None


class MultiKernelConsensus:
    """Tracks peer kernels and provides federation consensus."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._peers: Dict[str, PeerKernel] = {}

    def register_peer(self, peer: PeerKernel):
        peer.last_seen = now_z()
        self._peers[peer.kernel_id] = peer
        self._vault.log("MKC", "PEER_REGISTERED", kernel_id=peer.kernel_id)

    def federation_health(self) -> Dict[str, Any]:
        total = len(self._peers)
        healthy = sum(1 for p in self._peers.values()
                      if not p.quarantined and not p.sas_active
                      and p.attestation_health and p.time_authority_ok)
        return {
            "total_peers": total,
            "healthy_peers": healthy,
            "quarantined": sum(1 for p in self._peers.values() if p.quarantined),
            "peers": {kid: asdict(p) for kid, p in self._peers.items()},
        }

    def verify_peer(self, kernel_id: str) -> Dict[str, Any]:
        peer = self._peers.get(kernel_id)
        if not peer:
            return {"verified": False, "reason": "peer_not_found"}
        if peer.quarantined:
            return {"verified": False, "reason": f"quarantined: {peer.quarantine_reason}"}
        if peer.sas_active:
            return {"verified": False, "reason": "sas_active"}
        if not peer.attestation_health:
            return {"verified": False, "reason": "attestation_unhealthy"}
        if not peer.time_authority_ok:
            return {"verified": False, "reason": "time_degraded"}
        return {"verified": True, "kernel_id": kernel_id, "policy_version": peer.policy_version}

    def quarantine_peer(self, kernel_id: str, reason: str):
        peer = self._peers.get(kernel_id)
        if peer:
            peer.quarantined = True
            peer.quarantine_reason = reason
            self._vault.log("MKC", "PEER_QUARANTINED",
                            kernel_id=kernel_id, reason=reason)

    def check_t4_consensus(self) -> Tuple[bool, str]:
        healthy = [p for p in self._peers.values()
                   if not p.quarantined and not p.sas_active
                   and p.attestation_health]
        if len(healthy) >= 1:
            return True, f"consensus_available: {len(healthy)} healthy peers"
        return False, "no_healthy_peers"


# ═════════════════════════════════════════════════════════════════════
# §7 — CONSTITUTIONAL ROLLBACK PROTOCOL (CRP)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class RollbackRecord:
    rollback_id: str
    reason: str
    from_policy: str
    to_policy: str
    initiator_pubkey: str
    tpi_challenge_id: str
    created_at: str
    executed: bool = False
    executed_at: Optional[str] = None


class ConstitutionalRollbackProtocol:
    """Manages constitutional rollback with TPI requirement."""

    def __init__(self, vault: k34.GuardianVaultX, tpi: TwoPersonIntegrity):
        self._vault = vault
        self._tpi = tpi
        self._records: Dict[str, RollbackRecord] = {}

    def initiate(self, reason: str, from_policy: str, to_policy: str,
                 initiator_pubkey: str) -> Tuple[str, str]:
        rid = secrets.token_hex(8)
        ch = self._tpi.initiate(TPIScope.ROLLBACK, initiator_pubkey,
                                {"reason": reason, "from": from_policy, "to": to_policy})
        rec = RollbackRecord(
            rollback_id=rid, reason=reason,
            from_policy=from_policy, to_policy=to_policy,
            initiator_pubkey=initiator_pubkey,
            tpi_challenge_id=ch.challenge_id,
            created_at=now_z(),
        )
        self._records[rid] = rec
        self._vault.log("CRP", "ROLLBACK_INITIATED", rollback_id=rid,
                        from_policy=from_policy, to_policy=to_policy)
        return rid, ch.challenge_id

    def execute(self, rollback_id: str) -> Tuple[bool, str]:
        rec = self._records.get(rollback_id)
        if not rec:
            return False, "rollback_not_found"
        if rec.executed:
            return False, "already_executed"
        if not self._tpi.is_satisfied(rec.tpi_challenge_id):
            return False, "tpi_not_satisfied"
        rec.executed = True
        rec.executed_at = now_z()
        self._vault.log("CRP", "ROLLBACK_EXECUTED", rollback_id=rollback_id,
                        to_policy=rec.to_policy)
        return True, "rollback_executed"

    def history(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._records.values()]


# ═════════════════════════════════════════════════════════════════════
# §8 — CONSTITUTIONAL LIVENESS GUARANTEES (CLG)
# ═════════════════════════════════════════════════════════════════════

class LivenessEvent(Enum):
    AUDIT_SEAL = "AUDIT_SEAL"
    HEARTBEAT = "HEARTBEAT"
    ATTESTATION = "ATTESTATION"
    FEDERATION_PING = "FEDERATION_PING"


class ConstitutionalLivenessGuarantees:
    """Tracks liveness events to ensure system responsiveness."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._events: List[Dict[str, Any]] = []

    def record_event(self, event: LivenessEvent):
        rec = {"event": event.value, "recorded_at": now_z()}
        self._events.append(rec)
        self._vault.log("CLG", "LIVENESS_EVENT", liveness_event=event.value)

    def check_all(self) -> Dict[str, Any]:
        return {
            "events": self._events,
            "total_events": len(self._events),
            "checked_at": now_z(),
        }


# ═════════════════════════════════════════════════════════════════════
# §9 — GOVERNANCE IDENTITY FEDERATION (GIF)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class FederatedIdentity:
    identity_id: str
    operator_pubkey: str
    operator_name: str
    operator_role: str
    issuing_kernel: str
    issued_at: str
    revoked: bool = False
    revoked_at: Optional[str] = None


class GovernanceIdentityFederation:
    """Issues and manages portable operator identities across kernels."""

    def __init__(self, vault: k34.GuardianVaultX, kernel_key_id: str):
        self._vault = vault
        self._kernel_key_id = kernel_key_id
        self._identities: Dict[str, FederatedIdentity] = {}
        self._revocations: List[Dict[str, Any]] = []

    def issue_portable_identity(self, rec: k34.OperatorRecord) -> FederatedIdentity:
        fid = FederatedIdentity(
            identity_id=secrets.token_hex(12),
            operator_pubkey=rec.pubkey_hex,
            operator_name=rec.name,
            operator_role=rec.role,
            issuing_kernel=self._kernel_key_id,
            issued_at=now_z(),
        )
        self._identities[fid.identity_id] = fid
        self._vault.log("GIF", "IDENTITY_ISSUED",
                        identity_id=fid.identity_id, operator=rec.name)
        return fid

    def revoke_identity(self, identity_id: str, reason: str):
        fid = self._identities.get(identity_id)
        if fid:
            fid.revoked = True
            fid.revoked_at = now_z()
            self._revocations.append({
                "identity_id": identity_id, "reason": reason,
                "revoked_at": fid.revoked_at,
            })
            self._vault.log("GIF", "IDENTITY_REVOKED",
                            identity_id=identity_id, reason=reason)

    def list_identities(self) -> List[Dict[str, Any]]:
        return [asdict(f) for f in self._identities.values()]

    def get_revocations(self) -> List[Dict[str, Any]]:
        return list(self._revocations)


# ═════════════════════════════════════════════════════════════════════
# §10 — CONSTITUTIONAL ECONOMICS LAYER (CEL)
# ═════════════════════════════════════════════════════════════════════

class RiskEventType(Enum):
    refusal = "refusal"
    sas_entry = "sas_entry"
    drift_event = "drift_event"
    override = "override"
    geofence_violation = "geofence_violation"
    integrity_failure = "integrity_failure"

# Risk units per event type
_RISK_WEIGHTS: Dict[str, float] = {
    "refusal": 5.0,
    "sas_entry": 50.0,
    "drift_event": 20.0,
    "override": 30.0,
    "geofence_violation": 25.0,
    "integrity_failure": 100.0,
}


@dataclass
class RiskCost:
    event_type: str
    risk_units: float
    operator_id: Optional[str]
    model_id: Optional[str]
    recorded_at: str


class ConstitutionalEconomicsLayer:
    """Quantifies governance risk for insurance and compliance."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._events: List[RiskCost] = []

    def record(self, event_type: RiskEventType,
               operator_id: Optional[str] = None,
               model_id: Optional[str] = None,
               details: Optional[Dict[str, Any]] = None) -> RiskCost:
        weight = _RISK_WEIGHTS.get(event_type.value, 10.0)
        cost = RiskCost(
            event_type=event_type.value, risk_units=weight,
            operator_id=operator_id, model_id=model_id,
            recorded_at=now_z(),
        )
        self._events.append(cost)
        self._vault.log("CEL", "RISK_EVENT", event_type=event_type.value,
                        risk_units=weight, operator_id=operator_id)
        return cost

    def risk_report(self) -> Dict[str, Any]:
        total = sum(e.risk_units for e in self._events)
        by_op: Dict[str, float] = {}
        by_model: Dict[str, float] = {}
        for e in self._events:
            if e.operator_id:
                by_op[e.operator_id] = by_op.get(e.operator_id, 0) + e.risk_units
            if e.model_id:
                by_model[e.model_id] = by_model.get(e.model_id, 0) + e.risk_units
        return {
            "total_risk_units": total,
            "event_count": len(self._events),
            "by_operator": by_op,
            "by_model": by_model,
            "reported_at": now_z(),
        }

    def export_events(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self._events]


# ═════════════════════════════════════════════════════════════════════
# §11 — CONSTITUTIONAL SIMULATION MODE (CSM)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class SimResult:
    scenario: str
    scope: str
    nonce: str
    outcome: str
    side_effects: List[str]
    simulated_at: str


class ConstitutionalSimulationMode:
    """Side-effect-free simulation of governance decisions."""

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._history: List[SimResult] = []

    def simulate_authorize(self, scope: k34.ActionScope, nonce: str,
                           scenario: str = "default",
                           model_ctx: Optional[k34.ModelContext] = None) -> SimResult:
        tier = k34.SCOPE_TIER_MAP[scope]
        outcome = "ALLOW"
        if tier.value >= k34.ActionTier.T3_INTERVENTION.value and model_ctx is None:
            outcome = "DENY"
        result = SimResult(
            scenario=scenario, scope=scope.value, nonce=nonce,
            outcome=outcome, side_effects=[], simulated_at=now_z(),
        )
        self._history.append(result)
        self._vault.log("CSM", "SIM_AUTHORIZE", scope=scope.value,
                        scenario=scenario, outcome=outcome)
        return result

    def simulate_sas(self, reason: str = "drill") -> SimResult:
        result = SimResult(
            scenario=f"sas_drill:{reason}", scope="sas", nonce="",
            outcome="SAS", side_effects=[], simulated_at=now_z(),
        )
        self._history.append(result)
        self._vault.log("CSM", "SIM_SAS", reason=reason)
        return result

    def simulate_policy_migration(self, from_version: str,
                                  to_version: str) -> SimResult:
        result = SimResult(
            scenario=f"policy_migration:{from_version}->{to_version}",
            scope="policy", nonce="",
            outcome="ALLOW", side_effects=[], simulated_at=now_z(),
        )
        self._history.append(result)
        self._vault.log("CSM", "SIM_POLICY_MIGRATION",
                        from_version=from_version, to_version=to_version)
        return result

    def history(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._history]


# ═════════════════════════════════════════════════════════════════════
# §12 — GOVERNANCE FORENSICS ENGINE (GFE)
# ═════════════════════════════════════════════════════════════════════

class GovernanceForensicsEngine:
    """Analyses vault entries for forensic intelligence."""

    def __init__(self, vault: k34.GuardianVaultX, gov: k34.Governor):
        self._vault = vault
        self._gov = gov

    def timeline_replay(self, start: Optional[str] = None,
                        end: Optional[str] = None,
                        stream: Optional[str] = None) -> List[Dict[str, Any]]:
        entries = self._vault.export()
        if stream:
            entries = [e for e in entries if e.get("stream") == stream]
        if start:
            entries = [e for e in entries if e.get("ts", "") >= start]
        if end:
            entries = [e for e in entries if e.get("ts", "") <= end]
        return entries

    def operator_behavior_clustering(self) -> Dict[str, Any]:
        entries = self._vault.export()
        ops: Dict[str, List[str]] = {}
        for e in entries:
            d = e.get("details", {})
            op = d.get("issuer") or d.get("operator") or d.get("name")
            if op:
                ops.setdefault(op, []).append(e.get("event", ""))
        low_risk = []
        elevated = []
        for op, events in ops.items():
            refusals = sum(1 for ev in events if "REFUS" in ev.upper()
                          or "DENIED" in ev.upper() or "REJECTED" in ev.upper())
            if refusals > 2:
                elevated.append(op)
            else:
                low_risk.append(op)
        return {"low_risk": low_risk, "elevated": elevated, "total_operators": len(ops)}

    def drift_pattern_analysis(self) -> List[Dict[str, Any]]:
        entries = self._vault.export()
        drifts = [e for e in entries
                  if "drift" in str(e.get("details", {})).lower()
                  or "REATTEST" in e.get("event", "")]
        return drifts

    def sas_root_cause(self) -> List[Dict[str, Any]]:
        entries = self._vault.export()
        sas_events = [e for e in entries
                      if "SAS" in e.get("event", "")
                      or e.get("stream") == "KERNEL" and "PANIC" in e.get("event", "")]
        return sas_events

    def anomaly_correlation(self) -> Dict[str, Any]:
        entries = self._vault.export()
        streams: Dict[str, int] = {}
        for e in entries:
            s = e.get("stream", "unknown")
            streams[s] = streams.get(s, 0) + 1
        return {
            "total_entries": len(entries),
            "by_stream": streams,
            "analyzed_at": now_z(),
        }

    def export_signed_report(self) -> Dict[str, Any]:
        report = {
            "schema": SCHEMA_VERSION,
            "kind": "FORENSICS_REPORT",
            "generated_at": now_z(),
            "timeline_entries": len(self._vault.export()),
            "clustering": self.operator_behavior_clustering(),
            "drift_events": len(self.drift_pattern_analysis()),
            "sas_events": len(self.sas_root_cause()),
            "anomalies": self.anomaly_correlation(),
        }
        payload = k34._json_canon(report).encode()
        sig = self._gov._km.sign_hex(payload)
        report["signature"] = sig
        return report


# ═════════════════════════════════════════════════════════════════════
# §13 — CONSTITUTIONAL EXPORT FORMAT (CEF)
# ═════════════════════════════════════════════════════════════════════

class ConstitutionalExportFormat:
    """Produces a full constitutional snapshot for audit / compliance."""

    def __init__(self, kernel: "WhiteSwanKernel35"):
        self._kernel = kernel

    def export(self) -> Dict[str, Any]:
        ker = self._kernel
        gov = ker.gov
        health = gov.governance_health()
        mba_data = ker.mba.export()

        cef = {
            "kind": "CONSTITUTIONAL_EXPORT_FORMAT",
            "schema": SCHEMA_VERSION,
            "exported_at": now_z(),
            "kernel": {
                "key_id": gov.kernel_key_id,
                "pubkey_hex": gov.kernel_pubkey_hex,
                "policy_version": gov._policy_version,
                "attestation": mba_data,
            },
            "policy_history": gov.policy_history(),
            "operators": gov.list_operators(),
            "audit_seals": ker.vault.export_seals(),
            "vault_chain_ok": ker.vault.verify_chain(),
            "risk_metrics": ker.cel.risk_report() if hasattr(ker, "cel") else {},
            "federation": ker.mkc.federation_health() if hasattr(ker, "mkc") else {},
            "hsm_manifest": ker.hsm.export_manifest(),
            "rollback_history": ker.crp.history() if hasattr(ker, "crp") else [],
            "simulation_history": ker.csm.history() if hasattr(ker, "csm") else [],
            "federated_identities": ker.gif.list_identities() if hasattr(ker, "gif") else [],
            "liveness": ker.clg.check_all() if hasattr(ker, "clg") else {},
            "forensics_summary": {
                "timeline_entries": len(ker.vault.export()),
                "drift_events": len(ker.gfe.drift_pattern_analysis()) if hasattr(ker, "gfe") else 0,
            },
            "compliance_targets": ["NIST_RMF", "EU_AI_ACT", "SOC2"],
        }

        # Sign the CEF
        payload = k34._json_canon(cef).encode()
        cef["cef_hash"] = hashlib.sha256(payload).hexdigest()
        cef["cef_signature"] = gov._km.sign_hex(payload)

        return cef


# ═════════════════════════════════════════════════════════════════════
# UNIFIED KERNEL ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════

class WhiteSwanKernel35:
    """Top-level kernel orchestrator.

    Wraps the v3.4 Governor and instantiates all 11 v3.5 subsystems.
    The API layer guards access via _require_attr / hasattr().
    """

    def __init__(
        self,
        db_file: str = ":memory:",
        key_file: str = ".ws35_key",
        seal_interval: int = 100,
    ):
        self.vault = k34.GuardianVaultX(seal_interval=seal_interval)
        self.gov = k34.Governor(
            self.vault, db_file=db_file, key_file=key_file,
        )
        self.mgi = k34.MGI(self.gov)

        # §3  HSM Key Custody
        self.hsm = HSMKeyCustody(self.vault)
        # §4  Measured Boot & Attestation
        self.mba = MeasuredBootAttestation(self.vault, self.gov)
        # §5  Two-Person Integrity
        self.tpi = TwoPersonIntegrity(self.vault)
        # §6  Multi-Kernel Consensus
        self.mkc = MultiKernelConsensus(self.vault)
        # §7  Constitutional Rollback Protocol (requires TPI)
        self.crp = ConstitutionalRollbackProtocol(self.vault, self.tpi)
        # §8  Constitutional Liveness Guarantees
        self.clg = ConstitutionalLivenessGuarantees(self.vault)
        # §9  Governance Identity Federation
        self.gif = GovernanceIdentityFederation(self.vault, self.gov.kernel_key_id)
        # §10 Constitutional Economics Layer
        self.cel = ConstitutionalEconomicsLayer(self.vault)
        # §11 Constitutional Simulation Mode
        self.csm = ConstitutionalSimulationMode(self.vault)
        # §12 Governance Forensics Engine
        self.gfe = GovernanceForensicsEngine(self.vault, self.gov)
        # §13 Constitutional Export Format (last — needs references to all others)
        self.cef = ConstitutionalExportFormat(self)

        self.vault.log("KERNEL", "V35_READY", schema=SCHEMA_VERSION)

    # ── Aggregate health ─────────────────────────────────────────────

    def full_health(self) -> Dict[str, Any]:
        health = self.gov.governance_health()
        health["schema"] = SCHEMA_VERSION
        health["hsm"] = self.hsm.export_manifest()
        health["boot_attestation"] = self.mba.export()
        health["federation"] = self.mkc.federation_health()
        health["liveness"] = self.clg.check_all()
        return health

    # ── Constitutional invariant checks ──────────────────────────────

    def check_invariants(self) -> Dict[str, Any]:
        checks = {
            "db_integrity": self.gov.db.integrity_check(),
            "vault_chain": self.vault.verify_chain(),
            "kernel_key_present": bool(self.gov.kernel_key_id),
            "time_authority": self.gov.time.health().ok,
            "boot_attestation_ok": self.mba.attest().ok,
            "hsm_slots_initialized": len(self.hsm._slots) >= 4,
        }
        checks["all_invariants_hold"] = all(checks.values())
        return checks

    # ── Lifecycle ────────────────────────────────────────────────────

    def close(self):
        self.gov.close()
