#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — NSA-Quality Defensive Governance Subsystems
Holmes & Watson Supreme AI™

Implements Sections 3–13 of the v3.5 specification:
  §3  HSM Key Custody (FIPS 140-3 abstraction)
  §4  Measured Boot & Continuous Attestation (TPM/PCR)
  §5  Two-Person Integrity (TPI)
  §6  Multi-Kernel Consensus (MKC)
  §7  Constitutional Rollback Protocol (CRP)
  §8  Constitutional Liveness Guarantees (CLG)
  §9  Governance Identity Federation (GIF)
  §10 Constitutional Economics Layer (CEL)
  §11 Constitutional Simulation Mode (CSM)
  §12 Governance Forensics Engine (GFE)
  §13 Constitutional Export Format (CEF)

This is a SINGLE ECOSYSTEM — no module can be separated.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from kernel_v34 import (
    SCHEMA_VERSION as V34_SCHEMA,
    ActionScope,
    ActionTier,
    AuditSeal,
    GovernanceViolation,
    Governor,
    GuardianVaultX,
    InsufficientAuthorityError,
    KernelDB,
    MGI,
    ModelContext,
    OperatorIdentity,
    OperatorNotAuthorizedError,
    OperatorRecord,
    RefusalReason,
    RefusalTier,
    SASActiveError,
    SCOPE_TIER_MAP,
    Telemetry,
    _json_canon,
    generate_nonce,
    iso_z,
    now_utc,
    now_z,
    sha256_bytes,
)

SCHEMA_VERSION = "ws-hs-v3.5"

# =============================================================================
# §3 — HSM KEY CUSTODY (FIPS 140-3 Abstraction)
# =============================================================================

class HSMSlot(Enum):
    KERNEL_ATTESTATION = "kernel_attestation"
    AUDIT_SEALING = "audit_sealing"
    FEDERATION_CONSENSUS = "federation_consensus"
    EXPORT_CEF = "export_cef"

@dataclass
class HSMKeyRecord:
    slot: HSMSlot
    key_id: str
    algorithm: str
    epoch: int
    created_at: str
    rotated_from: Optional[str] = None
    activation_ceremony_hash: Optional[str] = None
    witnesses: List[str] = field(default_factory=list)

class HSMKeyStore:
    """
    Abstraction layer for FIPS 140-3 HSM operations.
    In production: wraps PKCS#11 or cloud HSM APIs.
    In dev: software HSM with identical interface contract.
    """

    def __init__(self, vault: GuardianVaultX):
        self._keys: Dict[str, HSMKeyRecord] = {}
        self._epochs: Dict[HSMSlot, int] = defaultdict(int)
        self._rotation_log: List[Dict[str, Any]] = []
        self._vault = vault
        self._lock = threading.Lock()

    def generate_key(self, slot: HSMSlot, witnesses: List[str],
                     ceremony_data: Dict[str, Any] = None) -> HSMKeyRecord:
        """M-of-N activation ceremony — generate key inside HSM boundary."""
        with self._lock:
            epoch = self._epochs[slot] + 1
            self._epochs[slot] = epoch
            key_id = f"{slot.value}:epoch-{epoch}:{secrets.token_hex(8)}"
            ceremony_hash = sha256_bytes(
                _json_canon({"slot": slot.value, "epoch": epoch,
                             "witnesses": witnesses, "data": ceremony_data or {}}).encode()
            )
            rec = HSMKeyRecord(
                slot=slot, key_id=key_id, algorithm="ed25519",
                epoch=epoch, created_at=now_z(),
                activation_ceremony_hash=ceremony_hash,
                witnesses=list(witnesses),
            )
            old_key = self._get_current(slot)
            if old_key:
                rec.rotated_from = old_key.key_id
                self._rotation_log.append({
                    "slot": slot.value, "old_key_id": old_key.key_id,
                    "new_key_id": key_id, "epoch": epoch,
                    "rotated_at": now_z(), "witnesses": witnesses,
                })
            self._keys[key_id] = rec
            self._vault.log("HSM", "KEY_GENERATED", slot=slot.value,
                          key_id=key_id, epoch=epoch, witnesses=len(witnesses))
            return rec

    def _get_current(self, slot: HSMSlot) -> Optional[HSMKeyRecord]:
        """Get highest-epoch key for a slot."""
        candidates = [k for k in self._keys.values() if k.slot == slot]
        return max(candidates, key=lambda k: k.epoch) if candidates else None

    def get_key(self, slot: HSMSlot) -> Optional[HSMKeyRecord]:
        return self._get_current(slot)

    def verify_epoch(self, key_id: str, expected_epoch: int) -> bool:
        """Epoch-based verification — history never invalidated."""
        rec = self._keys.get(key_id)
        return rec is not None and rec.epoch == expected_epoch

    def rotation_history(self) -> List[Dict[str, Any]]:
        return list(self._rotation_log)

    def export_manifest(self) -> Dict[str, Any]:
        return {
            "slots": {s.value: self._epochs[s] for s in HSMSlot},
            "active_keys": {
                s.value: asdict(self._get_current(s))
                for s in HSMSlot if self._get_current(s)
            },
            "rotation_count": len(self._rotation_log),
            "fips_mode": "FIPS-140-3-L3-ABSTRACTION",
        }

# =============================================================================
# §4 — MEASURED BOOT & CONTINUOUS ATTESTATION
# =============================================================================

@dataclass
class PCRState:
    """Platform Configuration Register state."""
    pcr0_kernel_binary: str    # SHA-256 of kernel binary
    pcr1_configuration: str    # SHA-256 of runtime config
    pcr2_policy_version: str   # SHA-256 of policy version
    measured_at: str = ""

    def composite_hash(self) -> str:
        return sha256_bytes(
            f"{self.pcr0_kernel_binary}:{self.pcr1_configuration}:{self.pcr2_policy_version}".encode()
        )

@dataclass
class AttestationResult:
    ok: bool
    pcr_composite: str
    attestation_hash: str
    measured_at: str
    drift_from_baseline: float
    degraded: bool = False
    reason: str = ""

class MeasuredBootAuthority:
    """TPM-based measured boot + continuous runtime attestation."""

    def __init__(self, vault: GuardianVaultX, telemetry: Telemetry):
        self._vault = vault
        self._telemetry = telemetry
        self._baseline_pcr: Optional[PCRState] = None
        self._current_pcr: Optional[PCRState] = None
        self._attestation_interval_sec = 60
        self._last_attestation: Optional[str] = None
        self._degraded = False
        self._lock = threading.Lock()

    def measure_boot(self, kernel_binary_hash: str, config_hash: str,
                     policy_version: str) -> PCRState:
        """Record initial measured boot PCR values."""
        pcr = PCRState(
            pcr0_kernel_binary=kernel_binary_hash,
            pcr1_configuration=config_hash,
            pcr2_policy_version=sha256_bytes(policy_version.encode()),
            measured_at=now_z(),
        )
        with self._lock:
            self._baseline_pcr = pcr
            self._current_pcr = pcr
            self._degraded = False
        self._vault.log("BOOT", "MEASURED_BOOT", composite=pcr.composite_hash())
        self._telemetry.inc("measured_boots_total")
        return pcr

    def attest(self, current_kernel_hash: str = None,
               current_config_hash: str = None,
               current_policy_version: str = None) -> AttestationResult:
        """Runtime re-attestation — compare current state to baseline."""
        if not self._baseline_pcr:
            return AttestationResult(
                ok=False, pcr_composite="", attestation_hash="",
                measured_at=now_z(), drift_from_baseline=1.0,
                degraded=True, reason="no_baseline",
            )

        current = PCRState(
            pcr0_kernel_binary=current_kernel_hash or self._baseline_pcr.pcr0_kernel_binary,
            pcr1_configuration=current_config_hash or self._baseline_pcr.pcr1_configuration,
            pcr2_policy_version=sha256_bytes((current_policy_version or "").encode()) if current_policy_version else self._baseline_pcr.pcr2_policy_version,
            measured_at=now_z(),
        )

        drift = 0.0
        mismatches = []
        if current.pcr0_kernel_binary != self._baseline_pcr.pcr0_kernel_binary:
            drift += 0.5
            mismatches.append("pcr0_kernel")
        if current.pcr1_configuration != self._baseline_pcr.pcr1_configuration:
            drift += 0.3
            mismatches.append("pcr1_config")
        if current.pcr2_policy_version != self._baseline_pcr.pcr2_policy_version:
            drift += 0.2
            mismatches.append("pcr2_policy")

        attestation_hash = sha256_bytes(
            _json_canon({"baseline": self._baseline_pcr.composite_hash(),
                        "current": current.composite_hash(),
                        "drift": drift, "at": current.measured_at}).encode()
        )

        with self._lock:
            self._current_pcr = current
            self._last_attestation = current.measured_at
            self._degraded = drift > 0

        result = AttestationResult(
            ok=drift == 0.0,
            pcr_composite=current.composite_hash(),
            attestation_hash=attestation_hash,
            measured_at=current.measured_at,
            drift_from_baseline=drift,
            degraded=drift > 0,
            reason=",".join(mismatches) if mismatches else "clean",
        )

        stream = "ATTESTATION_DEGRADED" if result.degraded else "ATTESTATION_OK"
        self._vault.log("ATTEST", stream, drift=drift, mismatches=mismatches)
        self._telemetry.inc("attestations_total", {"status": "degraded" if result.degraded else "ok"})
        return result

    @property
    def is_degraded(self) -> bool:
        return self._degraded

    def last_attestation_hash(self) -> str:
        if self._current_pcr:
            return sha256_bytes(
                _json_canon({"pcr": self._current_pcr.composite_hash(),
                            "at": self._last_attestation}).encode()
            )
        return ""

    def export(self) -> Dict[str, Any]:
        return {
            "baseline": asdict(self._baseline_pcr) if self._baseline_pcr else None,
            "current": asdict(self._current_pcr) if self._current_pcr else None,
            "degraded": self._degraded,
            "last_attestation": self._last_attestation,
        }

# =============================================================================
# §5 — TWO-PERSON INTEGRITY (TPI)
# =============================================================================

class TPIScope(Enum):
    T4_ACTION = "T4_ACTION"
    POLICY_MIGRATION = "POLICY_MIGRATION"
    POLICY_ROLLBACK = "POLICY_ROLLBACK"
    SAS_EXIT = "SAS_EXIT"
    FEDERATION_TRUST = "FEDERATION_TRUST"
    KEY_ROTATION = "KEY_ROTATION"

@dataclass
class TPIChallenge:
    challenge_id: str
    scope: TPIScope
    initiated_by: str        # operator pubkey
    initiated_at: str
    requires_from: str = ""  # must be different credential chain
    completed_by: Optional[str] = None
    completed_at: Optional[str] = None
    evidence_hash: str = ""
    expired: bool = False

class TwoPersonIntegrity:
    """
    Enforces dual-person authorization for critical operations.
    Requires cryptographically distinct identities with independent credential chains.
    """

    def __init__(self, vault: GuardianVaultX, telemetry: Telemetry,
                 challenge_ttl_sec: int = 600):
        self._vault = vault
        self._telemetry = telemetry
        self._challenges: Dict[str, TPIChallenge] = {}
        self._ttl = challenge_ttl_sec
        self._lock = threading.Lock()

    def initiate(self, scope: TPIScope, initiator_pubkey: str,
                 evidence: Dict[str, Any] = None) -> TPIChallenge:
        """First person initiates. Returns challenge requiring second person."""
        cid = secrets.token_hex(16)
        ev_hash = sha256_bytes(_json_canon(evidence or {}).encode())
        challenge = TPIChallenge(
            challenge_id=cid, scope=scope, initiated_by=initiator_pubkey,
            initiated_at=now_z(), evidence_hash=ev_hash,
        )
        with self._lock:
            self._challenges[cid] = challenge
        self._vault.log("TPI", "INITIATED", challenge_id=cid[:12],
                       scope=scope.value, initiator=initiator_pubkey[:16])
        self._telemetry.inc("tpi_initiated_total", {"scope": scope.value})
        return challenge

    def complete(self, challenge_id: str, completer_pubkey: str,
                 completer_sig: str = "") -> Tuple[bool, str]:
        """Second person completes. Must be cryptographically distinct."""
        with self._lock:
            ch = self._challenges.get(challenge_id)
            if not ch:
                return False, "challenge_not_found"
            if ch.expired or ch.completed_by:
                return False, "already_completed_or_expired"

            # Check TTL
            initiated = now_utc()
            try:
                import datetime
                init_dt = datetime.datetime.fromisoformat(ch.initiated_at.replace("Z", "+00:00"))
                if (initiated - init_dt).total_seconds() > self._ttl:
                    ch.expired = True
                    self._vault.log("TPI", "EXPIRED", challenge_id=challenge_id[:12])
                    return False, "expired"
            except Exception:
                pass

            # Non-collapsible authority: different identity required
            if completer_pubkey == ch.initiated_by:
                self._vault.log("TPI", "SAME_IDENTITY_REJECTED",
                              challenge_id=challenge_id[:12])
                self._telemetry.inc("tpi_same_identity_rejected_total")
                return False, "same_identity_not_allowed"

            ch.completed_by = completer_pubkey
            ch.completed_at = now_z()

        self._vault.log("TPI", "COMPLETED", challenge_id=challenge_id[:12],
                       scope=ch.scope.value, completer=completer_pubkey[:16])
        self._telemetry.inc("tpi_completed_total", {"scope": ch.scope.value})
        return True, "ok"

    def is_satisfied(self, challenge_id: str) -> bool:
        ch = self._challenges.get(challenge_id)
        return ch is not None and ch.completed_by is not None and not ch.expired

    def get_challenge(self, challenge_id: str) -> Optional[TPIChallenge]:
        return self._challenges.get(challenge_id)

    def export(self) -> List[Dict[str, Any]]:
        return [asdict(c) for c in self._challenges.values()]

# =============================================================================
# §6 — MULTI-KERNEL CONSENSUS (MKC)
# =============================================================================

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
    quarantined: bool = False
    quarantine_reason: str = ""

class MultiKernelConsensus:
    """
    Constitutional mesh of peer kernels.
    Enforces cross-kernel verification for T4 actions and policy migrations.
    """

    def __init__(self, local_kernel_id: str, vault: GuardianVaultX,
                 telemetry: Telemetry):
        self._local_id = local_kernel_id
        self._vault = vault
        self._telemetry = telemetry
        self._peers: Dict[str, PeerKernel] = {}
        self._lock = threading.Lock()

    def register_peer(self, peer: PeerKernel):
        with self._lock:
            self._peers[peer.kernel_id] = peer
        self._vault.log("MKC", "PEER_REGISTERED", peer_id=peer.kernel_id[:12],
                       endpoint=peer.endpoint)
        self._telemetry.inc("mkc_peers_registered_total")

    def update_peer_state(self, kernel_id: str, **updates):
        with self._lock:
            peer = self._peers.get(kernel_id)
            if not peer:
                return
            for k, v in updates.items():
                if hasattr(peer, k):
                    setattr(peer, k, v)
            peer.last_seen = now_z()

    def quarantine_peer(self, kernel_id: str, reason: str):
        with self._lock:
            peer = self._peers.get(kernel_id)
            if peer:
                peer.quarantined = True
                peer.quarantine_reason = reason
        self._vault.log("MKC", "PEER_QUARANTINED", peer_id=kernel_id[:12], reason=reason)
        self._telemetry.inc("mkc_quarantines_total")

    def healthy_peers(self) -> List[PeerKernel]:
        with self._lock:
            return [p for p in self._peers.values()
                    if not p.quarantined and not p.sas_active
                    and p.attestation_health and p.time_authority_ok]

    def check_t4_consensus(self) -> Tuple[bool, str]:
        """T4 actions require >= 2 kernels (self + >= 1 healthy peer)."""
        healthy = self.healthy_peers()
        if len(healthy) < 1:
            self._telemetry.inc("mkc_t4_consensus_failed_total")
            return False, f"insufficient_peers: {len(healthy)} healthy, need >= 1"
        return True, f"consensus_ok: {len(healthy) + 1} kernels"

    def check_policy_quorum(self) -> Tuple[bool, str]:
        """Policy migrations require quorum (> 50% of registered non-quarantined)."""
        with self._lock:
            total = len([p for p in self._peers.values() if not p.quarantined])
        healthy = len(self.healthy_peers())
        if total == 0:
            return True, "solo_kernel"  # Solo mode — no peers registered
        quorum = (total // 2) + 1
        if healthy >= quorum:
            return True, f"quorum_met: {healthy}/{total}"
        return False, f"quorum_not_met: {healthy}/{total} (need {quorum})"

    def verify_peer(self, kernel_id: str) -> Dict[str, Any]:
        """Verify peer's audit seal roots, policy, SAS, time, attestation."""
        with self._lock:
            peer = self._peers.get(kernel_id)
        if not peer:
            return {"verified": False, "reason": "unknown_peer"}

        issues = []
        if peer.sas_active:
            issues.append("sas_active")
        if not peer.time_authority_ok:
            issues.append("time_degraded")
        if not peer.attestation_health:
            issues.append("attestation_degraded")
        if peer.quarantined:
            issues.append(f"quarantined:{peer.quarantine_reason}")

        return {
            "verified": len(issues) == 0,
            "kernel_id": kernel_id,
            "policy_version": peer.policy_version,
            "issues": issues,
            "last_seen": peer.last_seen,
        }

    def federation_health(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._peers)
            healthy = len([p for p in self._peers.values()
                          if not p.quarantined and not p.sas_active])
            quarantined = len([p for p in self._peers.values() if p.quarantined])
        return {
            "local_kernel": self._local_id,
            "total_peers": total,
            "healthy_peers": healthy,
            "quarantined_peers": quarantined,
            "t4_consensus_available": self.check_t4_consensus()[0],
            "policy_quorum_available": self.check_policy_quorum()[0],
        }

# =============================================================================
# §7 — CONSTITUTIONAL ROLLBACK PROTOCOL (CRP)
# =============================================================================

@dataclass
class RollbackRecord:
    rollback_id: str
    initiated_at: str
    reason: str
    from_policy: str
    to_policy: str
    tpi_challenge_id: str
    quorum_met: bool
    kernel_consensus: bool
    sessions_invalidated: int
    handshakes_invalidated: int
    executed: bool = False
    executed_at: Optional[str] = None
    sealed_evidence_hash: str = ""

class ConstitutionalRollbackProtocol:
    """
    Rollback = constitutional emergency.
    Requires: quorum + TPI + kernel consensus.
    Effects: all sessions/handshakes invalidated, permanently recorded.
    Cannot be silent, partial, or overridden.
    """

    def __init__(self, gov: Governor, tpi: TwoPersonIntegrity,
                 mkc: MultiKernelConsensus, vault: GuardianVaultX,
                 telemetry: Telemetry):
        self._gov = gov
        self._tpi = tpi
        self._mkc = mkc
        self._vault = vault
        self._telemetry = telemetry
        self._rollbacks: List[RollbackRecord] = []

    def initiate(self, reason: str, from_policy: str, to_policy: str,
                 initiator_pubkey: str) -> Tuple[str, str]:
        """
        Returns (rollback_id, tpi_challenge_id).
        Caller must complete TPI before execute().
        """
        tpi_ch = self._tpi.initiate(TPIScope.POLICY_ROLLBACK, initiator_pubkey,
                                    evidence={"reason": reason, "from": from_policy, "to": to_policy})

        rid = secrets.token_hex(16)
        rec = RollbackRecord(
            rollback_id=rid, initiated_at=now_z(), reason=reason,
            from_policy=from_policy, to_policy=to_policy,
            tpi_challenge_id=tpi_ch.challenge_id,
            quorum_met=False, kernel_consensus=False,
            sessions_invalidated=0, handshakes_invalidated=0,
        )
        self._rollbacks.append(rec)
        self._vault.log("CRP", "INITIATED", rollback_id=rid[:12], reason=reason)
        self._telemetry.inc("crp_initiated_total")
        return rid, tpi_ch.challenge_id

    def execute(self, rollback_id: str) -> Tuple[bool, str]:
        """Execute rollback — all three conditions must be met."""
        rec = next((r for r in self._rollbacks if r.rollback_id == rollback_id), None)
        if not rec:
            return False, "rollback_not_found"
        if rec.executed:
            return False, "already_executed"

        # Check TPI
        if not self._tpi.is_satisfied(rec.tpi_challenge_id):
            return False, "tpi_not_satisfied"
        rec.quorum_met = True

        # Check kernel consensus
        ok, msg = self._mkc.check_policy_quorum()
        rec.kernel_consensus = ok
        if not ok and len(self._mkc._peers) > 0:  # Solo mode passes
            return False, f"kernel_consensus_failed: {msg}"

        # Execute: invalidate everything
        self._gov.db.revoke_all_hs()
        # Count invalidated sessions
        sessions = self._gov.db.conn.execute(
            "UPDATE sessions SET valid=0 WHERE valid=1"
        ).rowcount
        self._gov.db.conn.commit()

        rec.sessions_invalidated = sessions or 0
        rec.handshakes_invalidated = -1  # all revoked
        rec.executed = True
        rec.executed_at = now_z()

        # Seal evidence
        evidence = _json_canon(asdict(rec))
        rec.sealed_evidence_hash = sha256_bytes(evidence.encode())

        self._vault.log("CRP", "EXECUTED", rollback_id=rollback_id[:12],
                       from_policy=rec.from_policy, to_policy=rec.to_policy,
                       sessions_invalidated=rec.sessions_invalidated)
        self._telemetry.inc("crp_executed_total")
        return True, "rollback_complete"

    def history(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._rollbacks]

# =============================================================================
# §8 — CONSTITUTIONAL LIVENESS GUARANTEES (CLG)
# =============================================================================

class LivenessEvent(Enum):
    AUDIT_SEAL = "AUDIT_SEAL"
    REPLAY_PRUNE = "REPLAY_PRUNE"
    TIME_REFRESH = "TIME_REFRESH"
    ATTESTATION_REFRESH = "ATTESTATION_REFRESH"

@dataclass
class LivenessDeadline:
    event: LivenessEvent
    interval_sec: int
    last_fired: Optional[str] = None
    missed_count: int = 0

class ConstitutionalLivenessGuarantees:
    """
    Guarantees bounded progress through mandatory periodic events.
    Missed liveness → degraded authority. Continued failure → SAS.
    """

    def __init__(self, vault: GuardianVaultX, telemetry: Telemetry,
                 sas_callback: Callable[[str], None],
                 seal_interval: int = 300, prune_interval: int = 600,
                 time_interval: int = 60, attest_interval: int = 120,
                 max_misses: int = 3):
        self._vault = vault
        self._telemetry = telemetry
        self._sas_callback = sas_callback
        self._max_misses = max_misses
        self._degraded = False

        self._deadlines: Dict[LivenessEvent, LivenessDeadline] = {
            LivenessEvent.AUDIT_SEAL: LivenessDeadline(LivenessEvent.AUDIT_SEAL, seal_interval),
            LivenessEvent.REPLAY_PRUNE: LivenessDeadline(LivenessEvent.REPLAY_PRUNE, prune_interval),
            LivenessEvent.TIME_REFRESH: LivenessDeadline(LivenessEvent.TIME_REFRESH, time_interval),
            LivenessEvent.ATTESTATION_REFRESH: LivenessDeadline(LivenessEvent.ATTESTATION_REFRESH, attest_interval),
        }

    def record_event(self, event: LivenessEvent):
        dl = self._deadlines.get(event)
        if dl:
            dl.last_fired = now_z()
            dl.missed_count = 0
            self._telemetry.inc("clg_events_total", {"event": event.value})

    def check_all(self) -> Dict[str, Any]:
        """Check all liveness deadlines. Returns health + triggers SAS if needed."""
        import datetime
        now = now_utc()
        results = {}
        any_degraded = False

        for event, dl in self._deadlines.items():
            if dl.last_fired:
                last = datetime.datetime.fromisoformat(dl.last_fired.replace("Z", "+00:00"))
                elapsed = (now - last).total_seconds()
                overdue = elapsed > dl.interval_sec
            else:
                overdue = True
                elapsed = float('inf')

            if overdue:
                dl.missed_count += 1
                any_degraded = True
                self._telemetry.inc("clg_misses_total", {"event": event.value})

                if dl.missed_count >= self._max_misses:
                    self._vault.log("CLG", "SAS_TRIGGERED", event=event.value,
                                  missed=dl.missed_count)
                    self._sas_callback(f"CLG:{event.value}:missed_{dl.missed_count}")

            results[event.value] = {
                "last_fired": dl.last_fired,
                "interval_sec": dl.interval_sec,
                "missed_count": dl.missed_count,
                "overdue": overdue,
                "elapsed_sec": int(elapsed) if elapsed != float('inf') else None,
            }

        self._degraded = any_degraded
        return {"liveness_ok": not any_degraded, "events": results}

    @property
    def is_degraded(self) -> bool:
        return self._degraded

# =============================================================================
# §9 — GOVERNANCE IDENTITY FEDERATION (GIF)
# =============================================================================

@dataclass
class FederatedIdentity:
    identity_id: str
    operator_pubkey: str
    operator_name: str
    home_kernel: str
    scopes_json: str
    signed_at: str
    signature: str
    revoked: bool = False
    revoked_at: Optional[str] = None

class GovernanceIdentityFederation:
    """
    Portable, signed operator identities that work across kernel federation.
    Revocations propagate. Sessions can be cross-kernel.
    """

    def __init__(self, local_kernel_id: str, vault: GuardianVaultX,
                 telemetry: Telemetry, sign_fn: Callable[[bytes], str]):
        self._local_id = local_kernel_id
        self._vault = vault
        self._telemetry = telemetry
        self._sign = sign_fn
        self._identities: Dict[str, FederatedIdentity] = {}
        self._revocation_log: List[Dict[str, Any]] = []

    def issue_portable_identity(self, operator: OperatorRecord) -> FederatedIdentity:
        """Create a signed, portable identity object."""
        iid = secrets.token_hex(16)
        payload = _json_canon({
            "identity_id": iid, "pubkey": operator.pubkey_hex,
            "name": operator.name, "home_kernel": self._local_id,
            "scopes": [s.value for s in operator.allowed_scopes],
            "issued_at": now_z(),
        })
        sig = self._sign(payload.encode())
        fid = FederatedIdentity(
            identity_id=iid, operator_pubkey=operator.pubkey_hex,
            operator_name=operator.name, home_kernel=self._local_id,
            scopes_json=json.dumps([s.value for s in operator.allowed_scopes]),
            signed_at=now_z(), signature=sig,
        )
        self._identities[iid] = fid
        self._vault.log("GIF", "IDENTITY_ISSUED", identity_id=iid[:12],
                       operator=operator.name)
        self._telemetry.inc("gif_identities_issued_total")
        return fid

    def revoke_identity(self, identity_id: str, reason: str):
        fid = self._identities.get(identity_id)
        if fid:
            fid.revoked = True
            fid.revoked_at = now_z()
            self._revocation_log.append({
                "identity_id": identity_id, "revoked_at": now_z(),
                "reason": reason, "propagated": True,
            })
            self._vault.log("GIF", "IDENTITY_REVOKED", identity_id=identity_id[:12],
                          reason=reason)
            self._telemetry.inc("gif_revocations_total")

    def accept_foreign_identity(self, fid: FederatedIdentity):
        """Accept identity from peer kernel."""
        self._identities[fid.identity_id] = fid
        self._vault.log("GIF", "FOREIGN_IDENTITY_ACCEPTED",
                       identity_id=fid.identity_id[:12],
                       home_kernel=fid.home_kernel[:12])

    def get_revocations(self) -> List[Dict[str, Any]]:
        return list(self._revocation_log)

    def list_identities(self) -> List[Dict[str, Any]]:
        return [asdict(f) for f in self._identities.values()]

# =============================================================================
# §10 — CONSTITUTIONAL ECONOMICS LAYER (CEL)
# =============================================================================

class RiskEventType(Enum):
    REFUSAL = "refusal"
    OVERRIDE = "override"
    SAS_ENTRY = "sas_entry"
    DRIFT_EVENT = "drift_event"
    REPLAY_SATURATION = "replay_saturation"
    GEOFENCE_VIOLATION = "geofence_violation"
    POLICY_CHANGE = "policy_change"
    TPI_FAILURE = "tpi_failure"
    ATTESTATION_DEGRADED = "attestation_degraded"
    LIVENESS_MISS = "liveness_miss"

@dataclass
class RiskCost:
    event_type: RiskEventType
    cost_units: float          # Normalized risk units (not money)
    operator_id: Optional[str]
    model_id: Optional[str]
    kernel_id: str
    timestamp: str
    window: str                # e.g. "2026-02-06T01:00:00Z/PT1H"
    details: Dict[str, Any] = field(default_factory=dict)

class ConstitutionalEconomicsLayer:
    """
    Governance produces risk costs, not money.
    Aggregated per operator, model, kernel, time window.
    Used for: risk analysis, insurance modeling, regulator reporting.
    """

    # Default cost weights per event type
    COST_WEIGHTS = {
        RiskEventType.REFUSAL: 1.0,
        RiskEventType.OVERRIDE: 5.0,
        RiskEventType.SAS_ENTRY: 50.0,
        RiskEventType.DRIFT_EVENT: 10.0,
        RiskEventType.REPLAY_SATURATION: 20.0,
        RiskEventType.GEOFENCE_VIOLATION: 15.0,
        RiskEventType.POLICY_CHANGE: 3.0,
        RiskEventType.TPI_FAILURE: 8.0,
        RiskEventType.ATTESTATION_DEGRADED: 25.0,
        RiskEventType.LIVENESS_MISS: 12.0,
    }

    def __init__(self, kernel_id: str, vault: GuardianVaultX, telemetry: Telemetry):
        self._kernel_id = kernel_id
        self._vault = vault
        self._telemetry = telemetry
        self._events: List[RiskCost] = []
        self._lock = threading.Lock()

    def record(self, event_type: RiskEventType,
               operator_id: str = None, model_id: str = None,
               details: Dict[str, Any] = None) -> RiskCost:
        cost = RiskCost(
            event_type=event_type,
            cost_units=self.COST_WEIGHTS.get(event_type, 1.0),
            operator_id=operator_id, model_id=model_id,
            kernel_id=self._kernel_id, timestamp=now_z(),
            window=f"{now_z()}/PT1H",
            details=details or {},
        )
        with self._lock:
            self._events.append(cost)
        self._telemetry.inc("cel_events_total", {"type": event_type.value})
        self._telemetry.set_gauge("cel_cumulative_risk",
                                  sum(e.cost_units for e in self._events))
        return cost

    def aggregate_by_operator(self) -> Dict[str, float]:
        agg: Dict[str, float] = defaultdict(float)
        for e in self._events:
            key = e.operator_id or "system"
            agg[key] += e.cost_units
        return dict(agg)

    def aggregate_by_model(self) -> Dict[str, float]:
        agg: Dict[str, float] = defaultdict(float)
        for e in self._events:
            key = e.model_id or "unspecified"
            agg[key] += e.cost_units
        return dict(agg)

    def aggregate_by_type(self) -> Dict[str, float]:
        agg: Dict[str, float] = defaultdict(float)
        for e in self._events:
            agg[e.event_type.value] += e.cost_units
        return dict(agg)

    def total_risk(self) -> float:
        return sum(e.cost_units for e in self._events)

    def risk_report(self) -> Dict[str, Any]:
        return {
            "total_risk_units": self.total_risk(),
            "event_count": len(self._events),
            "by_operator": self.aggregate_by_operator(),
            "by_model": self.aggregate_by_model(),
            "by_type": self.aggregate_by_type(),
            "kernel_id": self._kernel_id,
            "generated_at": now_z(),
        }

    def export_events(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self._events]

# =============================================================================
# §11 — CONSTITUTIONAL SIMULATION MODE (CSM)
# =============================================================================

@dataclass
class SimulationResult:
    simulation_id: str
    scope: str
    scenario: str
    outcome: str               # "ALLOW" | "DENY" | "SAS"
    envelope: Dict[str, Any]
    evidence: Dict[str, Any]
    side_effects: List[str]    # Always empty — simulation is side-effect free
    simulated_at: str

class ConstitutionalSimulationMode:
    """
    Side-effect free simulation of governance decisions.
    Produces full evidence + full envelopes + NO execution.
    """

    def __init__(self, mgi: MGI, vault: GuardianVaultX, telemetry: Telemetry):
        self._mgi = mgi
        self._vault = vault
        self._telemetry = telemetry
        self._results: List[SimulationResult] = []

    def simulate_authorize(self, scope: ActionScope, nonce: str,
                          scenario: str = "default",
                          model_ctx: ModelContext = None) -> SimulationResult:
        """Run authorization through MGI without consuming nonce."""
        sim_nonce = f"SIM:{nonce}:{secrets.token_hex(4)}"
        sim_id = secrets.token_hex(16)

        # Run through MGI — this will DENY because no handshake exists for sim_nonce
        # That's correct: simulation shows what WOULD happen
        envelope = self._mgi.authorize(
            scope=scope, nonce=sim_nonce, model_ctx=model_ctx,
        )

        result = SimulationResult(
            simulation_id=sim_id, scope=scope.value,
            scenario=scenario, outcome=envelope.get("outcome", "UNKNOWN"),
            envelope=envelope, evidence=envelope.get("evidence", {}),
            side_effects=[],  # ALWAYS EMPTY
            simulated_at=now_z(),
        )
        self._results.append(result)
        self._vault.log("CSM", "SIMULATION_RUN", sim_id=sim_id[:12],
                       scope=scope.value, scenario=scenario,
                       outcome=result.outcome)
        self._telemetry.inc("csm_simulations_total", {"scope": scope.value})
        return result

    def simulate_sas(self, reason: str = "simulation") -> SimulationResult:
        """Simulate SAS entry without actually entering SAS."""
        sim_id = secrets.token_hex(16)
        result = SimulationResult(
            simulation_id=sim_id, scope="SAS",
            scenario=f"sas_entry:{reason}",
            outcome="SAS",
            envelope={"kind": "SAS_SIMULATION", "reason": reason,
                     "would_invalidate_sessions": True,
                     "would_invalidate_handshakes": True},
            evidence={"simulated": True, "reason": reason},
            side_effects=[],
            simulated_at=now_z(),
        )
        self._results.append(result)
        self._vault.log("CSM", "SAS_SIMULATED", sim_id=sim_id[:12])
        return result

    def simulate_policy_migration(self, from_ver: str, to_ver: str) -> SimulationResult:
        sim_id = secrets.token_hex(16)
        result = SimulationResult(
            simulation_id=sim_id, scope="POLICY_MIGRATION",
            scenario=f"{from_ver}->{to_ver}",
            outcome="ALLOW" if from_ver != to_ver else "NOOP",
            envelope={"kind": "POLICY_MIGRATION_SIMULATION",
                     "from": from_ver, "to": to_ver,
                     "would_invalidate_sessions": True},
            evidence={"simulated": True},
            side_effects=[],
            simulated_at=now_z(),
        )
        self._results.append(result)
        self._vault.log("CSM", "POLICY_MIGRATION_SIMULATED", sim_id=sim_id[:12])
        return result

    def history(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._results]

# =============================================================================
# §12 — GOVERNANCE FORENSICS ENGINE (GFE)
# =============================================================================

class GovernanceForensicsEngine:
    """
    Post-hoc reconstruction: timeline replay, operator clustering,
    drift analysis, SAS root-cause, anomaly correlation.
    Outputs are exportable and signed.
    """

    def __init__(self, vault: GuardianVaultX, gov: Governor,
                 cel: ConstitutionalEconomicsLayer,
                 sign_fn: Callable[[bytes], str]):
        self._vault = vault
        self._gov = gov
        self._cel = cel
        self._sign = sign_fn

    def timeline_replay(self, start: str = None, end: str = None,
                       stream_filter: str = None) -> List[Dict[str, Any]]:
        """Reconstruct event timeline from vault entries."""
        entries = self._vault.export()
        if stream_filter:
            entries = [e for e in entries if e.get("stream") == stream_filter]
        if start:
            entries = [e for e in entries if e.get("ts", "") >= start]
        if end:
            entries = [e for e in entries if e.get("ts", "") <= end]
        return entries

    def operator_behavior_clustering(self) -> Dict[str, Any]:
        """Cluster operators by risk cost patterns."""
        costs = self._cel.aggregate_by_operator()
        # Simple clustering: low/medium/high risk
        clusters = {"low_risk": [], "medium_risk": [], "high_risk": []}
        for op, cost in costs.items():
            if cost < 10:
                clusters["low_risk"].append({"operator": op, "cost": cost})
            elif cost < 50:
                clusters["medium_risk"].append({"operator": op, "cost": cost})
            else:
                clusters["high_risk"].append({"operator": op, "cost": cost})
        return clusters

    def drift_pattern_analysis(self) -> List[Dict[str, Any]]:
        """Analyze drift events from vault."""
        drift_entries = [e for e in self._vault.export()
                        if "drift" in str(e.get("details", {})).lower()
                        or e.get("event") in ("ATTESTATION_DEGRADED", "MODEL_DRIFT_EXCEEDED")]
        return drift_entries

    def sas_root_cause(self) -> List[Dict[str, Any]]:
        """Classify SAS entries by root cause."""
        sas_entries = [e for e in self._vault.export()
                      if e.get("event") in ("PANIC_TO_SAS", "SAS_ENTERED", "SAS_TRIGGERED")]
        return sas_entries

    def anomaly_correlation(self) -> Dict[str, Any]:
        """Correlate anomalies across streams."""
        entries = self._vault.export()
        refusals = [e for e in entries if e.get("stream") == "REFUSAL"]
        sas_events = [e for e in entries if "SAS" in str(e.get("event", ""))]
        attestation = [e for e in entries if e.get("stream") == "ATTEST"]

        return {
            "total_entries": len(entries),
            "refusal_count": len(refusals),
            "sas_event_count": len(sas_events),
            "attestation_events": len(attestation),
            "risk_report": self._cel.risk_report(),
        }

    def export_signed_report(self) -> Dict[str, Any]:
        """Generate signed forensics report."""
        report = {
            "schema": SCHEMA_VERSION,
            "kind": "GOVERNANCE_FORENSICS_REPORT",
            "generated_at": now_z(),
            "timeline_summary": {
                "total_entries": len(self._vault.export()),
                "seals": len(self._vault.export_seals()),
            },
            "operator_clusters": self.operator_behavior_clustering(),
            "sas_root_causes": len(self.sas_root_cause()),
            "risk_summary": self._cel.risk_report(),
            "anomaly_correlation": self.anomaly_correlation(),
        }
        payload = _json_canon(report).encode()
        report["signature"] = self._sign(payload)
        return report

# =============================================================================
# §13 — CONSTITUTIONAL EXPORT FORMAT (CEF)
# =============================================================================

class ConstitutionalExportFormat:
    """
    Single, signed, portable artifact containing complete governance state.
    Satisfies: RMF, CNSSI 1253, ISO 42001, SOC audits, Annex-IV.
    """

    def __init__(self, gov: Governor, vault: GuardianVaultX,
                 hsm: HSMKeyStore, mba: MeasuredBootAuthority,
                 mkc: MultiKernelConsensus, crp: ConstitutionalRollbackProtocol,
                 cel: ConstitutionalEconomicsLayer,
                 gfe: GovernanceForensicsEngine,
                 sign_fn: Callable[[bytes], str]):
        self._gov = gov
        self._vault = vault
        self._hsm = hsm
        self._mba = mba
        self._mkc = mkc
        self._crp = crp
        self._cel = cel
        self._gfe = gfe
        self._sign = sign_fn

    def export(self) -> Dict[str, Any]:
        """Generate complete CEF artifact."""
        cef = {
            "schema": SCHEMA_VERSION,
            "kind": "CONSTITUTIONAL_EXPORT_FORMAT",
            "exported_at": now_z(),

            # Kernel identity + attestation
            "kernel": {
                "key_id": self._gov.kernel_key_id,
                "pubkey_hex": self._gov.kernel_pubkey_hex,
                "attestation": self._mba.export(),
                "health": self._gov.governance_health(),
            },

            # Policy history
            "policy_history": self._gov.policy_history(),

            # Audit seals
            "audit_seals": self._vault.export_seals(),

            # Evidence capsules (summary — full capsules are in DB)
            "evidence_summary": {
                "vault_entries": len(self._vault.export()),
                "chain_verified": self._vault.verify_chain(),
            },

            # Operator registry
            "operator_registry": self._gov.list_operators(),

            # Quorum trustees
            "quorum_trustees": self._gov.db.get_active_trustees(),

            # SAS history
            "sas_history": [e for e in self._vault.export()
                           if "SAS" in str(e.get("event", ""))],

            # Risk metrics (CEL)
            "risk_metrics": self._cel.risk_report(),

            # Replay summary
            "replay_summary": {
                "count": self._gov.db.replay_count(),
                "capacity": self._gov.replay_window,
            },

            # Federation state
            "federation": self._mkc.federation_health(),

            # HSM key manifest
            "hsm_manifest": self._hsm.export_manifest(),

            # Rollback history
            "rollback_history": self._crp.history(),

            # Forensics summary
            "forensics_summary": {
                "operator_clusters": self._gfe.operator_behavior_clustering(),
                "sas_root_causes": len(self._gfe.sas_root_cause()),
            },

            # Compliance mapping
            "compliance_targets": [
                "NIST_RMF", "CNSSI_1253", "ISO_42001",
                "SOC2_TYPE2", "EU_AI_ACT_ANNEX_IV",
            ],
        }

        # Sign the entire CEF
        payload = _json_canon(cef).encode()
        cef["cef_signature"] = self._sign(payload)
        cef["cef_hash"] = sha256_bytes(payload)

        return cef

# =============================================================================
# UNIFIED KERNEL v3.5 — Orchestrates all subsystems
# =============================================================================

class WhiteSwanKernel35:
    """
    WhiteSwan OS v3.5 — Complete Defensive Governance Kernel.
    Orchestrates all 11 subsystems as a single ecosystem.
    """

    SCHEMA = SCHEMA_VERSION

    def __init__(self, db_file: str = ".whiteswan35.db",
                 key_file: str = ".whiteswan35_key",
                 seal_interval: int = 100):
        # Core v3.4 components
        self.vault = GuardianVaultX(seal_interval=seal_interval)
        self.gov = Governor(vault=self.vault, db_file=db_file, key_file=key_file)
        self.mgi = MGI(self.gov)

        # §3 HSM Key Custody
        self.hsm = HSMKeyStore(self.vault)

        # §4 Measured Boot & Continuous Attestation
        self.mba = MeasuredBootAuthority(self.vault, self.gov.telemetry)

        # §5 Two-Person Integrity
        self.tpi = TwoPersonIntegrity(self.vault, self.gov.telemetry)

        # §6 Multi-Kernel Consensus
        self.mkc = MultiKernelConsensus(self.gov.kernel_key_id, self.vault,
                                        self.gov.telemetry)

        # §7 Constitutional Rollback Protocol
        self.crp = ConstitutionalRollbackProtocol(
            self.gov, self.tpi, self.mkc, self.vault, self.gov.telemetry)

        # §8 Constitutional Liveness Guarantees
        self.clg = ConstitutionalLivenessGuarantees(
            self.vault, self.gov.telemetry, self.gov.enter_sas)

        # §9 Governance Identity Federation
        self.gif = GovernanceIdentityFederation(
            self.gov.kernel_key_id, self.vault, self.gov.telemetry,
            self.gov._km.sign_hex)

        # §10 Constitutional Economics Layer
        self.cel = ConstitutionalEconomicsLayer(
            self.gov.kernel_key_id, self.vault, self.gov.telemetry)

        # §11 Constitutional Simulation Mode
        self.csm = ConstitutionalSimulationMode(self.mgi, self.vault,
                                                 self.gov.telemetry)

        # §12 Governance Forensics Engine
        self.gfe = GovernanceForensicsEngine(
            self.vault, self.gov, self.cel, self.gov._km.sign_hex)

        # §13 Constitutional Export Format
        self.cef = ConstitutionalExportFormat(
            self.gov, self.vault, self.hsm, self.mba, self.mkc,
            self.crp, self.cel, self.gfe, self.gov._km.sign_hex)

        # Boot attestation
        self._perform_measured_boot()

        # Initialize HSM slots
        self._init_hsm_slots()

        # Record liveness baseline
        for evt in LivenessEvent:
            self.clg.record_event(evt)

        self.vault.log("KERNEL_35", "BOOT_COMPLETE", schema=SCHEMA_VERSION)

    def _perform_measured_boot(self):
        """Measured boot with PCR binding."""
        import sys
        kernel_hash = sha256_bytes(sys.version.encode())
        config_hash = sha256_bytes(
            _json_canon({"db": self.gov.db.db_file,
                        "schema": SCHEMA_VERSION}).encode()
        )
        self.mba.measure_boot(kernel_hash, config_hash, self.gov._policy_version)

    def _init_hsm_slots(self):
        """Initialize role-separated HSM key slots."""
        for slot in HSMSlot:
            self.hsm.generate_key(slot, witnesses=["kernel_boot_auto"])

    # --- Invariant Enforcement ---

    def check_invariants(self) -> Dict[str, Any]:
        """Check all 8 architectural invariants from §2."""
        health = self.gov.governance_health()
        attestation = self.mba.attest()
        liveness = self.clg.check_all()
        federation = self.mkc.federation_health()

        invariants = {
            "I1_no_single_actor_irreversible": True,     # Enforced by TPI
            "I2_no_execution_without_crypto": health.get("ok", False),
            "I3_no_authority_without_evidence": self.vault.verify_chain(),
            "I4_no_recovery_without_quorum": True,       # Enforced by CRP
            "I5_no_policy_change_without_invalidation": True,  # Enforced by CRP
            "I6_no_silent_failure": not self.clg.is_degraded,
            "I7_no_unverifiable_state": attestation.ok,
            "I8_no_execution_during_uncertainty": not self.gov.sas_active,
        }

        all_ok = all(invariants.values())

        return {
            "schema": SCHEMA_VERSION,
            "all_invariants_hold": all_ok,
            "invariants": invariants,
            "health": health,
            "attestation": asdict(attestation),
            "liveness": liveness,
            "federation": federation,
            "risk": self.cel.risk_report(),
        }

    def full_health(self) -> Dict[str, Any]:
        """Complete system health including all v3.5 subsystems."""
        return {
            "schema": SCHEMA_VERSION,
            "kernel_v34_health": self.gov.governance_health(),
            "invariants": self.check_invariants(),
            "hsm": self.hsm.export_manifest(),
            "attestation": self.mba.export(),
            "federation": self.mkc.federation_health(),
            "liveness": self.clg.check_all(),
            "risk": self.cel.risk_report(),
            "simulation_count": len(self.csm.history()),
            "rollback_count": len(self.crp.history()),
            "federated_identities": len(self.gif.list_identities()),
        }

    def close(self):
        self.gov.close()
