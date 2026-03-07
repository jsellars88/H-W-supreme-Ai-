#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 Kernel — Unified Governance Kernel
Holmes & Watson Supreme AI™

Extends v3.4 Governor with subsystem modules for constitutional governance.
Currently implements:
  §3 HSM Key Custody
  §4 Measured Boot & Attestation

Remaining subsystems (TPI, MKC, CRP, CLG, GIF, CEL, CSM, GFE, CEF)
will be added incrementally.
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
    """Software-simulated HSM key custody.

    Production deployments should back this with a real HSM / KMS.
    """

    def __init__(self, vault: k34.GuardianVaultX):
        self._vault = vault
        self._slots: Dict[str, HSMKeyRecord] = {}
        self._rotations: List[Dict[str, Any]] = []
        # Bootstrap all four slots at epoch 1
        for slot in HSMSlot:
            self._slots[slot.value] = HSMKeyRecord(
                slot=slot.value,
                epoch=1,
                pubkey_hex=secrets.token_hex(32),
                created_at=now_z(),
                witnesses=[],
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
            slot=slot.value,
            epoch=new_epoch,
            pubkey_hex=secrets.token_hex(32),
            created_at=now_z(),
            witnesses=witnesses,
        )
        self._slots[slot.value] = rec
        self._rotations.append({
            "slot": slot.value,
            "old_epoch": new_epoch - 1,
            "new_epoch": new_epoch,
            "rotated_at": now_z(),
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
        self._vault.log("MBA", "REATTEST", ok=ok, drift=drift_pct)
        return AttestationResult(
            ok=ok,
            drift_from_baseline=drift_pct,
            measurements=current,
            attested_at=now_z(),
        )

    def last_attestation_hash(self) -> Optional[str]:
        return self._last_hash


# ═════════════════════════════════════════════════════════════════════
# UNIFIED KERNEL ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════

class WhiteSwanKernel35:
    """Top-level kernel orchestrator.

    Wraps the v3.4 Governor and adds v3.5 subsystem instances.
    Subsystems that are not yet implemented will simply not be
    present as attributes — the API layer guards access via hasattr().
    """

    def __init__(
        self,
        db_file: str = ":memory:",
        key_file: str = ".ws35_key",
        seal_interval: int = 100,
    ):
        self.vault = k34.GuardianVaultX(seal_interval=seal_interval)
        self.gov = k34.Governor(
            self.vault,
            db_file=db_file,
            key_file=key_file,
        )
        self.mgi = k34.MGI(self.gov)

        # v3.5 subsystems (implemented)
        self.hsm = HSMKeyCustody(self.vault)
        self.mba = MeasuredBootAttestation(self.vault, self.gov)

        # Future subsystems (not yet attached):
        #   self.tpi  — Two-Person Integrity
        #   self.mkc  — Multi-Kernel Consensus
        #   self.crp  — Constitutional Rollback Protocol
        #   self.clg  — Constitutional Liveness Guarantees
        #   self.gif  — Governance Identity Federation
        #   self.cel  — Constitutional Economics Layer
        #   self.csm  — Constitutional Simulation Mode
        #   self.gfe  — Governance Forensics Engine
        #   self.cef  — Constitutional Export Format

        self.vault.log("KERNEL", "V35_READY", schema=SCHEMA_VERSION)

    # ── Aggregate health ─────────────────────────────────────────────

    def full_health(self) -> Dict[str, Any]:
        health = self.gov.governance_health()
        health["schema"] = SCHEMA_VERSION
        health["hsm"] = self.hsm.export_manifest()
        health["boot_attestation"] = self.mba.export()
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
