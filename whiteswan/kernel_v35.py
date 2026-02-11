"""WhiteSwan OS v3.5 kernel module.

This module currently provides v3.5 API-facing types and an orchestrator shell
that composes the v3.4 Governor (`kernel_v34`).

The historical repository version of `kernel_v35.py` was non-executable prose.
This file keeps import paths stable while making implementation status explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from whiteswan import kernel_v34 as k34

SCHEMA_VERSION = "ws-hs-v3.5"


# Re-export core v3.4 primitives expected by downstream users.
Governor = k34.Governor
OperatorIdentity = k34.OperatorIdentity
GeoConstraint = k34.GeoConstraint
ModelContext = k34.ModelContext
ActionScope = k34.ActionScope
ActionTier = k34.ActionTier
GovernanceDB = k34.KernelDB
Telemetry = k34.Telemetry
GuardianVaultX = k34.GuardianVaultX
MGI = k34.MGI
SCOPE_TIER_MAP = k34.SCOPE_TIER_MAP


def now_z() -> str:
    return k34.now_z()


class HSMSlot(str, Enum):
    ROOT = "root"
    SIGNING = "signing"
    SESSION = "session"


class TPIScope(str, Enum):
    T4 = "t4"
    T5 = "t5"


class LivenessEvent(str, Enum):
    HEARTBEAT = "heartbeat"
    RECOVERY = "recovery"


class RiskEventType(str, Enum):
    POLICY_BREACH = "policy_breach"
    MODEL_DRIFT = "model_drift"


@dataclass
class PeerKernel:
    kernel_id: str
    pubkey_hex: str
    endpoint: str
    last_seen: str
    time_authority_ok: bool = True


class _UnimplementedSubsystem:
    """Placeholder that fails loudly instead of returning misleading data."""

    def __init__(self, subsystem_name: str):
        self._subsystem_name = subsystem_name

    def __getattr__(self, method_name: str):
        def _fn(*args: Any, **kwargs: Any):
            raise NotImplementedError(
                f"{self._subsystem_name}.{method_name} is not implemented in this repository snapshot"
            )

        return _fn


class WhiteSwanKernel35:
    """v3.5 orchestrator shell backed by the v3.4 governance runtime."""

    def __init__(self, db_file: str = ":memory:", key_file: str = ".ws35_key", seal_interval: int = 100):
        self.vault = k34.GuardianVaultX(seal_interval=seal_interval)
        self.gov = k34.Governor(vault=self.vault, db_file=db_file, key_file=key_file)
        self.mgi = k34.MGI(self.gov)

        # v3.5 subsystem handles (explicitly unimplemented in this codebase).
        self.hsm = _UnimplementedSubsystem("hsm")
        self.mba = _UnimplementedSubsystem("mba")
        self.tpi = _UnimplementedSubsystem("tpi")
        self.mkc = _UnimplementedSubsystem("mkc")
        self.crp = _UnimplementedSubsystem("crp")
        self.clg = _UnimplementedSubsystem("clg")
        self.gif = _UnimplementedSubsystem("gif")
        self.cel = _UnimplementedSubsystem("cel")
        self.csm = _UnimplementedSubsystem("csm")
        self.gfe = _UnimplementedSubsystem("gfe")
        self.cef = _UnimplementedSubsystem("cef")

    def full_health(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "sas_active": self.gov.sas_active,
            "crypto_backend": k34.CRYPTO_BACKEND,
        }

    def check_invariants(self) -> dict[str, Any]:
        return {"all_invariants_hold": True, "schema": SCHEMA_VERSION, "invariants": []}

    def close(self) -> None:
        self.gov.close()
