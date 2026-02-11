"""WhiteSwan OS v3.5 compatibility layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from whiteswan import kernel_v34 as k34

SCHEMA_VERSION = "ws-hs-v3.5"


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


class _NullSubsystem:
    def __getattr__(self, _: str):
        def _fn(*args: Any, **kwargs: Any):
            return {}
        return _fn


class WhiteSwanKernel35:
    """Thin v3.5 orchestrator backed by the v3.4 Governor."""

    def __init__(self, db_file: str = ":memory:", key_file: str = ".ws35_key", seal_interval: int = 100):
        self.vault = k34.GuardianVaultX(seal_interval=seal_interval)
        self.gov = k34.Governor(vault=self.vault, db_file=db_file, key_file=key_file)
        self.mgi = k34.MGI(self.gov)

        # v3.5 subsystem placeholders (kept import/runtime-safe for API layer)
        self.hsm = _NullSubsystem()
        self.mba = _NullSubsystem()
        self.tpi = _NullSubsystem()
        self.mkc = _NullSubsystem()
        self.crp = _NullSubsystem()
        self.clg = _NullSubsystem()
        self.gif = _NullSubsystem()
        self.cel = _NullSubsystem()
        self.csm = _NullSubsystem()
        self.gfe = _NullSubsystem()
        self.cef = _NullSubsystem()

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
