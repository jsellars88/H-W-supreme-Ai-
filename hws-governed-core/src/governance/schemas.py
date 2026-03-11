from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Optional


class ActionTier(IntEnum):
    T0_SENSE = 0
    T1_ALERT = 1
    T2_ADVISE = 2
    T3_EXECUTE = 3
    T4_IRREVERSIBLE = 4


@dataclass
class ExecuteRequest:
    actor_id: str
    tenant_id: str
    action: str
    tier: ActionTier
    payload: Dict[str, Any] = field(default_factory=dict)
    handshake_token: Optional[str] = None


@dataclass
class GovernanceDecision:
    allowed: bool
    reason: str
    requires_handshake: bool
    decision_id: str
