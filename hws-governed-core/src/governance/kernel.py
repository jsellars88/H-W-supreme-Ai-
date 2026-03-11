from __future__ import annotations

import hashlib
import time
import uuid
from typing import Dict, Optional

from governance.schemas import ActionTier, ExecuteRequest, GovernanceDecision
from ledger.ledger import DecisionLedger


class GovernanceKernel:
    def __init__(self, ledger: DecisionLedger) -> None:
        self.ledger = ledger
        self.handshakes: Dict[str, Dict] = {}

    def issue_handshake(
        self,
        issuer: str,
        tenant_id: str,
        allowed_tier: ActionTier,
        ttl_seconds: int = 300,
    ) -> str:
        token = hashlib.sha256(
            f"{issuer}:{tenant_id}:{allowed_tier}:{uuid.uuid4()}:{time.time()}".encode()
        ).hexdigest()[:32]

        self.handshakes[token] = {
            "issuer": issuer,
            "tenant_id": tenant_id,
            "allowed_tier": int(allowed_tier),
            "expires_at": time.time() + ttl_seconds,
            "consumed": False,
        }
        return token

    def _verify_handshake(
        self, token: Optional[str], tenant_id: str, tier: ActionTier
    ) -> bool:
        if not token:
            return False

        record = self.handshakes.get(token)
        if not record:
            return False
        if record["consumed"]:
            return False
        if record["tenant_id"] != tenant_id:
            return False
        if time.time() > record["expires_at"]:
            return False
        if record["allowed_tier"] < int(tier):
            return False

        record["consumed"] = True
        return True

    def authorize(self, req: ExecuteRequest) -> GovernanceDecision:
        decision_id = str(uuid.uuid4())

        if req.tier <= ActionTier.T1_ALERT:
            self.ledger.append(
                actor_id=req.actor_id,
                tenant_id=req.tenant_id,
                action=req.action,
                tier=int(req.tier),
                allowed=True,
                reason="Autonomous low-risk action allowed",
                metadata={"decision_id": decision_id, "path": "autonomous"},
            )
            return GovernanceDecision(
                allowed=True,
                reason="Autonomous low-risk action allowed",
                requires_handshake=False,
                decision_id=decision_id,
            )

        valid = self._verify_handshake(req.handshake_token, req.tenant_id, req.tier)

        if not valid:
            self.ledger.append(
                actor_id=req.actor_id,
                tenant_id=req.tenant_id,
                action=req.action,
                tier=int(req.tier),
                allowed=False,
                reason="Blocked: valid handshake required before execution",
                metadata={"decision_id": decision_id, "path": "fail_closed"},
            )
            return GovernanceDecision(
                allowed=False,
                reason="Blocked: valid handshake required before execution",
                requires_handshake=True,
                decision_id=decision_id,
            )

        self.ledger.append(
            actor_id=req.actor_id,
            tenant_id=req.tenant_id,
            action=req.action,
            tier=int(req.tier),
            allowed=True,
            reason="Authorized by valid handshake",
            metadata={"decision_id": decision_id, "path": "approved"},
        )
        return GovernanceDecision(
            allowed=True,
            reason="Authorized by valid handshake",
            requires_handshake=False,
            decision_id=decision_id,
        )
