from __future__ import annotations

from governance.kernel import GovernanceKernel
from governance.schemas import ExecuteRequest


class DemoAgent:
    def __init__(self, kernel: GovernanceKernel) -> None:
        self.kernel = kernel

    def execute(self, req: ExecuteRequest) -> dict:
        decision = self.kernel.authorize(req)

        if not decision.allowed:
            return {
                "status": "BLOCKED",
                "decision_id": decision.decision_id,
                "reason": decision.reason,
            }

        return {
            "status": "EXECUTED",
            "decision_id": decision.decision_id,
            "action": req.action,
            "message": f"Executed action: {req.action}",
        }
