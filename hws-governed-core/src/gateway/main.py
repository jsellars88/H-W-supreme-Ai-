from __future__ import annotations

from fastapi import FastAPI, HTTPException
from dataclasses import dataclass

from agents.demo_agent import DemoAgent
from governance.kernel import GovernanceKernel
from governance.schemas import ActionTier, ExecuteRequest
from identity.auth import AuthStub
from ledger.ledger import DecisionLedger

app = FastAPI(title="HWS Governed Core")

ledger = DecisionLedger()
kernel = GovernanceKernel(ledger=ledger)
agent = DemoAgent(kernel=kernel)
auth = AuthStub()


@dataclass
class HandshakeRequest:
    issuer: str
    tenant_id: str
    allowed_tier: ActionTier
    ttl_seconds: int = 300


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "chain_valid": ledger.verify_chain()}


@app.post("/governance/handshake")
def issue_handshake(req: HandshakeRequest) -> dict:
    token = kernel.issue_handshake(
        issuer=req.issuer,
        tenant_id=req.tenant_id,
        allowed_tier=req.allowed_tier,
        ttl_seconds=req.ttl_seconds,
    )
    return {"token": token}


@app.post("/agents/execute")
def execute(req: ExecuteRequest) -> dict:
    try:
        auth.validate(actor_id=req.actor_id, tenant_id=req.tenant_id)
    except ValueError as err:
        raise HTTPException(status_code=401, detail=str(err)) from err

    return agent.execute(req)


@app.get("/ledger")
def show_ledger() -> dict:
    return {"chain_valid": ledger.verify_chain(), "entries": ledger.list_all()}
