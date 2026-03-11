from agents.demo_agent import DemoAgent
from governance.kernel import GovernanceKernel
from governance.schemas import ActionTier, ExecuteRequest
from ledger.ledger import DecisionLedger


def test_low_risk_executes() -> None:
    ledger = DecisionLedger(":memory:")
    kernel = GovernanceKernel(ledger)
    agent = DemoAgent(kernel)

    req = ExecuteRequest(
        actor_id="user-1",
        tenant_id="tenant-a",
        action="read_status",
        tier=ActionTier.T0_SENSE,
    )

    result = agent.execute(req)
    assert result["status"] == "EXECUTED"
    assert ledger.verify_chain()


def test_high_risk_blocked_without_handshake() -> None:
    ledger = DecisionLedger(":memory:")
    kernel = GovernanceKernel(ledger)
    agent = DemoAgent(kernel)

    req = ExecuteRequest(
        actor_id="user-1",
        tenant_id="tenant-a",
        action="send_external_email",
        tier=ActionTier.T3_EXECUTE,
    )

    result = agent.execute(req)
    assert result["status"] == "BLOCKED"
    assert ledger.verify_chain()


def test_high_risk_executes_with_handshake() -> None:
    ledger = DecisionLedger(":memory:")
    kernel = GovernanceKernel(ledger)
    agent = DemoAgent(kernel)

    token = kernel.issue_handshake(
        issuer="jake",
        tenant_id="tenant-a",
        allowed_tier=ActionTier.T3_EXECUTE,
    )

    req = ExecuteRequest(
        actor_id="user-1",
        tenant_id="tenant-a",
        action="send_external_email",
        tier=ActionTier.T3_EXECUTE,
        handshake_token=token,
    )

    result = agent.execute(req)
    assert result["status"] == "EXECUTED"
    assert ledger.verify_chain()
