#!/usr/bin/env python3
"""
Grok + WhiteSwan Governance Proxy

Routes chat requests through WhiteSwan governance before forwarding to
the xAI Grok API.  Demonstrates T4 denial without dual authorization.

Usage:
    uvicorn grok_proxy:app --reload --port 8000

Env:
    GROK_API_KEY   xAI API key (optional — returns mock response if unset)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ── Make the repo root importable ────────────────────────────────────
_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

import kernel_v34 as k34
import kernel_v35 as k35

# ── Governance kernel (in-memory) ────────────────────────────────────

KERNEL = k35.WhiteSwanKernel35(db_file=":memory:", key_file=".grok_demo_key")

# Register a demo operator
_demo_op = k34.OperatorIdentity.generate("grok-demo-operator", "operator")
_demo_rec = KERNEL.gov.register_operator(
    _demo_op,
    {k34.ActionScope.SENSING, k34.ActionScope.NAVIGATION,
     k34.ActionScope.ALERT_ESCALATION, k34.ActionScope.DATA_EXPORT},
)
_demo_session = KERNEL.gov.create_session(_demo_op)

# ── Scope classifier ────────────────────────────────────────────────

_T4_KEYWORDS = [
    "irreversible", "lethal", "kill", "delete permanently",
    "administer medication", "execute order", "launch",
]
_T3_KEYWORDS = [
    "medical", "diagnose", "prescribe", "intervene", "kinetic",
]


def _classify_scope(text: str) -> k34.ActionScope:
    lower = text.lower()
    for kw in _T4_KEYWORDS:
        if kw in lower:
            return k34.ActionScope.IRREVERSIBLE_MEDICAL
    for kw in _T3_KEYWORDS:
        if kw in lower:
            return k34.ActionScope.MEDICAL_INTERVENTION
    return k34.ActionScope.SENSING


# ── FastAPI app ──────────────────────────────────────────────────────

app = FastAPI(title="Grok + WhiteSwan Governance Proxy")


class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    model: str = "grok-3"


class ChatResponse(BaseModel):
    response: Optional[str] = None
    governed: bool = True
    scope: str = ""
    tier: str = ""
    outcome: str = ""
    detail: Optional[str] = None


@app.post("/chat")
def chat(body: ChatRequest) -> ChatResponse:
    last_msg = body.messages[-1].get("content", "") if body.messages else ""
    scope = _classify_scope(last_msg)
    tier = k34.SCOPE_TIER_MAP[scope]

    # Attempt governance authorization
    nonce = k34.generate_nonce()

    # For T1/T2 — issue handshake and authorize
    if tier.value <= k34.ActionTier.T2_ESCALATION.value:
        try:
            KERNEL.gov.issue(_demo_op, _demo_session, scope, nonce)
            envelope = KERNEL.mgi.authorize(scope=scope, nonce=nonce)
            outcome = envelope.get("outcome", "DENY")
        except Exception as e:
            outcome = "DENY"
            return ChatResponse(
                scope=scope.value, tier=tier.name, outcome=outcome,
                detail=str(e),
            )

        if outcome == "ALLOW":
            # In production, forward to Grok API here
            grok_key = os.environ.get("GROK_API_KEY")
            if grok_key:
                # Real Grok call would go here via httpx
                response_text = f"[Grok response to: {last_msg[:80]}]"
            else:
                response_text = f"[DEMO] Governance ALLOWED. Grok would respond to: {last_msg[:80]}"

            return ChatResponse(
                response=response_text,
                scope=scope.value, tier=tier.name, outcome="ALLOW",
            )

    # T3/T4 — denied without proper dual authorization + model context
    KERNEL.cel.record(
        k35.RiskEventType.refusal,
        operator_id=_demo_op.key_id,
        details={"scope": scope.value, "reason": "governance_denial"},
    )

    KERNEL.vault.log("GROK_PROXY", "T4_DENIED",
                     scope=scope.value, tier=tier.name,
                     message_preview=last_msg[:50])

    return ChatResponse(
        scope=scope.value, tier=tier.name, outcome="DENY",
        detail=f"Action requires {tier.name} authorization. "
               f"Two-Person Integrity + Model Context attestation required. "
               f"This denial is cryptographically logged.",
    )


@app.get("/health")
def health():
    return KERNEL.full_health()


@app.get("/audit")
def audit():
    return KERNEL.vault.tail(20)


@app.get("/risk")
def risk():
    return KERNEL.cel.risk_report()
