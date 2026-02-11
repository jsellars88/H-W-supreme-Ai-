#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — HTTP API Layer
Holmes & Watson Supreme AI™

FastAPI server wrapping the unified v3.5 governance kernel.
Extends v3.4 API surface with 11 new subsystem endpoints.

Env vars:
  WS_API_KEYS              comma-separated API keys
  WS_REQUIRE_AUTH_READONLY  if "1", read endpoints also need key
  WS_DB_FILE               SQLite path (default :memory:)
  WS_KEY_FILE              Ed25519 key path
  WS_SEAL_INTERVAL         vault seal interval (default 100)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

# ── Import v3.5 kernel (which includes v3.4) ─────────────────────────
from whiteswan import kernel_v34 as k34
from whiteswan import kernel_v35 as k35

# ── Configuration ─────────────────────────────────────────────────────
API_KEYS: set[str] = set()
REQUIRE_AUTH_READONLY = False

# ── State ─────────────────────────────────────────────────────────────
KERNEL: Optional[k35.WhiteSwanKernel35] = None
# In-memory operator cache (production: HSM)
OP_KEYS: Dict[str, bytes] = {}  # pubkey_hex → private_key_bytes

# ── Lifespan ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global KERNEL, API_KEYS, REQUIRE_AUTH_READONLY
    raw = os.environ.get("WS_API_KEYS", "")
    API_KEYS = {k.strip() for k in raw.split(",") if k.strip()}
    REQUIRE_AUTH_READONLY = os.environ.get("WS_REQUIRE_AUTH_READONLY") == "1"
    db = os.environ.get("WS_DB_FILE", ":memory:")
    kf = os.environ.get("WS_KEY_FILE", ".ws35_key")
    si = int(os.environ.get("WS_SEAL_INTERVAL", "100"))
    KERNEL = k35.WhiteSwanKernel35(db_file=db, key_file=kf, seal_interval=si)
    yield
    if KERNEL:
        KERNEL.close()

app = FastAPI(
    title="WhiteSwan OS v3.5 — Defensive Governance API",
    version=k35.SCHEMA_VERSION,
    lifespan=lifespan,
)

# ── Auth Middleware ────────────────────────────────────────────────────
def _check_auth(request: Request, write: bool = True):
    if not API_KEYS:
        return
    if not write and not REQUIRE_AUTH_READONLY:
        return
    key = request.headers.get("X-WS-API-Key", "")
    if key not in API_KEYS:
        raise HTTPException(401, "invalid_api_key")

# ── Exception Handlers ────────────────────────────────────────────────
@app.exception_handler(k34.SASActiveError)
async def sas_handler(req, exc):
    return JSONResponse(503, {"error": "sas_active", "detail": str(exc)})

@app.exception_handler(k34.InsufficientAuthorityError)
async def auth_handler(req, exc):
    return JSONResponse(403, {"error": "insufficient_authority", "detail": str(exc)})

@app.exception_handler(k34.OperatorNotAuthorizedError)
async def op_handler(req, exc):
    return JSONResponse(401, {"error": "operator_not_authorized", "detail": str(exc)})

@app.exception_handler(k34.GovernanceViolation)
async def gov_handler(req, exc):
    return JSONResponse(400, {"error": "governance_violation", "detail": str(exc)})

# ═════════════════════════════════════════════════════════════════════
# SECTION A — V3.4 CORE ENDPOINTS (carried forward)
# ═════════════════════════════════════════════════════════════════════

# ── Observability ─────────────────────────────────────────────────────
@app.get("/v1/health")
def health(request: Request):
    _check_auth(request, write=False)
    return KERNEL.full_health()

@app.get("/v1/invariants")
def invariants(request: Request):
    _check_auth(request, write=False)
    return KERNEL.check_invariants()

@app.get("/v1/attestation")
def attestation(request: Request):
    _check_auth(request, write=False)
    gov = KERNEL.gov
    return {
        "schema": k35.SCHEMA_VERSION,
        "kernel_key_id": gov.kernel_key_id,
        "kernel_pubkey_hex": gov.kernel_pubkey_hex,
        "policy_version": gov._policy_version,
        "sas_active": gov.sas_active,
        "vault_entries": len(KERNEL.vault.export()),
        "boot_attestation": KERNEL.mba.export(),
        "attestation_hash": KERNEL.mba.last_attestation_hash(),
    }

@app.get("/v1/telemetry")
def telemetry_json(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gov.telemetry.export_dict()

@app.get("/v1/telemetry/prometheus")
def telemetry_prom(request: Request):
    _check_auth(request, write=False)
    return PlainTextResponse(KERNEL.gov.telemetry.export_prometheus(), media_type="text/plain")

@app.get("/v1/vault/tail")
def vault_tail(request: Request, n: int = 20):
    _check_auth(request, write=False)
    entries = KERNEL.vault.export()
    return entries[-n:]

@app.get("/v1/vault/chain/verify")
def vault_chain_verify(request: Request):
    _check_auth(request, write=False)
    ok = KERNEL.vault.verify_chain()
    return {"chain_verified": ok, "entries": len(KERNEL.vault.export())}

@app.get("/v1/seals")
def seals(request: Request):
    _check_auth(request, write=False)
    return KERNEL.vault.export_seals()

@app.get("/v1/scopes")
def scopes(request: Request):
    _check_auth(request, write=False)
    return {s.value: {"tier": t.name} for s, t in k34.SCOPE_TIER_MAP.items()}

@app.get("/v1/nonce")
def nonce(request: Request):
    _check_auth(request, write=False)
    return {"nonce": k34.generate_nonce()}

@app.get("/v1/policy/history")
def policy_history(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gov.policy_history()

# ── Operators ─────────────────────────────────────────────────────────
class RegisterOperatorReq(BaseModel):
    name: str
    role: str = "operator"
    scopes: List[str]
    max_tier: int = 3
    geofence: Optional[str] = None
    geo_allowed_regions: Optional[List[str]] = None
    geo_denied_regions: Optional[List[str]] = None

@app.post("/v1/operators")
def register_operator(body: RegisterOperatorReq, request: Request):
    _check_auth(request, write=True)
    scope_enums = set(k34.ActionScope(s) for s in body.scopes)

    geo = None
    if body.geofence or body.geo_allowed_regions:
        geo = k34.GeoConstraint(
            allowed_regions=set(body.geo_allowed_regions or ([body.geofence] if body.geofence else [])),
            denied_regions=set(body.geo_denied_regions or []),
        )

    op = k34.OperatorIdentity.generate(body.name, body.role)
    rec = KERNEL.gov.register_operator(op, scope_enums, geo)
    # Cache private key for session creation
    from nacl.encoding import HexEncoder
    priv_bytes = op.signing_key.encode()
    OP_KEYS[rec.pubkey_hex] = op.signing_key
    return {
        "pubkey_hex": rec.pubkey_hex,
        "private_key_hex": priv_bytes.hex(),
        "name": rec.name,
        "max_tier": body.max_tier,
        "warning": "private_key_shown_ONCE",
    }

@app.get("/v1/operators")
def list_operators(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gov.list_operators()

@app.delete("/v1/operators/{pubkey}")
def revoke_operator(pubkey: str, request: Request, reason: str = "revoked_via_api"):
    _check_auth(request, write=True)
    KERNEL.gov.revoke_operator(pubkey, reason)
    OP_KEYS.pop(pubkey, None)
    return {"revoked": pubkey}

# ── Sessions ──────────────────────────────────────────────────────────
class CreateSessionReq(BaseModel):
    operator_pubkey: str
    max_tier: int = 4

@app.post("/v1/sessions")
def create_session(body: CreateSessionReq, request: Request):
    _check_auth(request, write=True)
    sk = OP_KEYS.get(body.operator_pubkey)
    if not sk:
        raise HTTPException(400, "operator_private_key_not_cached")
    # Reconstruct OperatorIdentity from cached signing key
    from nacl.encoding import HexEncoder
    vk = sk.verify_key
    kid = hashlib.sha256(vk.encode()).hexdigest()[:16]
    # Look up name/role from DB
    row = KERNEL.gov.db.conn.execute(
        "SELECT name, role FROM operators WHERE pubkey_hex=? AND revoked=0",
        (body.operator_pubkey,)
    ).fetchone()
    name = row[0] if row else "unknown"
    role = row[1] if row else "operator"
    ident = k34.OperatorIdentity(kid, name, role, sk, vk)
    tier = k34.ActionTier(body.max_tier)
    sid = KERNEL.gov.create_session(ident, max_tier=tier)
    return {"session_id": sid, "operator": body.operator_pubkey}

@app.delete("/v1/sessions/{sid}")
def revoke_session(sid: str, request: Request):
    _check_auth(request, write=True)
    KERNEL.gov.revoke_session(sid)
    return {"revoked": sid}

# ── Handshakes & Authorization ────────────────────────────────────────
class IssueHandshakeReq(BaseModel):
    session_id: str
    scope: str
    nonce: str
    operator_pubkey: str
    model_ctx: Optional[Dict[str, Any]] = None

@app.post("/v1/handshakes/issue")
def issue_handshake(body: IssueHandshakeReq, request: Request):
    _check_auth(request, write=True)
    scope = k34.ActionScope(body.scope)
    sk = OP_KEYS.get(body.operator_pubkey)
    if not sk:
        raise HTTPException(400, "operator_key_not_cached")
    # Reconstruct identity
    vk = sk.verify_key
    kid = hashlib.sha256(vk.encode()).hexdigest()[:16]
    row = KERNEL.gov.db.conn.execute(
        "SELECT name, role FROM operators WHERE pubkey_hex=? AND revoked=0",
        (body.operator_pubkey,)
    ).fetchone()
    name = row[0] if row else "unknown"
    role = row[1] if row else "operator"
    ident = k34.OperatorIdentity(kid, name, role, sk, vk)
    mc = k34.ModelContext(**body.model_ctx) if body.model_ctx else None
    hs = KERNEL.gov.issue(ident, body.session_id, scope, body.nonce, model_ctx=mc)
    return {"handshake_token": hs.token_id, "scope": body.scope, "nonce": body.nonce}

class AuthorizeReq(BaseModel):
    scope: str
    nonce: str
    model_ctx: Optional[Dict[str, Any]] = None

@app.post("/v1/authorize")
def authorize(body: AuthorizeReq, request: Request):
    _check_auth(request, write=True)
    scope = k34.ActionScope(body.scope)
    mc = None
    if body.model_ctx:
        mc = k34.ModelContext(**body.model_ctx)
    envelope = KERNEL.mgi.authorize(scope=scope, nonce=body.nonce, model_ctx=mc)
    return envelope

@app.get("/v1/decisions/{scope}/{nonce}")
def get_decision(scope: str, nonce: str, request: Request):
    _check_auth(request, write=False)
    row = KERNEL.gov.db.conn.execute(
        "SELECT envelope_json FROM decisions WHERE scope=? AND nonce=?",
        (scope, nonce),
    ).fetchone()
    if not row:
        raise HTTPException(404, "decision_not_found")
    return json.loads(row[0])

# ── SAS & Emergency ───────────────────────────────────────────────────
class SASReq(BaseModel):
    reason: str

@app.post("/v1/sas/enter")
def enter_sas(body: SASReq, request: Request):
    _check_auth(request, write=True)
    KERNEL.gov.enter_sas(body.reason)
    return {"sas_active": True, "reason": body.reason}

@app.get("/v1/sas/status")
def sas_status(request: Request):
    _check_auth(request, write=False)
    return {"sas_active": KERNEL.gov.sas_active}

class EmergencyInitReq(BaseModel):
    reason: str
    quorum_required: int = 2

@app.post("/v1/emergency/initiate")
def emergency_initiate(body: EmergencyInitReq, request: Request):
    _check_auth(request, write=True)
    eid = KERNEL.gov.initiate_emergency_override(body.reason, body.quorum_required)
    return {"emergency_id": eid, "quorum_required": body.quorum_required}

class EmergencyApproveReq(BaseModel):
    emergency_id: str
    trustee_pubkey: str
    signature: str

@app.post("/v1/emergency/approve")
def emergency_approve(body: EmergencyApproveReq, request: Request):
    _check_auth(request, write=True)
    ok = KERNEL.gov.approve_emergency_override(
        body.emergency_id, body.trustee_pubkey, body.signature)
    return {"approved": ok}

# ── Vault Seals ───────────────────────────────────────────────────────
@app.post("/v1/seals/create")
def seal_create(request: Request):
    _check_auth(request, write=True)
    seal = KERNEL.vault.create_seal(KERNEL.gov._km.sign_hex)
    if seal:
        return asdict(seal)
    return {"status": "no_entries_to_seal"}

@app.post("/v1/seals/witness")
def seal_witness(request: Request):
    _check_auth(request, write=True)
    # Create seal then return latest
    KERNEL.vault.create_seal(KERNEL.gov._km.sign_hex)
    ss = KERNEL.vault.export_seals()
    return ss[-1] if ss else {}

# ── Trustees ──────────────────────────────────────────────────────────
class TrusteeReq(BaseModel):
    pubkey_hex: str
    name: str

@app.post("/v1/trustees")
def add_trustee(body: TrusteeReq, request: Request):
    _check_auth(request, write=True)
    KERNEL.gov.register_trustee(body.pubkey_hex, body.name)
    return {"registered": body.pubkey_hex, "name": body.name}

@app.get("/v1/trustees")
def list_trustees(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gov.db.get_active_trustees()

# ═════════════════════════════════════════════════════════════════════
# SECTION B — V3.5 NEW SUBSYSTEM ENDPOINTS
# ═════════════════════════════════════════════════════════════════════

# ── §3 HSM Key Custody ────────────────────────────────────────────────
@app.get("/v1/hsm/manifest")
def hsm_manifest(request: Request):
    _check_auth(request, write=False)
    return KERNEL.hsm.export_manifest()

class HSMRotateReq(BaseModel):
    slot: str
    witnesses: List[str]

@app.post("/v1/hsm/rotate")
def hsm_rotate(body: HSMRotateReq, request: Request):
    _check_auth(request, write=True)
    slot = k35.HSMSlot(body.slot)
    rec = KERNEL.hsm.generate_key(slot, body.witnesses)
    return asdict(rec)

@app.get("/v1/hsm/rotations")
def hsm_rotations(request: Request):
    _check_auth(request, write=False)
    return KERNEL.hsm.rotation_history()

# ── §4 Measured Boot & Attestation ────────────────────────────────────
@app.get("/v1/boot/attestation")
def boot_attestation(request: Request):
    _check_auth(request, write=False)
    return KERNEL.mba.export()

@app.post("/v1/boot/reattest")
def reattest(request: Request):
    _check_auth(request, write=True)
    result = KERNEL.mba.attest()
    return asdict(result)

# ── §5 Two-Person Integrity ──────────────────────────────────────────
class TPIInitReq(BaseModel):
    scope: str
    initiator_pubkey: str
    evidence: Optional[Dict[str, Any]] = None

@app.post("/v1/tpi/initiate")
def tpi_initiate(body: TPIInitReq, request: Request):
    _check_auth(request, write=True)
    scope = k35.TPIScope(body.scope)
    ch = KERNEL.tpi.initiate(scope, body.initiator_pubkey, body.evidence)
    return asdict(ch)

class TPICompleteReq(BaseModel):
    challenge_id: str
    completer_pubkey: str
    completer_sig: str = ""

@app.post("/v1/tpi/complete")
def tpi_complete(body: TPICompleteReq, request: Request):
    _check_auth(request, write=True)
    ok, msg = KERNEL.tpi.complete(body.challenge_id, body.completer_pubkey,
                                   body.completer_sig)
    return {"satisfied": ok, "message": msg}

@app.get("/v1/tpi/{challenge_id}")
def tpi_status(challenge_id: str, request: Request):
    _check_auth(request, write=False)
    ch = KERNEL.tpi.get_challenge(challenge_id)
    if not ch:
        raise HTTPException(404, "challenge_not_found")
    return asdict(ch)

# ── §6 Multi-Kernel Consensus ────────────────────────────────────────
class PeerRegisterReq(BaseModel):
    kernel_id: str
    pubkey_hex: str
    endpoint: str
    policy_version: str = "1.0"
    sas_active: bool = False
    last_seal_root: str = ""
    time_authority_ok: bool = True
    attestation_health: bool = True

@app.post("/v1/federation/peers")
def register_peer(body: PeerRegisterReq, request: Request):
    _check_auth(request, write=True)
    peer = k35.PeerKernel(
        kernel_id=body.kernel_id, pubkey_hex=body.pubkey_hex,
        endpoint=body.endpoint, policy_version=body.policy_version,
        sas_active=body.sas_active, last_seal_root=body.last_seal_root,
        last_seen=k35.now_z(), time_authority_ok=body.time_authority_ok,
        attestation_health=body.attestation_health,
    )
    KERNEL.mkc.register_peer(peer)
    return {"registered": body.kernel_id}

@app.get("/v1/federation/health")
def federation_health(request: Request):
    _check_auth(request, write=False)
    return KERNEL.mkc.federation_health()

@app.get("/v1/federation/peers/{kernel_id}/verify")
def verify_peer(kernel_id: str, request: Request):
    _check_auth(request, write=False)
    return KERNEL.mkc.verify_peer(kernel_id)

class QuarantineReq(BaseModel):
    kernel_id: str
    reason: str

@app.post("/v1/federation/quarantine")
def quarantine_peer(body: QuarantineReq, request: Request):
    _check_auth(request, write=True)
    KERNEL.mkc.quarantine_peer(body.kernel_id, body.reason)
    return {"quarantined": body.kernel_id, "reason": body.reason}

@app.get("/v1/federation/consensus/t4")
def check_t4_consensus(request: Request):
    _check_auth(request, write=False)
    ok, msg = KERNEL.mkc.check_t4_consensus()
    return {"t4_consensus": ok, "detail": msg}

# ── §7 Constitutional Rollback Protocol ──────────────────────────────
class RollbackInitReq(BaseModel):
    reason: str
    from_policy: str
    to_policy: str
    initiator_pubkey: str

@app.post("/v1/rollback/initiate")
def rollback_initiate(body: RollbackInitReq, request: Request):
    _check_auth(request, write=True)
    rid, tpi_id = KERNEL.crp.initiate(
        body.reason, body.from_policy, body.to_policy, body.initiator_pubkey)
    return {"rollback_id": rid, "tpi_challenge_id": tpi_id,
            "next_step": "complete TPI, then POST /v1/rollback/execute"}

class RollbackExecReq(BaseModel):
    rollback_id: str

@app.post("/v1/rollback/execute")
def rollback_execute(body: RollbackExecReq, request: Request):
    _check_auth(request, write=True)
    ok, msg = KERNEL.crp.execute(body.rollback_id)
    return {"executed": ok, "message": msg}

@app.get("/v1/rollback/history")
def rollback_history(request: Request):
    _check_auth(request, write=False)
    return KERNEL.crp.history()

# ── §8 Constitutional Liveness Guarantees ────────────────────────────
class LivenessRecordReq(BaseModel):
    event: str

@app.post("/v1/liveness/record")
def liveness_record(body: LivenessRecordReq, request: Request):
    _check_auth(request, write=True)
    evt = k35.LivenessEvent(body.event)
    KERNEL.clg.record_event(evt)
    return {"recorded": body.event}

@app.get("/v1/liveness/check")
def liveness_check(request: Request):
    _check_auth(request, write=False)
    return KERNEL.clg.check_all()

# ── §9 Governance Identity Federation ────────────────────────────────
class FederatedIdentityReq(BaseModel):
    operator_pubkey: str

@app.post("/v1/federation/identities")
def issue_federated_identity(body: FederatedIdentityReq, request: Request):
    _check_auth(request, write=True)
    rec = KERNEL.gov._get_operator_record(body.operator_pubkey)
    if not rec or not rec.is_active:
        raise HTTPException(404, "operator_not_found_or_revoked")
    fid = KERNEL.gif.issue_portable_identity(rec)
    return asdict(fid)

@app.get("/v1/federation/identities")
def list_federated_identities(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gif.list_identities()

@app.get("/v1/federation/revocations")
def federation_revocations(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gif.get_revocations()

# ── §10 Constitutional Economics Layer ───────────────────────────────
class RiskEventReq(BaseModel):
    event_type: str
    operator_id: Optional[str] = None
    model_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@app.post("/v1/risk/record")
def record_risk(body: RiskEventReq, request: Request):
    _check_auth(request, write=True)
    evt = k35.RiskEventType(body.event_type)
    cost = KERNEL.cel.record(evt, body.operator_id, body.model_id, body.details)
    return asdict(cost)

@app.get("/v1/risk/report")
def risk_report(request: Request):
    _check_auth(request, write=False)
    return KERNEL.cel.risk_report()

@app.get("/v1/risk/events")
def risk_events(request: Request):
    _check_auth(request, write=False)
    return KERNEL.cel.export_events()

# ── §11 Constitutional Simulation Mode ───────────────────────────────
class SimAuthReq(BaseModel):
    scope: str
    nonce: str
    scenario: str = "default"
    model_ctx: Optional[Dict[str, Any]] = None

@app.post("/v1/simulate/authorize")
def simulate_authorize(body: SimAuthReq, request: Request):
    _check_auth(request, write=True)
    scope = k34.ActionScope(body.scope)
    mc = k34.ModelContext(**body.model_ctx) if body.model_ctx else None
    result = KERNEL.csm.simulate_authorize(scope, body.nonce, body.scenario, mc)
    return asdict(result)

@app.post("/v1/simulate/sas")
def simulate_sas(request: Request, reason: str = "drill"):
    _check_auth(request, write=True)
    result = KERNEL.csm.simulate_sas(reason)
    return asdict(result)

class SimPolicyReq(BaseModel):
    from_version: str
    to_version: str

@app.post("/v1/simulate/policy-migration")
def simulate_policy_migration(body: SimPolicyReq, request: Request):
    _check_auth(request, write=True)
    result = KERNEL.csm.simulate_policy_migration(body.from_version, body.to_version)
    return asdict(result)

@app.get("/v1/simulate/history")
def simulation_history(request: Request):
    _check_auth(request, write=False)
    return KERNEL.csm.history()

# ── §12 Governance Forensics Engine ──────────────────────────────────
@app.get("/v1/forensics/timeline")
def forensics_timeline(request: Request, start: str = None, end: str = None,
                       stream: str = None):
    _check_auth(request, write=False)
    return KERNEL.gfe.timeline_replay(start, end, stream)

@app.get("/v1/forensics/operators")
def forensics_operators(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gfe.operator_behavior_clustering()

@app.get("/v1/forensics/drift")
def forensics_drift(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gfe.drift_pattern_analysis()

@app.get("/v1/forensics/sas-causes")
def forensics_sas(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gfe.sas_root_cause()

@app.get("/v1/forensics/anomalies")
def forensics_anomalies(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gfe.anomaly_correlation()

@app.get("/v1/forensics/report")
def forensics_report(request: Request):
    _check_auth(request, write=False)
    return KERNEL.gfe.export_signed_report()

# ── §13 Constitutional Export Format ─────────────────────────────────
@app.get("/v1/export/cef")
def export_cef(request: Request):
    _check_auth(request, write=False)
    return KERNEL.cef.export()