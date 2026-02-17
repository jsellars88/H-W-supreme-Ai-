#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — HTTP API Layer
Holmes & Watson Supreme AI™

FastAPI server wrapping the unified v3.5 governance kernel.
Extends v3.4 API surface with subsystem endpoints (guarded if not implemented).

Env vars:
WS_API_KEYS               comma-separated API keys
WS_REQUIRE_AUTH_READONLY  if "1", read endpoints also need key
WS_DB_FILE                SQLite path (default :memory:)
WS_KEY_FILE               Ed25519 key path
WS_SEAL_INTERVAL          vault seal interval (default 100)
WS_DEV_EXPOSE_KEYS         if "1", return private keys ONCE on operator register (NOT for prod)
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

# ── Import v3.5 kernel (which includes v3.4) ─────────────────────────
# These imports must exist in your project.
import kernel_v34 as k34
import kernel_v35 as k35

# ── Configuration ────────────────────────────────────────────────────

API_KEYS: Set[str] = set()
REQUIRE_AUTH_READONLY = False
DEV_EXPOSE_KEYS = False

# ── State ────────────────────────────────────────────────────────────

KERNEL: Optional[Any] = None  # expected: k35.WhiteSwanKernel35
# In-memory operator key cache (DEMO ONLY). Production: HSM or external KMS.
OP_KEYS: Dict[str, Any] = {}  # pubkey_hex -> nacl.signing.SigningKey


# ── Helpers ─────────────────────────────────────────────────────────

def _require_kernel() -> Any:
    if KERNEL is None:
        raise HTTPException(503, "kernel_not_ready")
    return KERNEL


def _check_auth(request: Request, write: bool = True) -> None:
    # If no keys configured, auth is effectively disabled.
    if not API_KEYS:
        return
    if not write and not REQUIRE_AUTH_READONLY:
        return
    key = request.headers.get("X-WS-API-Key", "")
    if key not in API_KEYS:
        raise HTTPException(401, "invalid_api_key")


def _get_operator_name_role(pubkey_hex: str) -> tuple[str, str]:
    ker = _require_kernel()
    row = ker.gov.db.conn.execute(
        "SELECT name, role FROM operators WHERE pubkey_hex=? AND revoked IS NULL",
        (pubkey_hex,),
    ).fetchone()
    if not row:
        return ("unknown", "operator")
    return (row[0] or "unknown", row[1] or "operator")


def _require_attr(obj: Any, attr: str, endpoint: str) -> Any:
    if not hasattr(obj, attr):
        raise HTTPException(501, f"{endpoint}_not_implemented")
    return getattr(obj, attr)


# ── Lifespan ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global KERNEL, API_KEYS, REQUIRE_AUTH_READONLY, DEV_EXPOSE_KEYS

    raw = os.environ.get("WS_API_KEYS", "")
    API_KEYS = {k.strip() for k in raw.split(",") if k.strip()}
    REQUIRE_AUTH_READONLY = os.environ.get("WS_REQUIRE_AUTH_READONLY") == "1"
    DEV_EXPOSE_KEYS = os.environ.get("WS_DEV_EXPOSE_KEYS") == "1"

    db = os.environ.get("WS_DB_FILE", ":memory:")
    kf = os.environ.get("WS_KEY_FILE", ".ws35_key")
    si = int(os.environ.get("WS_SEAL_INTERVAL", "100"))

    # Expected constructor based on your comment. If your kernel differs, adjust here.
    KERNEL = k35.WhiteSwanKernel35(db_file=db, key_file=kf, seal_interval=si)

    try:
        yield
    finally:
        if KERNEL is not None:
            try:
                KERNEL.close()
            except Exception:
                pass


app = FastAPI(
    title="WhiteSwan OS v3.5 — Defensive Governance API",
    version=getattr(k35, "SCHEMA_VERSION", "ws-hs-v3.5"),
    lifespan=lifespan,
)

# ── Exception Handlers (from v3.4) ───────────────────────────────────

@app.exception_handler(k34.SASActiveError)
async def sas_handler(req: Request, exc: Exception):
    return JSONResponse(status_code=503, content={"error": "sas_active", "detail": str(exc)})

@app.exception_handler(k34.InsufficientAuthorityError)
async def auth_handler(req: Request, exc: Exception):
    return JSONResponse(status_code=403, content={"error": "insufficient_authority", "detail": str(exc)})

@app.exception_handler(k34.OperatorNotAuthorizedError)
async def op_handler(req: Request, exc: Exception):
    return JSONResponse(status_code=401, content={"error": "operator_not_authorized", "detail": str(exc)})

@app.exception_handler(k34.GovernanceViolation)
async def gov_handler(req: Request, exc: Exception):
    return JSONResponse(status_code=400, content={"error": "governance_violation", "detail": str(exc)})


# ═════════════════════════════════════════════════════════════════════
# SECTION A — V3.4 CORE ENDPOINTS
# ═════════════════════════════════════════════════════════════════════

@app.get("/v1/health")
def health(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    # expected: WhiteSwanKernel35.full_health()
    return ker.full_health()

@app.get("/v1/invariants")
def invariants(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return ker.check_invariants()

@app.get("/v1/attestation")
def attestation(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    gov = ker.gov
    mba = getattr(ker, "mba", None)
    return {
        "schema": getattr(k35, "SCHEMA_VERSION", "ws-hs-v3.5"),
        "kernel_key_id": gov.kernel_key_id,
        "kernel_pubkey_hex": gov.kernel_pubkey_hex,
        "policy_version": getattr(gov, "_policy_version", ""),
        "sas_active": gov.sas_active,
        "vault_entries": len(ker.vault.export()),
        "boot_attestation": mba.export() if mba else None,
        "attestation_hash": mba.last_attestation_hash() if mba else None,
    }

@app.get("/v1/telemetry")
def telemetry_json(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return ker.gov.telemetry.export_dict()

@app.get("/v1/telemetry/prometheus")
def telemetry_prom(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return PlainTextResponse(ker.gov.telemetry.export_prometheus(), media_type="text/plain")

@app.get("/v1/vault/tail")
def vault_tail(request: Request, n: int = 20):
    _check_auth(request, write=False)
    ker = _require_kernel()
    entries = ker.vault.export()
    return entries[-n:]

@app.get("/v1/vault/chain/verify")
def vault_chain_verify(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    ok = ker.vault.verify_chain()
    return {"chain_verified": ok, "entries": len(ker.vault.export())}

@app.get("/v1/seals")
def seals(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return ker.vault.export_seals()

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
    ker = _require_kernel()
    return ker.gov.policy_history()

# ── Operators ─────────────────────────────────────────────────────────

class RegisterOperatorReq(BaseModel):
    name: str
    role: str = "operator"
    scopes: List[str]
    geofence: Optional[str] = None
    geo_allowed_regions: Optional[List[str]] = None
    geo_denied_regions: Optional[List[str]] = None

@app.post("/v1/operators")
def register_operator(body: RegisterOperatorReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()

    scope_enums = set(k34.ActionScope(s) for s in body.scopes)

    geo = None
    if body.geofence or body.geo_allowed_regions or body.geo_denied_regions:
        geo = k34.GeoConstraint(
            allowed_regions=set(body.geo_allowed_regions or ([body.geofence] if body.geofence else [])),
            denied_regions=set(body.geo_denied_regions or []),
        )

    op = k34.OperatorIdentity.generate(body.name, body.role)
    rec = ker.gov.register_operator(op, scope_enums, geo)

    # Cache signing key (DEMO ONLY)
    OP_KEYS[rec.pubkey_hex] = op.signing_key

    out = {
        "pubkey_hex": rec.pubkey_hex,
        "name": rec.name,
        "role": rec.role,
        "warning": "private keys are NOT returned by default",
    }

    if DEV_EXPOSE_KEYS:
        out["private_key_hex"] = op.signing_key.encode().hex()
        out["warning"] = "private_key_shown_ONCE_DEV_MODE"

    return out

@app.get("/v1/operators")
def list_operators(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return ker.gov.list_operators()

@app.delete("/v1/operators/{pubkey}")
def revoke_operator(pubkey: str, request: Request, reason: str = "revoked_via_api"):
    _check_auth(request, write=True)
    ker = _require_kernel()
    ker.gov.revoke_operator(pubkey, reason)
    OP_KEYS.pop(pubkey, None)
    return {"revoked": pubkey, "reason": reason}

# ── Sessions ──────────────────────────────────────────────────────────

class CreateSessionReq(BaseModel):
    operator_pubkey: str
    max_tier: int = 4

@app.post("/v1/sessions")
def create_session(body: CreateSessionReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()

    sk = OP_KEYS.get(body.operator_pubkey)
    if not sk:
        raise HTTPException(400, "operator_private_key_not_cached")

    vk = sk.verify_key
    kid = hashlib.sha256(vk.encode()).hexdigest()[:16]
    name, role = _get_operator_name_role(body.operator_pubkey)

    ident = k34.OperatorIdentity(kid, name, role, sk, vk)

    tier = k34.ActionTier(int(body.max_tier))
    sid = ker.gov.create_session(ident, max_tier=tier)
    return {"session_id": sid, "operator_pubkey": body.operator_pubkey, "max_tier": tier.name}

@app.delete("/v1/sessions/{sid}")
def revoke_session(sid: str, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    ker.gov.revoke_session(sid)
    return {"revoked": sid}

# ── Handshakes & Authorization ────────────────────────────────────────

class IssueHandshakeReq(BaseModel):
    session_id: str
    scope: str
    nonce: str
    operator_pubkey: str
    model_ctx: Optional[Dict[str, Any]] = None
    nonce_context: Optional[Dict[str, Any]] = None

@app.post("/v1/handshakes/issue")
def issue_handshake(body: IssueHandshakeReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()

    scope = k34.ActionScope(body.scope)

    sk = OP_KEYS.get(body.operator_pubkey)
    if not sk:
        raise HTTPException(400, "operator_key_not_cached")

    vk = sk.verify_key
    kid = hashlib.sha256(vk.encode()).hexdigest()[:16]
    name, role = _get_operator_name_role(body.operator_pubkey)
    ident = k34.OperatorIdentity(kid, name, role, sk, vk)

    mc = k34.ModelContext(**body.model_ctx) if body.model_ctx else None
    hs = ker.gov.issue(
        ident,
        body.session_id,
        scope,
        body.nonce,
        nonce_context=body.nonce_context,
        model_ctx=mc,
    )
    return {"handshake_token": hs.token_id, "scope": body.scope, "nonce": body.nonce}

class AuthorizeReq(BaseModel):
    scope: str
    nonce: str
    model_ctx: Optional[Dict[str, Any]] = None
    expected_context: Optional[Dict[str, Any]] = None

@app.post("/v1/authorize")
def authorize(body: AuthorizeReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    scope = k34.ActionScope(body.scope)
    mc = k34.ModelContext(**body.model_ctx) if body.model_ctx else None
    envelope = ker.mgi.authorize(scope=scope, nonce=body.nonce, expected_context=body.expected_context, model_ctx=mc)
    return envelope

@app.get("/v1/decisions/{scope}/{nonce}")
def get_decision(scope: str, nonce: str, request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    row = ker.gov.db.conn.execute(
        "SELECT envelope_json FROM decisions WHERE scope=? AND nonce=? ORDER BY decided_at DESC LIMIT 1",
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
    ker = _require_kernel()
    ker.gov.enter_sas(body.reason)
    return {"sas_active": True, "reason": body.reason}

@app.get("/v1/sas/status")
def sas_status(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return {"sas_active": ker.gov.sas_active}

class EmergencyInitReq(BaseModel):
    reason: str

@app.post("/v1/emergency/initiate")
def emergency_initiate(body: EmergencyInitReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    # v3.4 signature: initiate_emergency_override(reason) -> override_id
    eid = ker.gov.initiate_emergency_override(body.reason)
    return {"emergency_id": eid}

class EmergencyApproveReq(BaseModel):
    emergency_id: str
    trustee_id: str
    signature: str

@app.post("/v1/emergency/approve")
def emergency_approve(body: EmergencyApproveReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    ok = ker.gov.approve_emergency_override(body.emergency_id, body.trustee_id, body.signature)
    return {"approved": ok}

# ── Vault Seals ───────────────────────────────────────────────────────

@app.post("/v1/seals/create")
def seal_create(request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    seal = ker.vault.create_seal(ker.gov._km.sign_hex)
    if seal:
        return asdict(seal)
    return {"status": "no_entries_to_seal"}

@app.post("/v1/seals/witness")
def seal_witness(request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    ker.vault.create_seal(ker.gov._km.sign_hex)
    ss = ker.vault.export_seals()
    return ss[-1] if ss else {}

# ── Trustees ──────────────────────────────────────────────────────────

class TrusteeReq(BaseModel):
    trustee_id: str
    pubkey_hex: str
    name: str

@app.post("/v1/trustees")
def add_trustee(body: TrusteeReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    # v3.4 DB has add_trustee(tid, pubkey, name)
    ker.gov.db.add_trustee(body.trustee_id, body.pubkey_hex, body.name)
    return {"registered": body.trustee_id, "pubkey_hex": body.pubkey_hex, "name": body.name}

@app.get("/v1/trustees")
def list_trustees(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    return ker.gov.db.get_active_trustees()

# ═════════════════════════════════════════════════════════════════════
# SECTION B — V3.5 SUBSYSTEM ENDPOINTS (GUARDED)
# ═════════════════════════════════════════════════════════════════════

@app.get("/v1/hsm/manifest")
def hsm_manifest(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    hsm = _require_attr(ker, "hsm", "hsm")
    return hsm.export_manifest()

class HSMRotateReq(BaseModel):
    slot: str
    witnesses: List[str]

@app.post("/v1/hsm/rotate")
def hsm_rotate(body: HSMRotateReq, request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    hsm = _require_attr(ker, "hsm", "hsm")
    slot_enum = getattr(k35, "HSMSlot")(body.slot)
    rec = hsm.generate_key(slot_enum, body.witnesses)
    return asdict(rec)

@app.get("/v1/hsm/rotations")
def hsm_rotations(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    hsm = _require_attr(ker, "hsm", "hsm")
    return hsm.rotation_history()

@app.get("/v1/boot/attestation")
def boot_attestation(request: Request):
    _check_auth(request, write=False)
    ker = _require_kernel()
    mba = _require_attr(ker, "mba", "boot_attestation")
    return mba.export()

@app.post("/v1/boot/reattest")
def reattest(request: Request):
    _check_auth(request, write=True)
    ker = _require_kernel()
    mba = _require_attr(ker, "mba", "boot_reattest")
    result = mba.attest()
    return asdict(result)

# The rest of the v3.5 subsystems follow the same guarded pattern.
# Add them when kernel_v35 implements: tpi, mkc, crp, clg, gif, cel, csm, gfe, cef.
