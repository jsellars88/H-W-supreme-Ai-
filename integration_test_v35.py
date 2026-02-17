#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — Integration Test Suite
Holmes & Watson Supreme AI™

Tests v3.4 core + implemented v3.5 subsystems (HSM, MBA) via HTTP API.
Uses FastAPI TestClient — no separate server process.
"""

import json
import os
import sys

# Configure env BEFORE importing app
os.environ["WS_API_KEYS"] = "test-key-alpha,test-key-bravo"
os.environ["WS_REQUIRE_AUTH_READONLY"] = "1"
os.environ["WS_DB_FILE"] = ":memory:"
os.environ["WS_SEAL_INTERVAL"] = "50"
os.environ["WS_DEV_EXPOSE_KEYS"] = "1"

sys.path.insert(0, os.path.dirname(__file__))

from contextlib import contextmanager
from fastapi.testclient import TestClient

# Must import AFTER env is set
from app_v35 import app

PASS = 0
FAIL = 0
TESTS: list[str] = []

def ok(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    tag = "PASS" if cond else "FAIL"
    TESTS.append(f"[{tag}] {name}")
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  !! FAIL: {name} — {detail}")

H = {"X-WS-API-Key": "test-key-alpha"}
H2 = {"X-WS-API-Key": "test-key-bravo"}
BAD = {"X-WS-API-Key": "wrong-key"}

@contextmanager
def client():
    with TestClient(app) as c:
        yield c

def run_all():
    with client() as c:
        # ═══════════════════════════════════════════════════════
        # A. CORE V3.4 (carried forward)
        # ═══════════════════════════════════════════════════════

        # 1. Boot health
        r = c.get("/v1/health", headers=H)
        ok("01 boot_health", r.status_code == 200 and "ws-hs-v3.5" in r.json().get("schema", ""),
           f"status={r.status_code} body={r.text[:200]}")

        # 2. Auth rejection
        r = c.get("/v1/health", headers=BAD)
        ok("02 auth_rejection", r.status_code == 401)

        # 3. Invariants all hold
        r = c.get("/v1/invariants", headers=H)
        ok("03 invariants_hold", r.json().get("all_invariants_hold") is True,
           f"body={r.text[:200]}")

        # 4. Scope map
        r = c.get("/v1/scopes", headers=H)
        ok("04 scope_map", "sensing" in r.json())

        # 5. Register operator alpha (T1-T3)
        r = c.post("/v1/operators", headers=H, json={
            "name": "alpha", "role": "analyst",
            "scopes": ["sensing", "alert_escalation",
                        "diagnostic_inference"]})
        ok("05 register_alpha", r.status_code == 200, f"body={r.text[:200]}")
        alpha_pub = r.json()["pubkey_hex"]

        # 6. Register operator bravo (T4 + geofence)
        r = c.post("/v1/operators", headers=H, json={
            "name": "bravo", "role": "commander",
            "scopes": ["sensing", "kinetic_lethal", "irreversible_medical"],
            "geo_allowed_regions": ["US-CONUS"]})
        ok("06 register_bravo", r.status_code == 200, f"body={r.text[:200]}")
        bravo_pub = r.json()["pubkey_hex"]

        # 7. Create sessions
        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": alpha_pub})
        ok("07 session_alpha", r.status_code == 200, f"body={r.text[:200]}")
        alpha_sid = r.json()["session_id"]

        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": bravo_pub})
        ok("08 session_bravo", r.status_code == 200, f"body={r.text[:200]}")
        bravo_sid = r.json()["session_id"]

        # 8. Nonce generation
        r = c.get("/v1/nonce", headers=H)
        ok("09 nonce", len(r.json()["nonce"]) > 10)
        n1 = r.json()["nonce"]

        # 9. T1 handshake + authorize
        r = c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n1,
            "operator_pubkey": alpha_pub})
        ok("10 handshake_t1", r.status_code == 200, f"body={r.text[:200]}")

        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n1})
        ok("11 authorize_t1", r.json().get("outcome") == "ALLOW",
           f"body={r.text[:200]}")

        # 10. Decision replay
        r = c.get(f"/v1/decisions/sensing/{n1}", headers=H)
        ok("12 decision_replay", r.json().get("outcome") == "ALLOW",
           f"body={r.text[:200]}")

        # 11. Replay protection
        n2 = c.get("/v1/nonce", headers=H).json()["nonce"]
        c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n2,
            "operator_pubkey": alpha_pub})
        c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        ok("13 replay_protection", r.json().get("outcome") == "DENY",
           f"body={r.text[:200]}")

        # 12. Vault chain integrity
        r = c.get("/v1/vault/chain/verify", headers=H)
        ok("14 vault_chain", r.json().get("chain_verified") is True)

        # 13. Telemetry JSON
        r = c.get("/v1/telemetry", headers=H)
        ok("15 telemetry_json", "counters" in r.json())

        # 14. Telemetry Prometheus
        r = c.get("/v1/telemetry/prometheus", headers=H)
        ok("16 telemetry_prometheus",
           "counter" in r.text or "gauge" in r.text or r.text == "")

        # 15. Attestation bundle
        r = c.get("/v1/attestation", headers=H)
        ok("17 attestation_bundle", r.json().get("schema") == "ws-hs-v3.5")

        # 16. SAS status (should not be active)
        r = c.get("/v1/sas/status", headers=H)
        ok("18 sas_not_active", r.json().get("sas_active") is False)

        # 17. Vault tail
        r = c.get("/v1/vault/tail?n=5", headers=H)
        ok("19 vault_tail", isinstance(r.json(), list))

        # 18. Seals list
        r = c.get("/v1/seals", headers=H)
        ok("20 seals_list", isinstance(r.json(), list))

        # 19. Policy history
        r = c.get("/v1/policy/history", headers=H)
        ok("21 policy_history", isinstance(r.json(), list))

        # 20. List operators
        r = c.get("/v1/operators", headers=H)
        ops = r.json()
        ok("22 list_operators", len(ops) >= 2,
           f"found {len(ops)} operators")

        # 21. Create seal
        r = c.post("/v1/seals/create", headers=H)
        ok("23 seal_create", r.status_code == 200)

        # 22. Witness seal
        r = c.post("/v1/seals/witness", headers=H)
        ok("24 seal_witness", r.status_code == 200)

        # ═══════════════════════════════════════════════════════
        # B. §3 — HSM KEY CUSTODY
        # ═══════════════════════════════════════════════════════

        # 23. HSM manifest — 4 slots initialized at boot
        r = c.get("/v1/hsm/manifest", headers=H)
        ok("25 hsm_manifest", len(r.json().get("slots", {})) == 4,
           f"body={r.text[:200]}")

        # 24. Key rotation
        r = c.post("/v1/hsm/rotate", headers=H, json={
            "slot": "audit_sealing", "witnesses": ["trustee_a", "trustee_b"]})
        ok("26 hsm_rotate", r.json().get("epoch") == 2,
           f"body={r.text[:200]}")

        # 25. Rotation history
        r = c.get("/v1/hsm/rotations", headers=H)
        ok("27 hsm_rotation_history", len(r.json()) >= 1)

        # ═══════════════════════════════════════════════════════
        # C. §4 — MEASURED BOOT & ATTESTATION
        # ═══════════════════════════════════════════════════════

        # 26. Boot attestation state
        r = c.get("/v1/boot/attestation", headers=H)
        ok("28 boot_attestation", r.json().get("baseline") is not None,
           f"body={r.text[:200]}")

        # 27. Re-attestation (no drift)
        r = c.post("/v1/boot/reattest", headers=H)
        ok("29 reattest_clean",
           r.json().get("ok") is True and r.json().get("drift_from_baseline") == 0.0,
           f"body={r.text[:200]}")

        # ═══════════════════════════════════════════════════════
        # D. CROSS-CHECKS
        # ═══════════════════════════════════════════════════════

        # 28. Revoke operator and verify
        r = c.delete(f"/v1/operators/{bravo_pub}?reason=test_revoke", headers=H)
        ok("30 revoke_operator", r.json().get("revoked") == bravo_pub)

        # 29. Revoked operator session should fail
        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": bravo_pub})
        ok("31 revoked_session_denied", r.status_code in (400, 401),
           f"status={r.status_code}")

        # 30. Invariants still hold after all operations
        r = c.get("/v1/invariants", headers=H)
        ok("32 final_invariants_hold", r.json().get("all_invariants_hold") is True,
           f"body={r.text[:200]}")

        # 31. Vault chain still valid
        r = c.get("/v1/vault/chain/verify", headers=H)
        ok("33 final_vault_chain", r.json().get("chain_verified") is True)


if __name__ == "__main__":
    print("=" * 70)
    print("WhiteSwan OS v3.5 — Integration Test Suite")
    print("Holmes & Watson Supreme AI™")
    print("=" * 70)
    run_all()
    print("\n" + "=" * 70)
    for t in TESTS:
        print(t)
    print("=" * 70)
    print(f"\nRESULTS: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    if FAIL:
        sys.exit(1)
    else:
        print("\n✓ ALL TESTS PASSED")
