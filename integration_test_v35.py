#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — Full Integration Test Suite
Holmes & Watson Supreme AI™

Tests all v3.4 core + 11 v3.5 subsystems (§3–§13) via HTTP API.
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
        ok("01 boot_health",
           r.status_code == 200 and "ws-hs-v3.5" in r.json().get("schema", ""),
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
            "scopes": ["sensing", "alert_escalation", "diagnostic_inference"]})
        ok("05 register_alpha", r.status_code == 200, f"body={r.text[:200]}")
        alpha_pub = r.json()["pubkey_hex"]

        # 6. Register operator bravo (T4 + geofence)
        r = c.post("/v1/operators", headers=H, json={
            "name": "bravo", "role": "commander",
            "scopes": ["sensing", "kinetic_lethal", "irreversible_medical"],
            "geo_allowed_regions": ["US-CONUS"]})
        ok("06 register_bravo", r.status_code == 200, f"body={r.text[:200]}")
        bravo_pub = r.json()["pubkey_hex"]

        # 7-8. Create sessions
        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": alpha_pub})
        ok("07 session_alpha", r.status_code == 200, f"body={r.text[:200]}")
        alpha_sid = r.json()["session_id"]

        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": bravo_pub})
        ok("08 session_bravo", r.status_code == 200, f"body={r.text[:200]}")
        bravo_sid = r.json()["session_id"]

        # 9. Nonce generation
        r = c.get("/v1/nonce", headers=H)
        ok("09 nonce", len(r.json()["nonce"]) > 10)
        n1 = r.json()["nonce"]

        # 10. T1 handshake
        r = c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n1,
            "operator_pubkey": alpha_pub})
        ok("10 handshake_t1", r.status_code == 200, f"body={r.text[:200]}")

        # 11. Authorize T1
        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n1})
        ok("11 authorize_t1", r.json().get("outcome") == "ALLOW",
           f"body={r.text[:200]}")

        # 12. Decision replay
        r = c.get(f"/v1/decisions/sensing/{n1}", headers=H)
        ok("12 decision_replay", r.json().get("outcome") == "ALLOW",
           f"body={r.text[:200]}")

        # 13. Replay protection
        n2 = c.get("/v1/nonce", headers=H).json()["nonce"]
        c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n2,
            "operator_pubkey": alpha_pub})
        c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        ok("13 replay_protection", r.json().get("outcome") == "DENY",
           f"body={r.text[:200]}")

        # 14. Vault chain integrity
        r = c.get("/v1/vault/chain/verify", headers=H)
        ok("14 vault_chain", r.json().get("chain_verified") is True)

        # 15. Telemetry JSON
        r = c.get("/v1/telemetry", headers=H)
        ok("15 telemetry_json", "counters" in r.json())

        # 16. Telemetry Prometheus
        r = c.get("/v1/telemetry/prometheus", headers=H)
        ok("16 telemetry_prometheus",
           "counter" in r.text or "gauge" in r.text or r.text == "")

        # 17. Attestation bundle
        r = c.get("/v1/attestation", headers=H)
        ok("17 attestation_bundle", r.json().get("schema") == "ws-hs-v3.5")

        # 18. SAS not active
        r = c.get("/v1/sas/status", headers=H)
        ok("18 sas_not_active", r.json().get("sas_active") is False)

        # 19. Vault tail
        r = c.get("/v1/vault/tail?n=5", headers=H)
        ok("19 vault_tail", isinstance(r.json(), list))

        # 20. Seals list
        r = c.get("/v1/seals", headers=H)
        ok("20 seals_list", isinstance(r.json(), list))

        # 21. Policy history
        r = c.get("/v1/policy/history", headers=H)
        ok("21 policy_history", isinstance(r.json(), list))

        # 22. List operators
        r = c.get("/v1/operators", headers=H)
        ok("22 list_operators", len(r.json()) >= 2,
           f"found {len(r.json())} operators")

        # 23. Create seal
        r = c.post("/v1/seals/create", headers=H)
        ok("23 seal_create", r.status_code == 200)

        # 24. Witness seal
        r = c.post("/v1/seals/witness", headers=H)
        ok("24 seal_witness", r.status_code == 200)

        # ═══════════════════════════════════════════════════════
        # B. §3 — HSM KEY CUSTODY
        # ═══════════════════════════════════════════════════════

        # 25. HSM manifest — 4 slots initialized
        r = c.get("/v1/hsm/manifest", headers=H)
        ok("25 hsm_manifest", len(r.json().get("slots", {})) == 4,
           f"body={r.text[:200]}")

        # 26. Key rotation
        r = c.post("/v1/hsm/rotate", headers=H, json={
            "slot": "audit_sealing", "witnesses": ["trustee_a", "trustee_b"]})
        ok("26 hsm_rotate", r.json().get("epoch") == 2,
           f"body={r.text[:200]}")

        # 27. Rotation history
        r = c.get("/v1/hsm/rotations", headers=H)
        ok("27 hsm_rotation_history", len(r.json()) >= 1)

        # ═══════════════════════════════════════════════════════
        # C. §4 — MEASURED BOOT & ATTESTATION
        # ═══════════════════════════════════════════════════════

        # 28. Boot attestation state
        r = c.get("/v1/boot/attestation", headers=H)
        ok("28 boot_attestation", r.json().get("baseline") is not None,
           f"body={r.text[:200]}")

        # 29. Re-attestation (no drift)
        r = c.post("/v1/boot/reattest", headers=H)
        ok("29 reattest_clean",
           r.json().get("ok") is True and r.json().get("drift_from_baseline") == 0.0,
           f"body={r.text[:200]}")

        # ═══════════════════════════════════════════════════════
        # D. §5 — TWO-PERSON INTEGRITY (TPI)
        # ═══════════════════════════════════════════════════════

        # 30. TPI initiate challenge
        r = c.post("/v1/tpi/initiate", headers=H, json={
            "scope": "T4_ACTION", "initiator_pubkey": alpha_pub,
            "evidence": {"action": "test_t4"}})
        ok("30 tpi_initiate", r.json().get("challenge_id") is not None,
           f"body={r.text[:200]}")
        tpi_id = r.json()["challenge_id"]

        # 31. Same-identity rejection
        r = c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": tpi_id, "completer_pubkey": alpha_pub})
        ok("31 tpi_same_identity", r.json().get("message") == "same_identity",
           f"body={r.text[:200]}")

        # 32. TPI complete by different operator
        r = c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": tpi_id, "completer_pubkey": bravo_pub})
        ok("32 tpi_complete", r.json().get("ok") is True,
           f"body={r.text[:200]}")

        # 33. Get TPI challenge (verified completed)
        r = c.get(f"/v1/tpi/challenge/{tpi_id}", headers=H)
        ok("33 tpi_get_challenge",
           r.json().get("completed_by") == bravo_pub,
           f"body={r.text[:200]}")

        # ═══════════════════════════════════════════════════════
        # E. §6 — MULTI-KERNEL CONSENSUS (MKC)
        # ═══════════════════════════════════════════════════════

        # 34. Register peer
        r = c.post("/v1/federation/peers", headers=H, json={
            "kernel_id": "peer-alpha", "pubkey_hex": "aabbcc",
            "endpoint": "https://peer-alpha.local:8443",
            "policy_version": "1.0"})
        ok("34 register_peer", r.json().get("kernel_id") == "peer-alpha",
           f"body={r.text[:200]}")

        # 35. Federation health
        r = c.get("/v1/federation/health", headers=H)
        ok("35 federation_health",
           r.json().get("total_peers") == 1 and r.json().get("healthy_peers") == 1,
           f"body={r.text[:200]}")

        # 36. Verify peer
        r = c.get("/v1/federation/verify/peer-alpha", headers=H)
        ok("36 verify_peer", r.json().get("verified") is True,
           f"body={r.text[:200]}")

        # 37. Quarantine peer
        r = c.post("/v1/federation/quarantine", headers=H, json={
            "kernel_id": "peer-alpha", "reason": "drift_detected"})
        ok("37 quarantine_peer", r.json().get("quarantined") == "peer-alpha")

        # 38. Verify quarantined peer fails
        r = c.get("/v1/federation/verify/peer-alpha", headers=H)
        ok("38 verify_quarantined", r.json().get("verified") is False,
           f"body={r.text[:200]}")

        # 39. Consensus check
        r = c.get("/v1/federation/consensus", headers=H)
        ok("39 federation_consensus", "consensus" in r.json())

        # ═══════════════════════════════════════════════════════
        # F. §7 — CONSTITUTIONAL ROLLBACK PROTOCOL (CRP)
        # ═══════════════════════════════════════════════════════

        # 40. Initiate rollback
        r = c.post("/v1/rollback/initiate", headers=H, json={
            "reason": "policy_regression", "from_policy": "1.1",
            "to_policy": "1.0", "initiator_pubkey": alpha_pub})
        ok("40 rollback_initiate",
           r.json().get("rollback_id") is not None
           and r.json().get("tpi_challenge_id") is not None,
           f"body={r.text[:200]}")
        rb_id = r.json()["rollback_id"]
        rb_tpi = r.json()["tpi_challenge_id"]

        # 41. Execute fails (TPI not satisfied)
        r = c.post("/v1/rollback/execute", headers=H, json={"rollback_id": rb_id})
        ok("41 rollback_blocked", r.json().get("ok") is False
           and r.json().get("message") == "tpi_not_satisfied",
           f"body={r.text[:200]}")

        # 42. Satisfy TPI then execute
        c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": rb_tpi, "completer_pubkey": bravo_pub})
        r = c.post("/v1/rollback/execute", headers=H, json={"rollback_id": rb_id})
        ok("42 rollback_execute", r.json().get("ok") is True,
           f"body={r.text[:200]}")

        # 43. Rollback history
        r = c.get("/v1/rollback/history", headers=H)
        ok("43 rollback_history", len(r.json()) >= 1)

        # ═══════════════════════════════════════════════════════
        # G. §8 — CONSTITUTIONAL LIVENESS GUARANTEES (CLG)
        # ═══════════════════════════════════════════════════════

        # 44. Record liveness event
        r = c.post("/v1/liveness/record", headers=H, json={"event": "AUDIT_SEAL"})
        ok("44 liveness_record", r.json().get("recorded") == "AUDIT_SEAL")

        # 45. Record another event
        r = c.post("/v1/liveness/record", headers=H, json={"event": "HEARTBEAT"})
        ok("45 liveness_heartbeat", r.json().get("recorded") == "HEARTBEAT")

        # 46. Check liveness
        r = c.get("/v1/liveness/check", headers=H)
        ok("46 liveness_check", r.json().get("total_events") >= 2,
           f"body={r.text[:200]}")

        # ═══════════════════════════════════════════════════════
        # H. §9 — GOVERNANCE IDENTITY FEDERATION (GIF)
        # ═══════════════════════════════════════════════════════

        # 47. Issue portable identity
        r = c.post("/v1/federation/identities", headers=H, json={
            "operator_pubkey": alpha_pub})
        ok("47 issue_identity",
           r.json().get("identity_id") is not None
           and r.json().get("operator_name") == "alpha",
           f"body={r.text[:200]}")

        # 48. List identities
        r = c.get("/v1/federation/identities", headers=H)
        ok("48 list_identities", len(r.json()) >= 1)

        # 49. Revocations (empty)
        r = c.get("/v1/federation/revocations", headers=H)
        ok("49 revocations_empty", isinstance(r.json(), list))

        # ═══════════════════════════════════════════════════════
        # I. §10 — CONSTITUTIONAL ECONOMICS LAYER (CEL)
        # ═══════════════════════════════════════════════════════

        # 50. Record risk event
        r = c.post("/v1/risk/record", headers=H, json={
            "event_type": "refusal", "operator_id": "op_alpha",
            "model_id": "claude-4"})
        ok("50 risk_record",
           r.json().get("event_type") == "refusal"
           and r.json().get("risk_units") == 5.0,
           f"body={r.text[:200]}")

        # 51. Record another risk event
        r = c.post("/v1/risk/record", headers=H, json={
            "event_type": "sas_entry", "operator_id": "op_alpha"})
        ok("51 risk_sas_entry", r.json().get("risk_units") == 50.0,
           f"body={r.text[:200]}")

        # 52. Risk report
        r = c.get("/v1/risk/report", headers=H)
        ok("52 risk_report",
           r.json().get("total_risk_units") == 55.0
           and r.json().get("event_count") == 2,
           f"body={r.text[:200]}")

        # 53. Risk events
        r = c.get("/v1/risk/events", headers=H)
        ok("53 risk_events", len(r.json()) == 2)

        # ═══════════════════════════════════════════════════════
        # J. §11 — CONSTITUTIONAL SIMULATION MODE (CSM)
        # ═══════════════════════════════════════════════════════

        # 54. Simulate T1 authorize
        r = c.post("/v1/simulate/authorize", headers=H, json={
            "scope": "sensing", "nonce": "sim-001", "scenario": "t1_baseline"})
        ok("54 sim_authorize_t1",
           r.json().get("outcome") == "ALLOW"
           and len(r.json().get("side_effects", [])) == 0,
           f"body={r.text[:200]}")

        # 55. Simulate T3 without model_ctx -> DENY
        r = c.post("/v1/simulate/authorize", headers=H, json={
            "scope": "medical_intervention", "nonce": "sim-002",
            "scenario": "t3_no_ctx"})
        ok("55 sim_authorize_t3_deny", r.json().get("outcome") == "DENY",
           f"body={r.text[:200]}")

        # 56. Simulate SAS drill
        r = c.post("/v1/simulate/sas", headers=H, json={"reason": "fire_drill"})
        ok("56 sim_sas",
           r.json().get("outcome") == "SAS"
           and r.json().get("scenario") == "sas_drill:fire_drill",
           f"body={r.text[:200]}")

        # 57. Simulate policy migration
        r = c.post("/v1/simulate/policy", headers=H, json={
            "from_version": "1.0", "to_version": "1.1"})
        ok("57 sim_policy", r.json().get("outcome") == "ALLOW",
           f"body={r.text[:200]}")

        # 58. Simulation history
        r = c.get("/v1/simulate/history", headers=H)
        ok("58 sim_history", len(r.json()) >= 3)

        # ═══════════════════════════════════════════════════════
        # K. §12 — GOVERNANCE FORENSICS ENGINE (GFE)
        # ═══════════════════════════════════════════════════════

        # 59. Timeline replay
        r = c.get("/v1/forensics/timeline", headers=H)
        ok("59 forensics_timeline", len(r.json()) > 0)

        # 60. Timeline with stream filter
        r = c.get("/v1/forensics/timeline?stream=HSM", headers=H)
        ok("60 forensics_timeline_hsm",
           all(e.get("stream") == "HSM" for e in r.json()),
           f"found non-HSM entries")

        # 61. Operator clustering
        r = c.get("/v1/forensics/clustering", headers=H)
        ok("61 forensics_clustering", "low_risk" in r.json(),
           f"body={r.text[:200]}")

        # 62. Drift patterns
        r = c.get("/v1/forensics/drift", headers=H)
        ok("62 forensics_drift", isinstance(r.json(), list))

        # 63. SAS root cause
        r = c.get("/v1/forensics/sas", headers=H)
        ok("63 forensics_sas", isinstance(r.json(), list))

        # 64. Anomaly correlation
        r = c.get("/v1/forensics/anomalies", headers=H)
        ok("64 forensics_anomalies", r.json().get("total_entries", 0) > 0)

        # 65. Signed forensics report
        r = c.get("/v1/forensics/report", headers=H)
        ok("65 forensics_report",
           r.json().get("schema") == "ws-hs-v3.5" and "signature" in r.json(),
           f"body={r.text[:200]}")

        # ═══════════════════════════════════════════════════════
        # L. §13 — CONSTITUTIONAL EXPORT FORMAT (CEF)
        # ═══════════════════════════════════════════════════════

        # 66. Full CEF export
        r = c.get("/v1/cef/export", headers=H)
        cef = r.json()
        ok("66 cef_export",
           cef.get("kind") == "CONSTITUTIONAL_EXPORT_FORMAT"
           and cef.get("schema") == "ws-hs-v3.5",
           f"body={r.text[:200]}")

        # 67. CEF contains kernel info
        ok("67 cef_kernel", cef.get("kernel", {}).get("key_id") is not None)

        # 68. CEF contains compliance targets
        ok("68 cef_compliance",
           "NIST_RMF" in cef.get("compliance_targets", []))

        # 69. CEF is signed
        ok("69 cef_signed",
           cef.get("cef_signature") is not None
           and cef.get("cef_hash") is not None)

        # ═══════════════════════════════════════════════════════
        # M. CROSS-CHECKS & FINAL INVARIANTS
        # ═══════════════════════════════════════════════════════

        # 70. Revoke operator and verify
        r = c.delete(f"/v1/operators/{bravo_pub}?reason=test_revoke", headers=H)
        ok("70 revoke_operator", r.json().get("revoked") == bravo_pub)

        # 71. Revoked operator session should fail
        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": bravo_pub})
        ok("71 revoked_session_denied", r.status_code in (400, 401),
           f"status={r.status_code}")

        # 72. Final invariants still hold
        r = c.get("/v1/invariants", headers=H)
        ok("72 final_invariants_hold",
           r.json().get("all_invariants_hold") is True,
           f"body={r.text[:200]}")

        # 73. Final vault chain valid
        r = c.get("/v1/vault/chain/verify", headers=H)
        ok("73 final_vault_chain", r.json().get("chain_verified") is True)


if __name__ == "__main__":
    print("=" * 70)
    print("WhiteSwan OS v3.5 — Full Integration Test Suite")
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
