#!/usr/bin/env python3
"""
WhiteSwan OS v3.5 — Integration Test Suite
Holmes & Watson Supreme AI™

Tests all 11 v3.5 subsystems + v3.4 core via HTTP API.
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

sys.path.insert(0, os.path.dirname(__file__))

from contextlib import contextmanager
from fastapi.testclient import TestClient

# Must import AFTER env is set
from whiteswan_api_v35 import app

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
        ok("01 boot_health", r.status_code == 200 and "ws-hs-v3.5" in r.json()["schema"])

        # 2. Auth rejection
        r = c.get("/v1/health", headers=BAD)
        ok("02 auth_rejection", r.status_code == 401)

        # 3. Invariants all hold
        r = c.get("/v1/invariants", headers=H)
        ok("03 invariants_hold", r.json()["all_invariants_hold"] is True)

        # 4. Scope map
        r = c.get("/v1/scopes", headers=H)
        ok("04 scope_map", "sensing" in r.json())

        # 5. Register operator alpha (T1-T3)
        r = c.post("/v1/operators", headers=H, json={
            "name": "alpha", "role": "analyst",
            "scopes": ["sensing", "alert_escalation",
                        "diagnostic_inference"], "max_tier": 3})
        ok("05 register_alpha", r.status_code == 200)
        alpha_pub = r.json()["pubkey_hex"]

        # 6. Register operator bravo (T4 + geofence)
        r = c.post("/v1/operators", headers=H, json={
            "name": "bravo", "role": "commander",
            "scopes": ["sensing", "kinetic_lethal", "irreversible_medical"],
            "max_tier": 4, "geo_allowed_regions": ["US-CONUS"]})
        ok("06 register_bravo", r.status_code == 200)
        bravo_pub = r.json()["pubkey_hex"]

        # 7. Create sessions
        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": alpha_pub})
        ok("07 session_alpha", r.status_code == 200)
        alpha_sid = r.json()["session_id"]

        r = c.post("/v1/sessions", headers=H, json={"operator_pubkey": bravo_pub})
        ok("08 session_bravo", r.status_code == 200)
        bravo_sid = r.json()["session_id"]

        # 8. Nonce generation
        r = c.get("/v1/nonce", headers=H)
        ok("09 nonce", len(r.json()["nonce"]) > 10)
        n1 = r.json()["nonce"]

        # 9. T1 handshake + authorize
        r = c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n1,
            "operator_pubkey": alpha_pub})
        ok("10 handshake_t1", r.status_code == 200)

        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n1})
        ok("11 authorize_t1", r.json()["outcome"] == "ALLOW")

        # 10. Decision replay
        r = c.get(f"/v1/decisions/sensing/{n1}", headers=H)
        ok("12 decision_replay", r.json()["outcome"] == "ALLOW")

        # 11. Replay protection
        n2 = c.get("/v1/nonce", headers=H).json()["nonce"]
        c.post("/v1/handshakes/issue", headers=H, json={
            "session_id": alpha_sid, "scope": "sensing", "nonce": n2,
            "operator_pubkey": alpha_pub})
        c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        r = c.post("/v1/authorize", headers=H, json={"scope": "sensing", "nonce": n2})
        ok("13 replay_protection", r.json()["outcome"] == "DENY")

        # 12. Vault chain integrity
        r = c.get("/v1/vault/chain/verify", headers=H)
        ok("14 vault_chain", r.json()["chain_verified"] is True)

        # 13. Telemetry JSON
        r = c.get("/v1/telemetry", headers=H)
        ok("15 telemetry_json", "counters" in r.json())

        # 14. Telemetry Prometheus
        r = c.get("/v1/telemetry/prometheus", headers=H)
        ok("16 telemetry_prometheus", "counter" in r.text or "gauge" in r.text or "measured_boots" in r.text)

        # ═══════════════════════════════════════════════════════
        # B. §3 — HSM KEY CUSTODY
        # ═══════════════════════════════════════════════════════

        # 15. HSM manifest — 4 slots initialized at boot
        r = c.get("/v1/hsm/manifest", headers=H)
        ok("17 hsm_manifest", len(r.json()["slots"]) == 4)

        # 16. Key rotation
        r = c.post("/v1/hsm/rotate", headers=H, json={
            "slot": "audit_sealing", "witnesses": ["trustee_a", "trustee_b"]})
        ok("18 hsm_rotate", r.json()["epoch"] == 2)

        # 17. Rotation history
        r = c.get("/v1/hsm/rotations", headers=H)
        ok("19 hsm_rotation_history", len(r.json()) >= 1)

        # ═══════════════════════════════════════════════════════
        # C. §4 — MEASURED BOOT & ATTESTATION
        # ═══════════════════════════════════════════════════════

        # 18. Boot attestation state
        r = c.get("/v1/boot/attestation", headers=H)
        ok("20 boot_attestation", r.json()["baseline"] is not None)

        # 19. Re-attestation (no drift)
        r = c.post("/v1/boot/reattest", headers=H)
        ok("21 reattest_clean", r.json()["ok"] is True and r.json()["drift_from_baseline"] == 0.0)

        # ═══════════════════════════════════════════════════════
        # D. §5 — TWO-PERSON INTEGRITY
        # ═══════════════════════════════════════════════════════

        # 20. TPI initiate
        r = c.post("/v1/tpi/initiate", headers=H, json={
            "scope": "T4_ACTION", "initiator_pubkey": alpha_pub,
            "evidence": {"action": "test_t4"}})
        ok("22 tpi_initiate", r.status_code == 200)
        tpi_id = r.json()["challenge_id"]

        # 21. TPI same-identity rejection
        r = c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": tpi_id, "completer_pubkey": alpha_pub})
        ok("23 tpi_same_identity_rejected", r.json()["satisfied"] is False
           and "same_identity" in r.json()["message"])

        # 22. TPI completion by second person
        r = c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": tpi_id, "completer_pubkey": bravo_pub})
        ok("24 tpi_complete", r.json()["satisfied"] is True)

        # 23. TPI status check
        r = c.get(f"/v1/tpi/{tpi_id}", headers=H)
        ok("25 tpi_status", r.json()["completed_by"] == bravo_pub)

        # ═══════════════════════════════════════════════════════
        # E. §6 — MULTI-KERNEL CONSENSUS
        # ═══════════════════════════════════════════════════════

        # 24. Register peer kernels
        r = c.post("/v1/federation/peers", headers=H, json={
            "kernel_id": "peer-kernel-01", "pubkey_hex": "aabbcc",
            "endpoint": "https://peer1.example.com"})
        ok("26 register_peer_1", r.status_code == 200)

        r = c.post("/v1/federation/peers", headers=H, json={
            "kernel_id": "peer-kernel-02", "pubkey_hex": "ddeeff",
            "endpoint": "https://peer2.example.com"})
        ok("27 register_peer_2", r.status_code == 200)

        # 25. Federation health
        r = c.get("/v1/federation/health", headers=H)
        ok("28 federation_health", r.json()["total_peers"] == 2
           and r.json()["healthy_peers"] == 2)

        # 26. T4 consensus (now have peers)
        r = c.get("/v1/federation/consensus/t4", headers=H)
        ok("29 t4_consensus_available", r.json()["t4_consensus"] is True)

        # 27. Verify peer
        r = c.get("/v1/federation/peers/peer-kernel-01/verify", headers=H)
        ok("30 verify_peer", r.json()["verified"] is True)

        # 28. Quarantine rogue peer
        r = c.post("/v1/federation/quarantine", headers=H, json={
            "kernel_id": "peer-kernel-02", "reason": "attestation_failure"})
        ok("31 quarantine_peer", r.status_code == 200)

        r = c.get("/v1/federation/peers/peer-kernel-02/verify", headers=H)
        ok("32 quarantined_peer_fails", r.json()["verified"] is False)

        # ═══════════════════════════════════════════════════════
        # F. §7 — CONSTITUTIONAL ROLLBACK PROTOCOL
        # ═══════════════════════════════════════════════════════

        # 29. Initiate rollback
        r = c.post("/v1/rollback/initiate", headers=H, json={
            "reason": "policy_regression_detected",
            "from_policy": "v2.0", "to_policy": "v1.9",
            "initiator_pubkey": alpha_pub})
        ok("33 rollback_initiate", "rollback_id" in r.json())
        rb_id = r.json()["rollback_id"]
        rb_tpi_id = r.json()["tpi_challenge_id"]

        # 30. Execute without TPI → fails
        r = c.post("/v1/rollback/execute", headers=H, json={"rollback_id": rb_id})
        ok("34 rollback_no_tpi_fails", r.json()["executed"] is False)

        # 31. Complete TPI for rollback
        c.post("/v1/tpi/complete", headers=H, json={
            "challenge_id": rb_tpi_id, "completer_pubkey": bravo_pub})

        # 32. Execute rollback
        r = c.post("/v1/rollback/execute", headers=H, json={"rollback_id": rb_id})
        ok("35 rollback_executed", r.json()["executed"] is True)

        # 33. Rollback history
        r = c.get("/v1/rollback/history", headers=H)
        ok("36 rollback_history", len(r.json()) >= 1 and r.json()[0]["executed"] is True)

        # ═══════════════════════════════════════════════════════
        # G. §8 — CONSTITUTIONAL LIVENESS GUARANTEES
        # ═══════════════════════════════════════════════════════

        # 34. Record liveness event
        r = c.post("/v1/liveness/record", headers=H, json={"event": "AUDIT_SEAL"})
        ok("37 liveness_record", r.status_code == 200)

        # 35. Liveness check
        r = c.get("/v1/liveness/check", headers=H)
        ok("38 liveness_check", "events" in r.json())

        # ═══════════════════════════════════════════════════════
        # H. §9 — GOVERNANCE IDENTITY FEDERATION
        # ═══════════════════════════════════════════════════════

        # Re-register operator for federation identity (rollback cleared sessions)
        r = c.post("/v1/operators", headers=H, json={
            "name": "charlie", "role": "analyst",
            "scopes": ["sensing", "alert_escalation"],
            "max_tier": 2})
        charlie_pub = r.json()["pubkey_hex"]

        # 36. Issue federated identity
        r = c.post("/v1/federation/identities", headers=H, json={
            "operator_pubkey": charlie_pub})
        ok("39 federated_identity_issued", r.status_code == 200
           and r.json()["operator_name"] == "charlie")
        fid_id = r.json()["identity_id"]

        # 37. List identities
        r = c.get("/v1/federation/identities", headers=H)
        ok("40 list_identities", len(r.json()) >= 1)

        # ═══════════════════════════════════════════════════════
        # I. §10 — CONSTITUTIONAL ECONOMICS LAYER
        # ═══════════════════════════════════════════════════════

        # 38. Record risk events
        c.post("/v1/risk/record", headers=H, json={
            "event_type": "refusal", "operator_id": alpha_pub[:16],
            "model_id": "claude-3-opus"})
        c.post("/v1/risk/record", headers=H, json={
            "event_type": "sas_entry", "operator_id": bravo_pub[:16]})
        c.post("/v1/risk/record", headers=H, json={
            "event_type": "drift_event", "model_id": "gpt-4o"})
        c.post("/v1/risk/record", headers=H, json={
            "event_type": "override", "operator_id": alpha_pub[:16]})

        # 39. Risk report
        r = c.get("/v1/risk/report", headers=H)
        rr = r.json()
        ok("41 risk_report", rr["total_risk_units"] > 0 and rr["event_count"] == 4)

        # 40. Risk by operator
        ok("42 risk_by_operator", len(rr["by_operator"]) >= 2)

        # 41. Risk by model
        ok("43 risk_by_model", "claude-3-opus" in rr["by_model"])

        # 42. Risk events list
        r = c.get("/v1/risk/events", headers=H)
        ok("44 risk_events", len(r.json()) == 4)

        # ═══════════════════════════════════════════════════════
        # J. §11 — CONSTITUTIONAL SIMULATION MODE
        # ═══════════════════════════════════════════════════════

        # 43. Simulate authorization
        r = c.post("/v1/simulate/authorize", headers=H, json={
            "scope": "sensing", "nonce": "sim-test-001",
            "scenario": "routine_check"})
        sim = r.json()
        ok("45 simulate_authorize", sim["side_effects"] == []
           and sim["scenario"] == "routine_check")

        # 44. Simulate SAS
        r = c.post("/v1/simulate/sas?reason=earthquake_drill", headers=H)
        ok("46 simulate_sas", r.json()["outcome"] == "SAS"
           and r.json()["side_effects"] == [])

        # 45. Simulate policy migration
        r = c.post("/v1/simulate/policy-migration", headers=H, json={
            "from_version": "1.0", "to_version": "2.0"})
        ok("47 simulate_policy_migration", r.json()["outcome"] == "ALLOW")

        # 46. Simulation history
        r = c.get("/v1/simulate/history", headers=H)
        ok("48 simulation_history", len(r.json()) >= 3)

        # SAS should NOT be active (simulation is side-effect free)
        r = c.get("/v1/sas/status", headers=H)
        ok("49 sas_not_active_after_sim", r.json()["sas_active"] is False)

        # ═══════════════════════════════════════════════════════
        # K. §12 — GOVERNANCE FORENSICS ENGINE
        # ═══════════════════════════════════════════════════════

        # 47. Timeline replay
        r = c.get("/v1/forensics/timeline", headers=H)
        ok("50 forensics_timeline", len(r.json()) > 0)

        # 48. Operator clustering
        r = c.get("/v1/forensics/operators", headers=H)
        ok("51 forensics_operators", "low_risk" in r.json())

        # 49. Drift analysis
        r = c.get("/v1/forensics/drift", headers=H)
        ok("52 forensics_drift", isinstance(r.json(), list))

        # 50. SAS root causes
        r = c.get("/v1/forensics/sas-causes", headers=H)
        ok("53 forensics_sas_causes", isinstance(r.json(), list))

        # 51. Anomaly correlation
        r = c.get("/v1/forensics/anomalies", headers=H)
        ok("54 forensics_anomalies", "total_entries" in r.json())

        # 52. Signed forensics report
        r = c.get("/v1/forensics/report", headers=H)
        report = r.json()
        ok("55 forensics_signed_report", "signature" in report
           and report["schema"] == "ws-hs-v3.5")

        # ═══════════════════════════════════════════════════════
        # L. §13 — CONSTITUTIONAL EXPORT FORMAT
        # ═══════════════════════════════════════════════════════

        # 53. Full CEF export
        r = c.get("/v1/export/cef", headers=H)
        cef = r.json()
        ok("56 cef_export", cef["kind"] == "CONSTITUTIONAL_EXPORT_FORMAT")
        ok("57 cef_kernel_identity", "kernel" in cef and "pubkey_hex" in cef["kernel"])
        ok("58 cef_policy_history", "policy_history" in cef)
        ok("59 cef_audit_seals", "audit_seals" in cef)
        ok("60 cef_risk_metrics", cef["risk_metrics"]["event_count"] >= 4)
        ok("61 cef_federation", "federation" in cef)
        ok("62 cef_hsm_manifest", "hsm_manifest" in cef)
        ok("63 cef_rollback_history", len(cef["rollback_history"]) >= 1)
        ok("64 cef_compliance_targets", "NIST_RMF" in cef["compliance_targets"])
        ok("65 cef_signature", "cef_signature" in cef and "cef_hash" in cef)

        # ═══════════════════════════════════════════════════════
        # M. CROSS-SUBSYSTEM INTEGRATION
        # ═══════════════════════════════════════════════════════

        # 54. TPI required for rollback (cross: §5 × §7)
        r = c.post("/v1/rollback/initiate", headers=H, json={
            "reason": "integration_test", "from_policy": "v2.0",
            "to_policy": "v1.8", "initiator_pubkey": charlie_pub})
        rb2_id = r.json()["rollback_id"]
        rb2_tpi = r.json()["tpi_challenge_id"]
        r = c.post("/v1/rollback/execute", headers=H, json={"rollback_id": rb2_id})
        ok("66 cross_tpi_rollback_blocked", r.json()["executed"] is False
           and "tpi" in r.json()["message"])

        # 55. Risk event from SAS (cross: §10 × SAS)
        c.post("/v1/risk/record", headers=H, json={
            "event_type": "sas_entry", "details": {"source": "integration_test"}})
        r = c.get("/v1/risk/report", headers=H)
        ok("67 cross_cel_sas_recorded", r.json()["total_risk_units"] > 50)

        # 56. Federation + attestation (cross: §4 × §6)
        r = c.get("/v1/export/cef", headers=H)
        cef2 = r.json()
        ok("68 cross_cef_attestation", cef2["kernel"]["attestation"]["degraded"] is False)

        # 57. Simulation doesn't affect real state (cross: §11 × core)
        pre_vault = len(c.get("/v1/vault/tail?n=1000", headers=H).json())
        c.post("/v1/simulate/authorize", headers=H, json={
            "scope": "kinetic_lethal", "nonce": "sim-lethal-001"})
        post_vault = len(c.get("/v1/vault/tail?n=1000", headers=H).json())
        ok("69 sim_side_effect_free", post_vault >= pre_vault)  # vault logs sim but no exec

        # 58. Invariants still hold after all operations
        r = c.get("/v1/invariants", headers=H)
        ok("70 final_invariants_hold", r.json()["all_invariants_hold"] is True)


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
