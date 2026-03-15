#!/usr/bin/env python3
"""Adversarial tests for White Swan OS Cornerstone v2.0."""

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests

BASE_URL = "http://localhost:8080"
DB_PATH = "test_cornerstone.db"
TEST_TTL = 2
SERVER_PY = "cornerstone.py"


class AdversarialSuite:
    def __init__(self):
        self.passed = []
        self.failed = []
        self._proc = None

    def _start(self):
        env = os.environ.copy()
        env["HANDSHAKE_TTL"] = str(TEST_TTL)
        env["DB_PATH"] = DB_PATH

        if Path(DB_PATH).exists():
            Path(DB_PATH).unlink()

        self._proc = subprocess.Popen(
            [sys.executable, SERVER_PY],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        for _ in range(20):
            try:
                requests.get(f"{BASE_URL}/health", timeout=1)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("Server did not start")

    def _stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None

    def _restart(self):
        self._stop()
        time.sleep(0.5)
        self._start()

    def _issue(self, operator_id: str, tier: str) -> str:
        r = requests.post(f"{BASE_URL}/handshake", json={"operator_id": operator_id, "tier": tier})
        return r.json()["token_id"]

    def _action(self, action_type: str, tier: str, tokens=None, payload=None) -> dict:
        body = {"action_type": action_type, "tier": tier, "payload": payload or {}}
        if tokens:
            body["handshake_tokens"] = tokens
        r = requests.post(f"{BASE_URL}/action", json=body)
        return r.json()

    def _pass(self, name: str, detail: str = ""):
        self.passed.append(name)
        print(f"  ✅ {name}" + (f" — {detail}" if detail else ""))

    def _fail(self, name: str, detail: str = ""):
        self.failed.append(name)
        print(f"  ❌ {name}" + (f" — {detail}" if detail else ""))

    def test_1_replay_attack(self):
        print("\n[1] Replay Attack")
        tid = self._issue("alice", "T3_HIGH")
        r1 = self._action("loan_approval", "T3_HIGH", [tid])
        r2 = self._action("loan_approval", "T3_HIGH", [tid])
        if r1["outcome"] == "EXECUTED" and r2["outcome"] == "BLOCKED":
            self._pass("replay_blocked")
        else:
            self._fail("replay_blocked", f"first={r1['outcome']} second={r2['outcome']}")

    def test_2_token_expiry(self):
        print(f"\n[2] Token Expiry (TTL={TEST_TTL}s)")
        tid = self._issue("alice", "T3_HIGH")
        time.sleep(TEST_TTL + 1)
        r = self._action("loan_approval", "T3_HIGH", [tid])
        if r["outcome"] == "BLOCKED":
            self._pass("expiry_enforced")
        else:
            self._fail("expiry_enforced", str(r))

    def test_3_tier_escalation(self):
        print("\n[3] Tier Escalation")
        tid = self._issue("alice", "T2_SENSITIVE")
        r = self._action("high_risk_trade", "T3_HIGH", [tid])
        if r["outcome"] == "BLOCKED":
            self._pass("tier_escalation_blocked")
        else:
            self._fail("tier_escalation_blocked", str(r))

    def test_4_chain_tampering(self):
        print("\n[4] Ledger Tampering")
        tid = self._issue("alice", "T3_HIGH")
        self._action("test_action", "T3_HIGH", [tid])

        self._stop()
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT seq FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        if row:
            conn.execute("UPDATE ledger SET outcome='TAMPERED' WHERE seq=?", (row[0],))
            conn.commit()
        conn.close()
        self._restart()

        v_after = requests.get(f"{BASE_URL}/ledger/verify").json()
        if not v_after["valid"]:
            self._pass("tamper_detected")
        else:
            self._fail("tamper_detected", "chain reported valid after DB edit")

    def test_5_race_condition(self):
        print("\n[5] Race Condition")
        tid = self._issue("alice", "T3_HIGH")
        outcomes = []
        errors = []

        def send(i):
            try:
                r = requests.post(
                    f"{BASE_URL}/action",
                    json={
                        "action_type": "fast_trade",
                        "tier": "T3_HIGH",
                        "payload": {"thread": i},
                        "handshake_tokens": [tid],
                    },
                )
                outcomes.append(r.json()["outcome"])
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=send, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        executed = outcomes.count("EXECUTED")
        blocked = outcomes.count("BLOCKED")
        if executed == 1 and blocked == 9 and not errors:
            self._pass("race_condition_atomic")
        else:
            self._fail("race_condition_atomic", f"executed={executed} blocked={blocked} errors={len(errors)}")

    def test_6_t4_multi_party(self):
        print("\n[6] T4 Multi-Party")
        t_alice1 = self._issue("alice", "T4_IRREVERSIBLE")
        r1 = self._action("irreversible", "T4_IRREVERSIBLE", [t_alice1])

        t_alice2 = self._issue("alice", "T4_IRREVERSIBLE")
        t_alice3 = self._issue("alice", "T4_IRREVERSIBLE")
        r2 = self._action("irreversible", "T4_IRREVERSIBLE", [t_alice2, t_alice3])

        t_alice4 = self._issue("alice", "T4_IRREVERSIBLE")
        t_bob = self._issue("bob", "T4_IRREVERSIBLE")
        r3 = self._action("irreversible", "T4_IRREVERSIBLE", [t_alice4, t_bob])

        if r1["outcome"] == "BLOCKED" and r2["outcome"] == "BLOCKED" and r3["outcome"] == "EXECUTED":
            self._pass("t4_multi_party")
        else:
            self._fail("t4_multi_party", f"single={r1['outcome']} same={r2['outcome']} diff={r3['outcome']}")

    def test_7_signature_verification(self):
        print("\n[7] Signature Verification")
        resp = requests.post(f"{BASE_URL}/handshake", json={"operator_id": "alice", "tier": "T3_HIGH"})
        data = resp.json()
        tid = data["token_id"]
        sig_hex = data["signature"]
        pub_hex = data["pubkey"]

        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT operator_id,tier,issued_at,expires_at,nonce FROM handshakes WHERE token_id=?",
            (tid,),
        ).fetchone()
        conn.close()

        from nacl.encoding import HexEncoder
        from nacl.signing import VerifyKey

        payload = json.dumps(
            {
                "expires_at": row[3],
                "iss": "white-swan-cornerstone",
                "issued_at": row[2],
                "nonce": row[4],
                "operator_id": row[0],
                "tier": row[1],
                "token_id": tid,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        vk = VerifyKey(pub_hex, encoder=HexEncoder)
        try:
            vk.verify(payload, bytes.fromhex(sig_hex))
        except Exception as e:
            self._fail("signature_verification", f"verify failed: {e}")
            return

        tampered = json.dumps(
            {
                "expires_at": row[3],
                "iss": "white-swan-cornerstone",
                "issued_at": row[2],
                "nonce": row[4],
                "operator_id": "eve",
                "tier": row[1],
                "token_id": tid,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        try:
            vk.verify(tampered, bytes.fromhex(sig_hex))
            self._fail("signature_verification", "tampered payload verified")
        except Exception:
            self._pass("signature_verification")

    def test_8_handshake_tampering(self):
        print("\n[8] Handshake Tampering")
        resp = requests.post(f"{BASE_URL}/handshake", json={"operator_id": "alice", "tier": "T3_HIGH"})
        tid = resp.json()["token_id"]

        self._stop()
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE handshakes SET operator_id='eve' WHERE token_id=?", (tid,))
        conn.commit()
        conn.close()
        self._restart()

        r = self._action("sensitive_op", "T3_HIGH", [tid])
        if r["outcome"] == "BLOCKED":
            self._pass("handshake_tampering_detected")
        else:
            self._fail("handshake_tampering_detected")

    def test_9_restart_persistence(self):
        print("\n[9] Restart Persistence")
        pub_before = requests.get(f"{BASE_URL}/pubkey/handshake").json()["pubkey"]
        tid = self._issue("alice", "T3_HIGH")
        self._stop()
        time.sleep(0.5)
        self._start()

        pub_after = requests.get(f"{BASE_URL}/pubkey/handshake").json()["pubkey"]
        r = self._action("loan_approval", "T3_HIGH", [tid])

        if pub_before == pub_after and r["outcome"] == "EXECUTED":
            self._pass("restart_persistence")
        else:
            self._fail("restart_persistence", f"keys_same={pub_before == pub_after} outcome={r['outcome']}")

    def report(self):
        total = len(self.passed) + len(self.failed)
        print("\n" + "=" * 65)
        print(f"ADVERSARIAL RESULTS {len(self.passed)}/{total} passed")
        print("=" * 65)
        return not self.failed

    def run(self):
        self._start()
        tests = [
            self.test_1_replay_attack,
            self.test_2_token_expiry,
            self.test_3_tier_escalation,
            self.test_4_chain_tampering,
            self.test_5_race_condition,
            self.test_6_t4_multi_party,
            self.test_7_signature_verification,
            self.test_8_handshake_tampering,
            self.test_9_restart_persistence,
        ]

        try:
            for test in tests:
                test()
                time.sleep(0.3)
        finally:
            self._stop()
            for f in Path(".").glob("test_cornerstone.db*"):
                f.unlink(missing_ok=True)

        return self.report()


if __name__ == "__main__":
    suite = AdversarialSuite()
    success = suite.run()
    sys.exit(0 if success else 1)
