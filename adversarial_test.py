#!/usr/bin/env python3
"""
adversarial_test.py — White Swan OS Cornerstone v2.1

Runs real HTTP tests against a live local server.

Tests:
1. Replay attack
2. Token expiry
3. Tier escalation
4. Ledger tampering
5. Race condition
6. T4 multi-party
7. Signature verification
8. Handshake tampering
9. Restart persistence
"""

from __future__ import annotations

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

    def _start(self, reset_db: bool = False):
        env = os.environ.copy()
        env["HANDSHAKE_TTL"] = str(TEST_TTL)
        env["DB_PATH"] = DB_PATH

        if reset_db and Path(DB_PATH).exists():
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
        self._start(reset_db=False)

    def _issue(self, operator_id: str, tier: str) -> str:
        resp = requests.post(
            f"{BASE_URL}/handshake",
            json={"operator_id": operator_id, "tier": tier},
            timeout=5,
        )
        return resp.json()["token_id"]

    def _action(self, action_type: str, tier: str, tokens=None, payload=None) -> dict:
        body = {
            "action_type": action_type,
            "tier": tier,
            "payload": payload or {},
        }
        if tokens:
            body["handshake_tokens"] = tokens
        resp = requests.post(f"{BASE_URL}/action", json=body, timeout=5)
        return resp.json()

    def _pass(self, name: str, detail: str = ""):
        self.passed.append(name)
        print(f"  ✅ {name}" + (f" — {detail}" if detail else ""))

    def _fail(self, name: str, detail: str = ""):
        self.failed.append(name)
        print(f"  ❌ {name}" + (f" — {detail}" if detail else ""))

    def test_1_replay_attack(self):
        print("\n[1] Replay Attack")
        token_id = self._issue("alice", "T3_HIGH")

        first = self._action("loan_approval", "T3_HIGH", [token_id])
        second = self._action("loan_approval", "T3_HIGH", [token_id])

        print(f"    First use:  {first['outcome']}")
        print(f"    Second use: {second['outcome']}")

        if first["outcome"] == "EXECUTED" and second["outcome"] == "BLOCKED":
            self._pass("replay_blocked")
        else:
            self._fail("replay_blocked", f"first={first['outcome']} second={second['outcome']}")

    def test_2_token_expiry(self):
        print(f"\n[2] Token Expiry (TTL={TEST_TTL}s)")
        token_id = self._issue("alice", "T3_HIGH")
        time.sleep(TEST_TTL + 1)

        result = self._action("loan_approval", "T3_HIGH", [token_id])
        print(f"    Outcome: {result['outcome']}")

        if result["outcome"] == "BLOCKED":
            self._pass("expiry_enforced")
        else:
            self._fail("expiry_enforced", str(result))

    def test_3_tier_escalation(self):
        print("\n[3] Tier Escalation")
        token_id = self._issue("alice", "T2_SENSITIVE")
        result = self._action("high_risk_trade", "T3_HIGH", [token_id])

        print(f"    T2-token T3-action outcome: {result['outcome']}")

        if result["outcome"] == "BLOCKED":
            self._pass("tier_escalation_blocked")
        else:
            self._fail("tier_escalation_blocked", str(result))

    def test_4_chain_tampering(self):
        print("\n[4] Ledger Tampering")

        token_id = self._issue("alice", "T3_HIGH")
        self._action("test_action", "T3_HIGH", [token_id])

        before = requests.get(f"{BASE_URL}/ledger/verify", timeout=5).json()
        print(f"    Before tamper: valid={before['valid']} count={before.get('count', 0)}")

        self._stop()
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT seq FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        if row:
            conn.execute("UPDATE ledger SET outcome='TAMPERED' WHERE seq=?", (row[0],))
            conn.commit()
        conn.close()

        self._restart()
        after = requests.get(f"{BASE_URL}/ledger/verify", timeout=5).json()
        print(f"    After tamper: valid={after['valid']}")

        if not after["valid"]:
            self._pass("tamper_detected")
        else:
            self._fail("tamper_detected", "chain reported valid after DB edit")

    def test_5_race_condition(self):
        print("\n[5] Race Condition (10 concurrent requests, 1 token)")
        token_id = self._issue("alice", "T3_HIGH")
        outcomes = []
        errors = []

        def send(i):
            try:
                resp = requests.post(
                    f"{BASE_URL}/action",
                    json={
                        "action_type": "fast_trade",
                        "tier": "T3_HIGH",
                        "payload": {"thread": i},
                        "handshake_tokens": [token_id],
                    },
                    timeout=5,
                )
                outcomes.append(resp.json()["outcome"])
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=send, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        executed = outcomes.count("EXECUTED")
        blocked = outcomes.count("BLOCKED")

        print(f"    Outcomes: {executed} EXECUTED, {blocked} BLOCKED, {len(errors)} errors")

        if executed == 1 and blocked == 9 and not errors:
            self._pass("race_condition_atomic")
        else:
            self._fail(
                "race_condition_atomic",
                f"executed={executed} blocked={blocked} errors={len(errors)}",
            )

    def test_6_t4_multi_party(self):
        print("\n[6] T4 Multi-Party Requirement")

        t1 = self._issue("alice", "T4_IRREVERSIBLE")
        r1 = self._action("irreversible", "T4_IRREVERSIBLE", [t1])

        t2 = self._issue("alice", "T4_IRREVERSIBLE")
        t3 = self._issue("alice", "T4_IRREVERSIBLE")
        r2 = self._action("irreversible", "T4_IRREVERSIBLE", [t2, t3])

        t4 = self._issue("alice", "T4_IRREVERSIBLE")
        t5 = self._issue("bob", "T4_IRREVERSIBLE")
        r3 = self._action("irreversible", "T4_IRREVERSIBLE", [t4, t5])

        print(f"    Single token (Alice):     {r1['outcome']}")
        print(f"    Two tokens (Alice/Alice): {r2['outcome']}")
        print(f"    Two tokens (Alice/Bob):   {r3['outcome']}")

        if r1["outcome"] == "BLOCKED" and r2["outcome"] == "BLOCKED" and r3["outcome"] == "EXECUTED":
            self._pass("t4_multi_party")
        else:
            self._fail("t4_multi_party")

    def test_7_signature_verification(self):
        print("\n[7] Signature Verification (external verify with public key)")
        resp = requests.post(
            f"{BASE_URL}/handshake",
            json={"operator_id": "alice", "tier": "T3_HIGH"},
            timeout=5,
        ).json()

        token_id = resp["token_id"]
        sig_hex = resp["signature"]
        pub_hex = resp["pubkey"]

        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT operator_id, tier, issued_at, expires_at, nonce FROM handshakes WHERE token_id=?",
            (token_id,),
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
                "token_id": token_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        vk = VerifyKey(pub_hex, encoder=HexEncoder)

        try:
            vk.verify(payload, bytes.fromhex(sig_hex))
        except Exception as exc:
            self._fail("signature_verification", f"verify failed: {exc}")
            return

        tampered = json.dumps(
            {
                "expires_at": row[3],
                "iss": "white-swan-cornerstone",
                "issued_at": row[2],
                "nonce": row[4],
                "operator_id": "eve",
                "tier": row[1],
                "token_id": token_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        try:
            vk.verify(tampered, bytes.fromhex(sig_hex))
            self._fail("signature_verification", "tampered payload verified")
        except Exception:
            self._pass("signature_verification")

    def test_8_handshake_tampering(self):
        print("\n[8] Handshake Record Tampering")
        resp = requests.post(
            f"{BASE_URL}/handshake",
            json={"operator_id": "alice", "tier": "T3_HIGH"},
            timeout=5,
        ).json()
        token_id = resp["token_id"]

        self._stop()
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE handshakes SET operator_id='eve' WHERE token_id=?", (token_id,))
        conn.commit()
        conn.close()
        self._restart()

        result = self._action("sensitive_op", "T3_HIGH", [token_id])
        print(f"    Use tampered token: {result['outcome']}")

        if result["outcome"] == "BLOCKED":
            self._pass("handshake_tampering_detected")
        else:
            self._fail("handshake_tampering_detected", "tampered token was accepted")

    def test_9_restart_persistence(self):
        print("\n[9] Restart Persistence")
        pub_before = requests.get(f"{BASE_URL}/pubkey/handshake", timeout=5).json()["pubkey"]
        token_id = self._issue("alice", "T3_HIGH")

        self._stop()
        time.sleep(0.5)
        self._start()

        pub_after = requests.get(f"{BASE_URL}/pubkey/handshake", timeout=5).json()["pubkey"]
        result = self._action("loan_approval", "T3_HIGH", [token_id])

        print(f"    Public key unchanged: {pub_before == pub_after}")
        print(f"    Pre-restart token outcome: {result['outcome']}")

        if pub_before == pub_after and result["outcome"] == "EXECUTED":
            self._pass("restart_persistence")
        else:
            self._fail("restart_persistence")

    def report(self):
        total = len(self.passed) + len(self.failed)
        print("\n" + "=" * 65)
        print(f"ADVERSARIAL RESULTS {len(self.passed)}/{total} passed")
        print("=" * 65)

        if self.passed:
            print("\n✅ Passed:")
            for test in self.passed:
                print(f"   {test}")

        if self.failed:
            print("\n❌ Failed:")
            for test in self.failed:
                print(f"   {test}")

        return not self.failed

    def run(self):
        print("\n🔐 WHITE SWAN OS — ADVERSARIAL TESTING SUITE v2.1")
        print("=" * 65)

        self._start(reset_db=True)

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
                time.sleep(1)
        finally:
            self._stop()
            for file in Path(".").glob("test_cornerstone.db*"):
                file.unlink(missing_ok=True)

        return self.report()


if __name__ == "__main__":
    suite = AdversarialSuite()
    success = suite.run()
    sys.exit(0 if success else 1)
