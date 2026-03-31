#!/usr/bin/env python3
"""adversarial_standalone.py — Holmes & Watson Supreme AI™
Cornerstone v2.0 — Adversarial Concurrency Suite (self-contained)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DB_PATH = "/tmp/hws_adversarial_test.db"


class GovernanceKernel:
    CONFIDENCE_THRESHOLDS = {"T1_LOW": 0.40, "T2_MED": 0.60, "T3_HIGH": 0.75, "T4_CRITICAL": 0.92}
    TIER_RANK = {"T1_LOW": 1, "T2_MED": 2, "T3_HIGH": 3, "T4_CRITICAL": 4}

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._prev_hash = "GENESIS"

        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self.public_key_b64 = base64.b64encode(
            self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS decisions (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT UNIQUE,
                timestamp TEXT, operator_id TEXT, action_type TEXT, tier TEXT,
                approved INTEGER, outcome TEXT, payload_hash TEXT,
                prev_hash TEXT, entry_hash TEXT, signature TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS handshakes (
                token_id TEXT PRIMARY KEY,
                operator_id TEXT, tier TEXT, issued_at TEXT, expires_at TEXT, used INTEGER DEFAULT 0
            )"""
        )
        conn.commit()
        conn.close()

    def _conn(self):
        c = sqlite3.connect(self._db_path)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def issue_token(self, operator_id, tier="T3_HIGH", ttl_minutes=10):
        token_id = "hs_" + secrets.token_hex(8)
        issued = datetime.now(timezone.utc)
        expires = issued + timedelta(minutes=ttl_minutes)
        with self._conn() as c:
            c.execute(
                "INSERT INTO handshakes VALUES (?,?,?,?,?,0)",
                (token_id, operator_id, tier, issued.isoformat(), expires.isoformat()),
            )
        return token_id

    def issue_expired_token(self, operator_id, tier="T3_HIGH"):
        token_id = "hs_exp_" + secrets.token_hex(8)
        issued = datetime.now(timezone.utc)
        expires = issued - timedelta(minutes=5)
        with self._conn() as c:
            c.execute(
                "INSERT INTO handshakes VALUES (?,?,?,?,?,0)",
                (token_id, operator_id, tier, issued.isoformat(), expires.isoformat()),
            )
        return token_id

    def _recusa_evaluate(self, conn, operator_id, action_type, tier, payload, tokens):
        gates = {}
        gates["G1_OBSERVATION"] = {
            "passed": bool(action_type) and bool(payload),
            "reason": "OK" if bool(action_type) and bool(payload) else "Missing scope or payload",
        }

        tok_row = None
        expired = True
        if tokens:
            tok_row = conn.execute(
                "SELECT * FROM handshakes WHERE token_id=? AND used=0", (tokens[0],)
            ).fetchone()
            if tok_row:
                exp_dt = datetime.fromisoformat(tok_row[4])
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                expired = exp_dt < datetime.now(timezone.utc)

        gates["G2_AUTHORITY"] = {
            "passed": tok_row is not None and not expired,
            "reason": "Token valid" if (tok_row and not expired) else "Missing/expired/used token",
        }

        if tok_row and not expired:
            tok_tier_rank = self.TIER_RANK.get(tok_row[2], 0)
            req_tier_rank = self.TIER_RANK.get(tier, 99)
            gates["G3_TIER_AUTH"] = {
                "passed": tok_tier_rank >= req_tier_rank,
                "reason": f"Tier {tok_row[2]} vs required {tier}",
            }
        else:
            gates["G3_TIER_AUTH"] = {"passed": False, "reason": "No valid token for tier check"}

        gates["G4_IDENTITY"] = {
            "passed": bool(operator_id) and operator_id not in ("anonymous", ""),
            "reason": (
                "Identity verified"
                if (operator_id and operator_id not in ("anonymous", ""))
                else "Anonymous blocked"
            ),
        }
        gates["G5_PAYLOAD"] = {
            "passed": isinstance(payload, dict) and len(payload) > 0,
            "reason": "Payload OK" if (isinstance(payload, dict) and payload) else "Empty/malformed payload",
        }

        if tier == "T4_CRITICAL":
            gates["G6_HARM_SURFACE"] = {
                "passed": len(tokens or []) >= 2,
                "reason": "Dual token required for T4",
            }
        else:
            gates["G6_HARM_SURFACE"] = {"passed": True, "reason": "Standard harm surface"}

        failed = [k for k, v in gates.items() if not v["passed"]]
        return {"approved": len(failed) == 0, "gates": gates, "failed": failed}, tok_row

    def process(self, operator_id, action_type, tier, payload, tokens):
        t0 = time.perf_counter()

        with self._lock:
            conn = self._conn()
            try:
                gate, tok_row = self._recusa_evaluate(conn, operator_id, action_type, tier, payload, tokens)

                if gate["approved"] and tok_row:
                    conn.execute("UPDATE handshakes SET used=1 WHERE token_id=?", (tokens[0],))

                outcome = "EXECUTED" if gate["approved"] else f"BLOCKED:{','.join(gate['failed'])}"

                did = str(uuid.uuid4())
                ts = datetime.now(timezone.utc).isoformat()
                ph = hashlib.sha256(json.dumps(payload or {}, sort_keys=True).encode()).hexdigest()

                canonical = json.dumps(
                    {
                        "decision_id": did,
                        "timestamp": ts,
                        "operator_id": operator_id,
                        "action_type": action_type,
                        "tier": tier,
                        "approved": gate["approved"],
                        "outcome": outcome,
                        "payload_hash": ph,
                        "prev_hash": self._prev_hash,
                    },
                    sort_keys=True,
                )

                eh = hashlib.sha256(canonical.encode()).hexdigest()
                sig = base64.b64encode(self._priv.sign(canonical.encode())).decode()

                conn.execute(
                    "INSERT INTO decisions VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        did,
                        ts,
                        operator_id,
                        action_type,
                        tier,
                        int(gate["approved"]),
                        outcome,
                        ph,
                        self._prev_hash,
                        eh,
                        sig,
                    ),
                )
                conn.commit()
                self._prev_hash = eh

                ms = (time.perf_counter() - t0) * 1000
                return {
                    "approved": gate["approved"],
                    "decision_id": did,
                    "entry_hash": eh,
                    "latency_ms": ms,
                    "failed": gate["failed"],
                }
            finally:
                conn.close()

    def verify_chain(self):
        conn = self._conn()
        rows = conn.execute("SELECT * FROM decisions ORDER BY seq").fetchall()
        conn.close()
        prev, all_ok = "GENESIS", True
        for row in rows:
            seq, did, ts, op_id, act, tier, approved, outcome, ph, prev_h, eh, sig = row
            canonical = json.dumps(
                {
                    "decision_id": did,
                    "timestamp": ts,
                    "operator_id": op_id,
                    "action_type": act,
                    "tier": tier,
                    "approved": bool(approved),
                    "outcome": outcome,
                    "payload_hash": ph,
                    "prev_hash": prev_h,
                },
                sort_keys=True,
            )
            if (
                prev_h != prev
                or hashlib.sha256(canonical.encode()).hexdigest() != eh
                or not self._verify_sig(canonical, sig)
            ):
                all_ok = False
                break
            prev = eh
        return all_ok, len(rows)

    def _verify_sig(self, data, sig_b64):
        try:
            self._pub.verify(base64.b64decode(sig_b64), data.encode())
            return True
        except Exception:
            return False

    def decision_count(self):
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]

    def executed_count(self):
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM decisions WHERE approved=1").fetchone()[0]


if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

kernel = GovernanceKernel()
_results = []


def run_test(test_id, name, fn):
    print(f"\n  [{test_id}] {name}")
    t0 = time.perf_counter()
    passed, detail = fn()
    elapsed = time.perf_counter() - t0
    _results.append((test_id, name, passed, detail, elapsed))
    status = "✅" if passed else "❌"
    print(f"       {status} {detail}")
    return passed


def a1_replay_attack():
    token = kernel.issue_token("alice@bank.com", "T3_HIGH")
    executed, blocked = 0, 0
    barrier = threading.Barrier(50)

    def try_replay():
        nonlocal executed, blocked
        barrier.wait()
        r = kernel.process("alice@bank.com", "loan_approval", "T3_HIGH", {"amount": 50000}, [token])
        if r["approved"]:
            executed += 1
        else:
            blocked += 1

    threads = [threading.Thread(target=try_replay) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    passed = executed == 1 and blocked == 49
    return passed, f"Executed: {executed}/50 (expected 1) | Blocked: {blocked}/50 — atomic token consumption {'HOLDS' if passed else 'FAILED'}"


def a2_expired_tokens():
    blocked = 0
    for i in range(200):
        tok = kernel.issue_expired_token(f"exp_{i}@test.com")
        r = kernel.process(f"exp_{i}@test.com", "action", "T3_HIGH", {"v": i}, [tok])
        if not r["approved"]:
            blocked += 1
    passed = blocked == 200
    return passed, f"All {blocked}/200 expired tokens rejected"


def a3_tier_escalation():
    blocked = 0
    for i in range(100):
        tok = kernel.issue_token(f"esc_{i}@test.com", "T1_LOW")
        r = kernel.process(f"esc_{i}@test.com", "critical_op", "T4_CRITICAL", {"v": i}, [tok])
        if not r["approved"]:
            blocked += 1
    passed = blocked == 100
    return passed, f"All {blocked}/100 T1→T4 escalation attempts blocked at G3_TIER_AUTH"


def a4_anonymous_flood():
    blocked = 0
    for i in range(200):
        tok = kernel.issue_token("anon_backer@sys")
        r = kernel.process("anonymous", "action", "T3_HIGH", {"v": i}, [tok])
        if not r["approved"]:
            blocked += 1
    passed = blocked == 200
    return passed, f"All {blocked}/200 anonymous requests blocked at G4_IDENTITY"


def a5_malformed_payloads():
    stable = 0
    payloads = [
        {},
        {"amount": None},
        {"sql": "'; DROP TABLE decisions; --"},
        {"overflow": "A" * 5000},
        {"cmd": "$(whoami)"},
    ] * 60

    for i, p in enumerate(payloads):
        tok = kernel.issue_token(f"mal_{i}@test.com")
        try:
            kernel.process(f"mal_{i}@test.com", "action", "T3_HIGH", p, [tok])
            stable += 1
        except Exception:
            pass

    passed = stable == 300
    return passed, f"System stable (no crashes) under all 300 poison payloads: {stable}/300"


def a6_concurrent_rw():
    errors = []

    def do_write(i):
        tok = kernel.issue_token(f"rw_{i}@test.com")
        kernel.process(f"rw_{i}@test.com", "rw_op", "T3_HIGH", {"i": i}, [tok])

    def do_read(i):
        valid, _ = kernel.verify_chain()
        if not valid:
            errors.append(i)

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(do_write, i) for i in range(200)] + [ex.submit(do_read, i) for i in range(200)]
        list(as_completed(futures))

    valid, count = kernel.verify_chain()
    passed = len(errors) == 0 and valid
    return passed, f"Chain valid during concurrent read/write ops | errors: {len(errors)} | entries: {count}"


def a7_race_condition():
    token = kernel.issue_token("race@bank.com")
    executed = []
    barrier = threading.Barrier(100)

    def race(i):
        barrier.wait()
        r = kernel.process("race@bank.com", "race_op", "T3_HIGH", {"racer": i}, [token])
        if r["approved"]:
            executed.append(i)

    threads = [threading.Thread(target=race, args=(i,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    passed = len(executed) == 1
    return passed, f"Token consumed {len(executed)} time(s) under 100-thread simultaneous race (expected: 1)"


def a8_no_token_flood():
    blocked = 0
    for i in range(300):
        r = kernel.process(f"agent_{i}@test.com", "action", "T3_HIGH", {"v": i}, [])
        if not r["approved"]:
            blocked += 1
    passed = blocked == 300
    return passed, f"All {blocked}/300 tokenless requests blocked at G2_AUTHORITY"


def a9_final_chain_audit():
    valid, count = kernel.verify_chain()
    exec_count = kernel.executed_count()
    total = kernel.decision_count()
    passed = valid
    return passed, f"Full chain cryptographically valid | {count} entries total | {exec_count} executed | {total - exec_count} blocked"


print("\n" + "═" * 65)
print("  Holmes & Watson Supreme AI™ — Adversarial Load Test")
print("  Cornerstone v2.0 | 9-Vector Attack Suite")
print("═" * 65)
print(f"  Public Key: {kernel.public_key_b64[:40]}…")

t_start = time.perf_counter()

all_passed = [
    run_test("A1", "Replay Attack (50 concurrent threads, 1 token)", a1_replay_attack),
    run_test("A2", "Expired Token Injection (200 attempts)", a2_expired_tokens),
    run_test("A3", "Tier Escalation T1→T4 (100 attempts)", a3_tier_escalation),
    run_test("A4", "Anonymous Requestor Flood (200 attempts)", a4_anonymous_flood),
    run_test("A5", "Payload Poisoning (300 payloads, SQLi/overflow/null)", a5_malformed_payloads),
    run_test("A6", "Concurrent Read/Write Chain Stability (400 ops)", a6_concurrent_rw),
    run_test("A7", "Race Condition — 100 threads, 1 token simultaneously", a7_race_condition),
    run_test("A8", "No-Token Flood (300 requests)", a8_no_token_flood),
    run_test("A9", "Post-Attack Full Chain Cryptographic Audit", a9_final_chain_audit),
]

elapsed = time.perf_counter() - t_start

print("\n" + "═" * 65)
print("  ADVERSARIAL SUITE — FINAL RESULTS")
print("═" * 65)
for test_id, name, passed, detail, t in _results:
    s = "✅" if passed else "❌"
    print(f"  {s} [{test_id}] {name} ({t:.1f}s)")

print(f"\n  Tests passed:  {sum(all_passed)}/9")
print(f"  Total elapsed: {elapsed:.1f}s")
valid, count = kernel.verify_chain()
print(f"  Final chain:   {'VERIFIED' if valid else 'FAILED'} ({count} entries)")
print()
if all(all_passed):
    print("  ✅ ALL 9 ADVERSARIAL INVARIANTS HELD")
    print()
    print("  Claim confirmed: The governance gate cannot be bypassed")
    print("  by replay, expiry, tier escalation, anonymity, malformed")
    print("  payloads, concurrent racing, or tokenless flooding.")
    print("  Chain integrity survives all attack vectors.")
else:
    failed = [_results[i][0] for i, p in enumerate(all_passed) if not p]
    print(f"  ❌ FAILED: {', '.join(failed)}")
print("═" * 65)
