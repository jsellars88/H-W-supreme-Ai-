#!/usr/bin/env python3
"""stress_test.py — WhiteSwan Forensic Ledger v0.4 Concurrency Stress Test."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import threading
import time

from decision_ledger import DecisionLedger
from ledger_writer import LedgerWriter

SCOPES = [
    "diagnostic_inference",
    "alert_escalation",
    "data_export",
    "sensing",
    "medical_intervention",
    "loan_approval",
]
TIERS = ["T1_SAFE", "T2_ESCALATION", "T3_INTERVENTION", "T4_IRREVERSIBLE"]
OPS = [f"operator-{i:04d}" for i in range(20)]


def demo_ownership_violation() -> bool:
    print("  [Phase 0] Thread ownership enforcement...")
    ledger = DecisionLedger(db_path=":memory:")
    caught = threading.Event()

    def bad_write():
        try:
            ledger.record(
                decision_input={"action": "bypass_attempt"},
                model_version="v1",
                model_fingerprint="fp",
                policy_version="p1",
                operator_id="bad_actor",
                risk_tier="T1",
            )
            print("  ✗ Cross-thread write NOT blocked — enforcement broken")
        except RuntimeError as e:
            print(f"  ✓ Blocked: {str(e)[:80]}...")
            caught.set()

    t = threading.Thread(target=bad_write)
    t.start()
    t.join()
    ledger.close()

    return caught.is_set()


def run_concurrent(
    writer: LedgerWriter, n_threads: int, n_writes: int
) -> tuple[list[str], list[str], float]:
    writes_per_thread = n_writes // n_threads
    all_ids: list[str] = []
    all_errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(tid: int):
        barrier.wait()
        local_ids: list[str] = []
        local_errors: list[str] = []
        for i in range(writes_per_thread):
            try:
                rec = writer.submit(
                    decision_input={
                        "action": f"action_{secrets.token_hex(4)}",
                        "thread": tid,
                        "seq": i,
                        "model": "ws-kernel-v3.4",
                        "nonce": secrets.token_hex(8),
                    },
                    model_version="credit-scoring-v2.1",
                    model_fingerprint=hashlib.sha256(f"weights-t{tid}-i{i}".encode()).hexdigest()[
                        :64
                    ],
                    policy_version="lending-policy-2026-03",
                    operator_id=OPS[(tid * 7 + i) % len(OPS)],
                    risk_tier=TIERS[i % len(TIERS)],
                    nonce_scope=SCOPES[(tid + i) % len(SCOPES)],
                )
                local_ids.append(rec.decision_id)
            except Exception as e:
                local_errors.append(f"t{tid}:i{i} → {e}")

        with lock:
            all_ids.extend(local_ids)
            all_errors.extend(local_errors)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    start = time.perf_counter()
    for t in threads:
        t.start()

    total = n_threads * writes_per_thread
    while any(t.is_alive() for t in threads):
        done = len(all_ids)
        pct = int((done / total) * 42) if total else 42
        bar = "█" * pct + "░" * (42 - pct)
        print(f"\r  [{bar}] {done:>6}/{total}", end="", flush=True)
        time.sleep(0.08)

    for t in threads:
        t.join()

    elapsed = time.perf_counter() - start
    print(f"\r  [{'█' * 42}] {len(all_ids):>6}/{total}  ✓", flush=True)
    return all_ids, all_errors, elapsed


def run_verify(writer: LedgerWriter, expected: int):
    chain = writer.verify_chain()
    ok = chain.get("valid") and chain.get("record_count") == expected
    return ok, chain


def run_sample_verify(writer: LedgerWriter, all_ids: list[str], sample_n: int = 5) -> bool:
    import os
    import tempfile

    from verify_evidence import verify

    pubkey = writer.pubkey_hex
    if not pubkey:
        return False

    sample = all_ids[:sample_n] + all_ids[-sample_n:]
    all_ok = True

    for did in sample:
        proof = writer.export_proof(did)
        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(proof, f)
            ok = verify(tmp, pubkey, quiet=True)
            print(f"  {'✓' if ok else '✗'} proof verify: {did[:16]}...")
            all_ok = all_ok and ok
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser(description="WhiteSwan Ledger Stress Test v0.4")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--writes", type=int, default=10000)
    ap.add_argument("--output", type=str, default=None)
    ap.add_argument("--rekor", action="store_true", help="Enable Rekor anchoring")
    args = ap.parse_args()

    total = (args.writes // args.threads) * args.threads

    print("\n" + "═" * 66)
    print("  WHITESWAN FORENSIC LEDGER v0.4 — STRESS TEST")
    print("═" * 66)
    print(f"  Threads    : {args.threads}")
    print(f"  Writes     : {total:,}")
    print(f"  Rekor mode : {'offline/mock' if args.rekor else 'disabled'}")
    print("═" * 66 + "\n")

    p0_ok = demo_ownership_violation()
    print()

    print(f"  [Phase 1] {args.threads} threads firing simultaneously...")
    writer = LedgerWriter(db_path=":memory:", enable_rekor=args.rekor, rekor_offline=True)

    all_ids, all_errors, elapsed = run_concurrent(writer, args.threads, args.writes)
    wps = total / elapsed if elapsed > 0 else 0

    print(f"\n  [Phase 2] Verifying full chain ({total:,} entries)...")
    p2_ok, chain = run_verify(writer, total)
    print(
        f"  {'✓' if p2_ok else '✗'} chain_valid={chain.get('valid')} "
        f"record_count={chain.get('record_count')} key_ids={chain.get('key_ids_seen')}"
    )

    print("\n  [Phase 3] Sampling evidence packets (verify_evidence)...")
    p3_ok = run_sample_verify(writer, all_ids, sample_n=3)
    writer.close()

    ok_writes = len(all_ids) == total
    ok_unique = len(set(all_ids)) == total
    ok_errors = len(all_errors) == 0
    verdict = all([p0_ok, ok_writes, p2_ok, ok_unique, ok_errors, p3_ok])

    print("\n" + "═" * 66)
    print("  RESULTS")
    print("═" * 66)
    print(f"  {'✓' if p0_ok else '✗'} Phase 0: ownership enforce   BLOCKED")
    print(
        f"  {'✓' if ok_writes else '✗'} Writes completed             {len(all_ids):,} / {total:,}"
    )
    print(f"  ✓ Duration                     {elapsed:.3f}s")
    print(f"  ✓ Throughput                   {wps:,.0f} writes/sec")
    print(
        f"  {'✓' if p2_ok else '✗'} Chain integrity              "
        f"{'VERIFIED' if p2_ok else chain.get('message', 'FAILED')}"
    )
    print(
        f"  {'✓' if p2_ok else '✗'} Chain length                 {chain.get('record_count', 0):,}"
    )
    print(f"  {'✓' if ok_unique else '✗'} Unique decision_ids          {len(set(all_ids)):,}")
    print(
        f"  {'✓' if ok_errors else '✗'} Write errors                 "
        f"{len(all_errors) if all_errors else 'None'}"
    )
    print(f"  {'✓' if p3_ok else '✗'} Evidence packet verify       SAMPLED 6 RECORDS")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "schema": "ws-stress-report-v0.4",
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "params": {"threads": args.threads, "writes": total},
                    "results": {
                        "ownership_enforced": p0_ok,
                        "writes_completed": len(all_ids),
                        "writes_expected": total,
                        "duration_seconds": round(elapsed, 3),
                        "writes_per_second": round(wps, 1),
                        "chain_valid": chain.get("valid"),
                        "chain_length": chain.get("record_count"),
                        "unique_ids": len(set(all_ids)),
                        "errors": all_errors[:20],
                        "verdict": "PASS" if verdict else "FAIL",
                    },
                },
                f,
                indent=2,
            )
        print(f"\n  Report written → {args.output}")

    print("═" * 66)
    print(f"  VERDICT: {'✓  ALL CHECKS PASSED' if verdict else '✗  CHECKS FAILED'}")
    print("═" * 66 + "\n")

    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
