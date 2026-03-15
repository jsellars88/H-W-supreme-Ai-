# White Swan OS — Cornerstone v2.0

**Control-Grade Governance Reference Implementation**  
Holmes & Watson Supreme AI™

-----

## What This Is

A reference implementation demonstrating one invariant:

> **No high-tier action executes without valid human authority. Evidence is written before the action runs.**

This is a working prototype — not a production system. It does exactly what it claims and nothing more.

-----

## What This Demonstrates

| Property                                     | Status |
|----------------------------------------------|--------|
| T0/T1 actions pass without token             | ✅     |
| T2/T3/T4 blocked without valid token         | ✅     |
| T4 requires two distinct operators           | ✅     |
| Ed25519 signatures verified on every consume | ✅     |
| Keys persist across restarts                 | ✅     |
| Atomic single-use token consumption          | ✅     |
| Ledger entry written before execution        | ✅     |
| Hash-chain tamper detection                  | ✅     |
| Handshake record tampering detected          | ✅     |
| All 9 adversarial tests passing              | ✅     |

## What This Is Not

- Not production-ready
- Not audited
- Not scalable beyond single-instance SQLite
- Not a bearer-token system (tokens are DB-backed approval records, not self-contained JWTs)

**Honest framing:** Approval records are Ed25519-signed and persisted. Execution consumes a server-validated authority record. Signature is re-verified at consume time from the stored payload.

-----

## Quick Start

```bash
pip install -r requirements.txt
python cornerstone.py
```

Test TTL override for fast testing:

```bash
HANDSHAKE_TTL=2 python cornerstone.py
```

-----

## Adversarial Tests

```bash
python adversarial_test.py
```

Runs 9 tests against a live server instance:

1. Replay attack — token reuse
2. Token expiry — time-limited enforcement
3. Tier escalation — T2 token for T3 action
4. Ledger tampering — direct DB edit detected
5. Race condition — 10 concurrent requests, 1 token
6. T4 multi-party — requires 2 distinct operators
7. Signature verification — external verify with public key
8. Handshake tampering — edited DB record rejected
9. Restart persistence — keys and state survive restart

-----

## API

| Method | Endpoint              | Description                          |
|--------|-----------------------|--------------------------------------|
| POST   | `/action`             | Execute a governed action            |
| POST   | `/handshake`          | Issue authority token                |
| GET    | `/ledger`             | Evidence chain                       |
| GET    | `/ledger/verify`      | Chain integrity                      |
| GET    | `/ledger/record/{id}` | Single record with full signature    |
| GET    | `/pubkey/handshake`   | Public key for external verification |
| GET    | `/pubkey/ledger`      | Ledger public key                    |
| GET    | `/health`             | System status                        |

-----

## Architecture Decisions

**Why DB-backed approval records, not bearer tokens?**  
Easier revocation, stronger server-side authority enforcement, no token leakage risk. Verification is always server-authoritative.

**Why SQLite?**  
Simplicity. This is a reference implementation. Production would use PostgreSQL with explicit row-locking (`SELECT FOR UPDATE`).

**Why not RETURNING clause?**  
SQLite 3.35+ supports it, but the atomic consume here uses `UPDATE rowcount check` which works on any SQLite version and is simpler to reason about.

**Why Ed25519 over HMAC?**  
Asymmetric. Public key can be distributed to external verifiers. Ledger records and handshake records are independently verifiable by anyone with the public key.

-----

## File Layout

```text
cornerstone.py         # server + governance kernel + ledger
adversarial_test.py    # 9-test adversarial suite
requirements.txt       # dependencies
README.md              # this file
handshake_private.key  # generated on first run
handshake_public.key   # distribute to external verifiers
ledger_private.key     # generated on first run
ledger_public.key      # distribute to external verifiers
cornerstone.db         # SQLite evidence store
```

-----

© 2026 Holmes & Watson Supreme AI™ — Proprietary
