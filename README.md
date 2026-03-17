# White Swan OS — Cornerstone v2.0

**Control-Grade Governance Reference Implementation**
Holmes & Watson Supreme AI™

-----

## What This Is

A reference implementation demonstrating one invariant:

> **No high-tier action executes without valid human authority. Evidence is written before the action runs.**

This is a working prototype — not a production system. It does exactly what it claims and nothing more.

-----

## Where This Applies

This system is built for environments where AI decisions must be:

- **Authorized before execution** — no action runs without a cryptographically signed approval record
- **Provable after execution** — every decision produces a tamper-evident ledger entry
- **Independently verifiable** — anyone with the public key can verify any record, with no access to the originating system

**Concrete scenarios:**

|Scenario                 |What the system enforces                                                                                       |
|-------------------------|---------------------------------------------------------------------------------------------------------------|
|AI credit approval       |T3 action blocked without valid operator handshake; approval signed and ledger-written before decision executes|
|Medical decision support |High-tier recommendations require dual-operator authorization; evidence written pre-execution                  |
|Autonomous system control|Every actuation command validated against authority record; tampered records rejected at consume time          |

If a decision cannot be proven, it does not execute.

-----

## What This Demonstrates

|Property                                    |Status|
|--------------------------------------------|------|
|T0/T1 actions pass without token            |✅     |
|T2/T3/T4 blocked without valid token        |✅     |
|T4 requires two distinct operators          |✅     |
|Ed25519 signatures verified on every consume|✅     |
|Keys persist across restarts                |✅     |
|Atomic single-use token consumption         |✅     |
|Ledger entry written before execution       |✅     |
|Hash-chain tamper detection                 |✅     |
|Handshake record tampering detected         |✅     |
|All 9 adversarial tests passing             |✅     |

-----

## What This Is Not

This is a reference implementation designed to demonstrate enforceable governance invariants before scaling to production infrastructure:

- Not yet scaled beyond single-instance SQLite
- Not yet externally audited
- Not a bearer-token system — tokens are DB-backed approval records, not self-contained JWTs
- Production path: PostgreSQL with `SELECT FOR UPDATE`, external HSM for key custody

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
1. Token expiry — time-limited enforcement
1. Tier escalation — T2 token for T3 action
1. Ledger tampering — direct DB edit detected
1. Race condition — 10 concurrent requests, 1 token
1. T4 multi-party — requires 2 distinct operators
1. Signature verification — external verify with public key
1. Handshake tampering — edited DB record rejected
1. Restart persistence — keys and state survive restart

-----

## How a Governed Decision Works

```
1. Operator issues handshake    POST /handshake
                                → Ed25519-signed approval record written to DB
                                → Token ID returned

2. Action submitted             POST /action  {token_id, action, tier}
                                → Governance kernel validates token exists
                                → Signature re-verified from stored payload
                                → Token consumed atomically (UPDATE rowcount check)
                                → Ledger entry written and hash-chained
                                → Action executes

3. Independent verification     GET /ledger/record/{id}
                                → Returns full record with signature
                                → Anyone with ledger_public.key can verify
                                → No server access required for verification
```

This is the difference between logging what happened and proving it was authorized before it ran.

-----

## API

|Method|Endpoint             |Description                      |
|------|---------------------|---------------------------------|
|POST  |`/action`            |Execute a governed action        |
|POST  |`/handshake`         |Issue authority token            |
|GET   |`/ledger`            |Evidence chain                   |
|GET   |`/ledger/verify`     |Chain integrity                  |
|GET   |`/ledger/record/{id}`|Single record with full signature|
|GET   |`/health`            |System status                    |

**Independent verification — no server required:**

```bash
# Verify any record using only the public key
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import json, hashlib, base64

record = json.load(open('record.json'))
pubkey = load_pem_public_key(open('ledger_public.key', 'rb').read())
payload = json.dumps(record['payload'], sort_keys=True).encode()
pubkey.verify(base64.b64decode(record['signature']), payload)
print('VERIFIED')
"
```

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

```
cornstone.py          # server + governance kernel
adversarial_test.py     # 9-test adversarial suite
requirements.txt        # dependencies
README.md               # this file
handshake_private.key   # generated on first run
handshake_public.key    # distribute to external verifiers
ledger_private.key      # generated on first run
ledger_public.key       # distribute to external verifiers
cornerstone.db          # SQLite evidence store
```

-----

© 2026 Holmes & Watson Supreme AI™ — Proprietary