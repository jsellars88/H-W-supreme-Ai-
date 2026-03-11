# Holmes & Watson Supreme AI™

## WhiteSwan OS — Constitutional AI Governance Middleware

> **We don’t govern AI with policy. We govern it with proof.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/kernel-v3.5-brightgreen)](whiteswan/whiteswan_governance_kernel_v3_4.py)
[![Tests](https://img.shields.io/badge/tests-122%20passing-brightgreen)](tests/)

-----

## What This Is

**WhiteSwan OS** is a constitutional AI governance middleware layer that sits *above* existing AI model providers — Claude, GPT-4, Gemini, Grok, DeepSeek — and enforces runtime governance through cryptographic proof rather than soft policy controls.

It does not replace your AI model. It governs it.

Every AI decision passing through the system is:

- Evaluated against 23 constitutional invariants before execution
- Signed with Ed25519 and hash-chained into a tamper-evident forensic ledger
- Assigned a cryptographic capsule ID traceable to the originating request
- Optionally anchored to the Rekor public transparency log for third-party timestamp proof

The result is an AI decision trail that is **court-defensible, audit-ready, and independently verifiable** with no dependency on the AI provider to prove what happened.

-----

## Who This Is For

Primary targets are compliance officers and heads of AI risk at regulated enterprises — financial services, healthcare, legal, defense — facing mandatory regulatory deadlines under the **EU AI Act**, **NIST AI RMF**, and related frameworks.

If your organization deploys AI and needs to answer the question *“what did your AI do, why, and can you prove it?”* — this is the infrastructure layer that makes that answer possible.

-----

## Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   YOUR APPLICATION                      │
└─────────────────────┬───────────────────────────────────┘
                      │ every AI request
┌─────────────────────▼───────────────────────────────────┐
│            WhiteSwan Governance Kernel v3.5             │
│  ┌─────────────────────────────────────────────────┐    │
│  │  23 Constitutional Invariants                   │    │
│  │  • Evaluated pre- and post-inference            │    │
│  │  • Hard refusal on invariant breach             │    │
│  │  • Escalation routing via Recusa Nexus          │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Decision Ledger (Ed25519 + Hash Chain)         │    │
│  │  • Canonical JSON signing                       │    │
│  │  • SQLite WAL+FULL durability                   │    │
│  │  • Optional Rekor public anchoring              │    │
│  │  • Standalone regulator verifier                │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────┘
                      │ governed request
         ┌────────────┼────────────────┐
         ▼            ▼                ▼
      Claude        GPT-4           Gemini
    (or any AI model provider)
```

-----

## Key Properties

|Property                |How It Is Enforced                                                                     |
|------------------------|---------------------------------------------------------------------------------------|
|Tamper evidence         |Ed25519 signature + SHA-256 hash chain — any modification breaks verification          |
|Decision ordering       |Each record stores the hash of its predecessor — gaps are detectable                   |
|Non-repudiation         |Signing key tracked with `key_id = sha256(pubkey)[:16]` stored in every record         |
|Write serialization     |Single writer thread owns the signing key and DB transaction boundary                  |
|Durability              |SQLite `PRAGMA journal_mode=WAL` + `PRAGMA synchronous=FULL`                           |
|Canonical encoding      |All records serialized to canonical JSON before signing — no encoding ambiguity        |
|Independent verification|`verify_evidence.py` runs with no server, no database — public key and JSON packet only|
|Public anchoring        |Optional Rekor transparency log — third-party-verifiable timestamp proof               |

-----

## What This System Does NOT Claim

These boundaries are architectural features, not omissions:

- **Does not guarantee the AI decision was correct** — only that it was recorded faithfully
- **Does not guarantee operator identity** — key custody is the operator’s responsibility
- **Does not provide confidentiality** — the ledger is a tamper-evident log, not an encrypted vault
- **Does not guarantee completeness** — only records what passes through the kernel

-----

## Repository Structure

```
whiteswan/
  whiteswan_governance_kernel_v3_4.py # Core governance kernel — 23 invariants, runtime enforcement
  whiteswan_api_v35.py                # REST API wrapper — exposes kernel over HTTP
  kernel_v35.py                       # Kernel v3.5 with hardened invariant set

tests/
  integration_test_v35.py             # Full integration test suite
  test_whiteswan_governance_kernel.py # Governance kernel unit tests
  test_rekor_anchor.py                # Rekor anchor tests

app/
  main.py                             # Flask dashboard — governance status cards
  templates/                          # Jinja2 templates

data/
  posts.json                          # Dashboard content data

.github/workflows/                    # CI pipeline

requirements.txt                      # Python dependencies
render.yaml                           # Render deployment config
```

-----

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the governance kernel API
python whiteswan/whiteswan_api_v35.py

# Run all tests
pytest tests/

# Run the Flask governance dashboard
python app/main.py
# -> http://localhost:8080
```

-----

## Decision Ledger: Standalone Verification

The forensic Decision Ledger is independently verifiable by a regulator or auditor with no access to the originating system.

```bash
# Verify a single evidence packet
python verify_evidence.py packet.json --pubkey <hex_pubkey>

# Verify with Rekor public timestamp proof
python verify_evidence.py packet.json --pubkey <hex_pubkey> --rekor

# Verify chain ordering against a predecessor record
python verify_evidence.py packet.json --pubkey <hex_pubkey> --predecessor prev.json
```

Exit `0` = verified. Exit `1` = failed. No database. No server. No network required (unless `--rekor`).

-----

## Stress Test Results (Ledger v0.4)

```
Threads:    50
Writes:     10,000
Duration:   7.976s
Throughput: 1,254 writes/sec

Phase 0: cross-thread write BLOCKED        OK
Phase 1: 10,000/10,000 writes completed    OK
Phase 2: chain integrity VERIFIED          OK
Phase 3: evidence packets independently
         verified by verify_evidence.py    OK

VERDICT: ALL CHECKS PASSED
```

-----

## Compliance Posture

**One-line compliance statement:**

> All writes serialized through single writer thread owning signing key and DB transaction boundary. Each decision recorded as canonical JSON payload, signed with Ed25519, hash-chained for ordering. Chain integrity verified with reproducible 10,000-record concurrent stress test. Optional Rekor anchoring provides public third-party-verifiable timestamp proof.

**Relevant regulatory frameworks:**

- EU AI Act (Article 9 — Risk Management; Article 12 — Record Keeping)
- NIST AI RMF (Govern, Map, Measure, Manage functions)
- ISO 42001 (AI Management System requirements)
- GDPR Article 22 (Automated decision-making accountability)

-----

## Cross-Model Validation

WhiteSwan OS architecture has been independently validated across:

**Claude · GPT-4 · Gemini · Grok · DeepSeek · Perplexity · Microsoft Copilot**

Convergent validation across independent AI systems confirms technical feasibility and architectural soundness of the governance primitives.

-----

## About Holmes & Watson Supreme AI™

Holmes & Watson Supreme AI is building the governance infrastructure layer for regulated AI deployment. WhiteSwan OS is not a competing AI model — it is the constitutional layer that makes existing AI models auditable, insurable, and compliant with mandatory regulatory frameworks.

**Founder & Architect:** Jake Sellars
**Status:** Architecture validated. Production primitives implemented and tested.

-----

## License

MIT — see <LICENSE>
