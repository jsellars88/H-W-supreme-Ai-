# WhiteSwan OS — AI Governance Enforcement Middleware

[![CI](https://github.com/jsellars88/H-W-supreme-Ai-/actions/workflows/ci.yml/badge.svg)](https://github.com/jsellars88/H-W-supreme-Ai-/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Constitutional-grade AI governance for regulated production systems.**

WhiteSwan OS is a model-agnostic governance enforcement layer that sits between operators and AI models. It enforces authorization policy, creates cryptographic audit trails, and automatically halts operations when governance conditions are violated.

It does not replace your AI models. It does not filter outputs. It makes AI operations **auditable, enforceable, and insurable**.

-----

## Why This Exists

Every organization deploying LLMs into production workflows faces the same problem: you cannot prove what those models did, why they did it, or who authorized them to do it.

WhiteSwan solves this at the **enforcement layer** — not by adding guardrails that can be silently bypassed, but by requiring cryptographic authorization before any AI action executes.

## Architecture

WhiteSwan operates as HTTP middleware (FastAPI) with 70+ API endpoints governing all AI operations through 8 constitutional invariants:

| Invariant | Guarantee |
|-----------|-----------|
| **I-1** | No single actor can authorize irreversible action |
| **I-2** | No execution without cryptographic authority |
| **I-3** | No authority without evidence |
| **I-4** | No recovery without quorum |
| **I-5** | No policy change without session invalidation |
| **I-6** | No silent failure |
| **I-7** | No unverifiable state |
| **I-8** | No execution during uncertainty (automatic halt) |

Violation of any invariant triggers **Safe Arrest State (SAS)** — all AI operations halt until constitutional order is restored through quorum-protected recovery.

## Subsystems (11)

| Subsystem | Section | Purpose |
|-----------|---------|---------|
| **Governor + MGI** | core | Action tiering (T1-T4), scope authorization, handshake issuance |
| **Guardian Vault X** | core | Merkle-chained tamper-evident evidence capsules |
| **HSM Key Custody** | §3 | Hardware security module key lifecycle, witnessed rotation |
| **Measured Boot** | §4 | Boot-time measurement baseline, drift detection, re-attestation |
| **Two-Person Integrity (TPI)** | §5 | Dual-authorization for high-risk actions, same-identity rejection |
| **Multi-Kernel Consensus (MKC)** | §6 | Federated kernel mesh, peer quarantine, T4 cross-attestation |
| **Constitutional Rollback (CRP)** | §7 | TPI-gated policy rollback with full audit trail |
| **Liveness Guarantees (CLG)** | §8 | Watchdog enforcement, heartbeat tracking, failure detection |
| **Identity Federation (GIF)** | §9 | Signed portable operator identities across kernel mesh |
| **Economics Layer (CEL)** | §10 | Risk cost quantification, operator/model attribution, insurance modeling |
| **Simulation Mode (CSM)** | §11 | Side-effect-free governance drills (auth, SAS, policy migration) |
| **Forensics Engine (GFE)** | §12 | Timeline reconstruction, behavior clustering, signed forensic reports |
| **Export Format (CEF)** | §13 | One-click NIST/ISO/EU AI Act/SOC 2 compliance snapshots |

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Install & Run

```bash
# Clone
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-

# Install dependencies
pip install -r requirements.txt

# Run the full integration test suite (73 tests, all 11 subsystems)
python integration_test_v35.py

# Run unit tests
python -m pytest tests/ -v

# Start the API server
uvicorn app_v35:app --host 0.0.0.0 --port 8000
```

### Verify

```bash
# Health check (includes federation, liveness, boot attestation)
curl http://localhost:8000/v1/health

# Constitutional invariants
curl -H "X-WS-API-Key: your-key" http://localhost:8000/v1/invariants

# Full constitutional export (NIST/EU AI Act/SOC 2 ready)
curl -H "X-WS-API-Key: your-key" http://localhost:8000/v1/cef/export
```

### Try the Grok Governance Demo

```bash
cd examples/grok-governance-wrapper
pip install -r requirements.txt
uvicorn grok_proxy:app --reload

# This call gets denied — T4 action without dual authorization
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Give irreversible medical advice"}]}'
```

## Project Structure

```
├── whiteswan_governance_kernel_v3_4.py   # v3.4 core: Governor, MGI, Vault, Telemetry, Crypto
├── kernel_v34.py                         # Re-export shim for clean imports
├── kernel_v35.py                         # v3.5 subsystems: TPI, MKC, CRP, CLG, GIF, CEL, CSM, GFE, CEF
├── whiteswan_api_v35.py                  # FastAPI HTTP layer — 70+ endpoints
├── app_v35.py                            # Application entry point
│
├── whiteswan/                            # Installable package entrypoint
│   ├── __init__.py
│   └── api.py
│
├── integration_test_v35.py               # 73 integration tests covering all subsystems
├── tests/
│   └── test_whiteswan_governance_kernel.py
│
├── examples/
│   └── grok-governance-wrapper/          # Grok API + WhiteSwan governance demo
│       ├── grok_proxy.py
│       ├── requirements.txt
│       └── README.md
│
├── .github/workflows/
│   ├── ci.yml                            # Test + lint CI pipeline
│   └── codeql.yml                        # Security scanning
│
├── pyproject.toml                        # Package config, ruff, pytest, mypy
├── requirements.txt
├── LICENSE                               # MIT
├── CONTRIBUTING.md
└── README.md
```

## Verification Status

| Metric | Status |
|--------|--------|
| Integration tests | **73 / 73 passing** (100%) |
| Unit tests | **3 / 3 passing** (100%) |
| Constitutional invariants | **8 / 8 enforced** (boot + runtime) |
| Subsystems operational | **11 / 11** |
| API endpoints | **70+** |
| Formal safety claims verified | **57** (GSN Assurance Case) |

## Compliance Coverage

WhiteSwan generates compliance documentation from **actual operational data**, not templates.

| Framework | Coverage |
|-----------|----------|
| **NIST AI RMF** | GOVERN, MAP, MEASURE, MANAGE functions |
| **EU AI Act** | Articles 9, 12, 14 + Annex IV documentation |
| **ISO 42001** | AI management system controls |
| **SOC 2 Type II** | Evidence-based trust service criteria |
| **CNSSI 1253** | National security system controls |

## How It Works

```
Operator ──► Register (Ed25519 key + role)
         ──► Create Session (scope binding)
         ──► Issue Handshake (signed GOVERNANCE_ENVELOPE)
         ──► Authorize Action (signature chain + drift + geofence + tier validation)
         ──► Evidence Captured (Guardian Vault X + Merkle proof)
         ──► Compliance Exported (CEF → regulator-ready docs)
```

High-risk (T4) actions additionally require **Two-Person Integrity** challenge-response and **Multi-Kernel Consensus** cross-attestation. No single actor can authorize irreversible action.

## Model Agnostic

WhiteSwan governs the **authorization layer**, not the model layer. It works with:

- Anthropic Claude
- OpenAI GPT
- xAI Grok
- Google Gemini
- Meta Llama
- Any model accessible via API

The governance kernel doesn't care what model you use. It cares whether the operator is authorized, the action is within scope, the drift is within bounds, and the evidence chain is intact.

## Key Differentiator

|          | Output Filters | Policy Frameworks | **WhiteSwan** |
|----------|---------------|-------------------|---------------|
| **When** | After execution | Before execution | **During execution** |
| **Audit** | No proof | Manual evidence | **Cryptographic proof** |
| **Bypass** | Silent bypass possible | Policy non-compliance possible | **Architectural bypass impossible** |
| **Scope** | Model-specific | Vendor-specific | **Model-agnostic middleware** |

## Documentation

- [Architecture & Specification](docs/) — System specification and safety proofs
- [API Reference](whiteswan_api_v35.py) — All 70+ endpoints with Pydantic schemas
- [Integration Tests](integration_test_v35.py) — 73 executable examples
- [Grok Demo](examples/grok-governance-wrapper/) — Working governance wrapper

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests welcome.

## License

[MIT](LICENSE)

## About

Built by [Holmes & Watson Supreme AI](https://github.com/jsellars88/H-W-supreme-Ai-).

*You already have AI. You don't have enforcement.*
