# WhiteSwan OS — AI Governance Enforcement Middleware

**Constitutional-grade AI governance for regulated production systems.**

WhiteSwan OS is a model-agnostic governance enforcement layer that sits between operators and AI models. It enforces authorization policy, creates cryptographic audit trails, and automatically halts operations when governance conditions are violated.

It does not replace your AI models. It does not filter outputs. It makes AI operations **auditable, enforceable, and insurable**.

-----

## Why This Exists

Every organization deploying LLMs into production workflows faces the same problem: you cannot prove what those models did, why they did it, or who authorized them to do it.

WhiteSwan solves this at the **enforcement layer** — not by adding guardrails that can be silently bypassed, but by requiring cryptographic authorization before any AI action executes.

## Architecture

WhiteSwan operates as HTTP middleware (FastAPI) with 52 API endpoints governing all AI operations through 8 constitutional invariants:

|Invariant|Guarantee                                        |
|---------|-------------------------------------------------|
|**I-1**  |No single actor can authorize irreversible action|
|**I-2**  |No execution without cryptographic authority     |
|**I-3**  |No authority without evidence                    |
|**I-4**  |No recovery without quorum                       |
|**I-5**  |No policy change without session invalidation    |
|**I-6**  |No silent failure                                |
|**I-7**  |No unverifiable state                            |
|**I-8**  |No execution during uncertainty (automatic halt) |

Violation of any invariant triggers **Safe Arrest State (SAS)** — all AI operations halt until constitutional order is restored through quorum-protected recovery.

## Subsystems (11)

|Subsystem                        |Purpose                                                        |
|---------------------------------|---------------------------------------------------------------|
|**Governor + MGI**               |Action tiering (T1-T4), scope authorization, handshake issuance|
|**Guardian Vault X**             |Merkle-chained tamper-evident evidence capsules                |
|**Two-Person Integrity (TPI)**   |Dual-authorization for high-risk actions                       |
|**Multi-Kernel Consensus (MKC)** |Federated kernel mesh, T4 cross-attestation                    |
|**Constitutional Rollback (CRP)**|Quorum + TPI + consensus for state recovery                    |
|**Liveness Guarantees (CLG)**    |Watchdog enforcement, failure detection                        |
|**Identity Federation (GIF)**    |Signed portable operator identities                            |
|**Economics Layer (CEL)**        |Risk cost tracking, insurance modeling                         |
|**Simulation Mode (CSM)**        |Side-effect-free governance testing                            |
|**Forensics Engine (GFE)**       |Timeline reconstruction, anomaly detection                     |
|**Export Format (CEF)**          |One-click NIST/ISO/EU AI Act/SOC 2 compliance docs             |

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Install & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Run the governance kernel tests (70 integration tests)
python -m pytest tests/ -v

# Start the API server
uvicorn whiteswan.api:app --host 0.0.0.0 --port 8000
```

### Verify

```bash
# Health check
curl http://localhost:8000/health

# Check invariants
curl -H "X-Api-Key: your-key" http://localhost:8000/invariants
```

## Project Structure

```text
whiteswan/                     # Governance engine (the product)
├── kernel_v34.py              # Base governance kernel (Governor, MGI, Vault, Telemetry)
├── kernel_v35.py              # v3.5 subsystems (TPI, MKC, CRP, CLG, GIF, CEL, CSM, GFE, CEF)
├── api.py                     # FastAPI HTTP layer — 52 endpoints
└── __init__.py

tests/
├── integration_test_v35.py    # 70 integration tests covering all subsystems
└── conftest.py

docs/                          # Specifications and compliance
├── WhiteSwan_OS_v3_5_Specification.docx
├── GSN_Assurance_Case.docx    # Formal safety proof (57 evidence items)
└── ARCHITECTURE.md

site/                          # Marketing site (Flask content cards)
├── app/
│   ├── main.py
│   └── templates/
└── data/posts.json

pyproject.toml                 # Python package configuration
requirements.txt
LICENSE
README.md
```

## Verification Status

|Metric                       |Status                             |
|-----------------------------|-----------------------------------|
|Integration tests            |**70 / 70 passing** (100%)         |
|Constitutional invariants    |**8 / 8 enforced** (boot + runtime)|
|Subsystems operational       |**11 / 11**                        |
|API endpoints                |**52**                             |
|Formal safety claims verified|**57** (GSN Assurance Case)        |

## Compliance Coverage

WhiteSwan generates compliance documentation from **actual operational data**, not templates.

|Framework        |Coverage                                   |
|-----------------|-------------------------------------------|
|**NIST AI RMF**  |GOVERN, MAP, MEASURE, MANAGE functions     |
|**EU AI Act**    |Articles 9, 12, 14 + Annex IV documentation|
|**ISO 42001**    |AI management system controls              |
|**SOC 2 Type II**|Evidence-based trust service criteria      |
|**CNSSI 1253**   |National security system controls          |

## How It Works

1. **Operator registers** with Ed25519 signing key and role assignment
1. **Session created** binding operator identity to authorized scope
1. **Handshake issued** — signed `GOVERNOR_ENVELOPE` authorizes specific action tier
1. **Action authorized** — kernel validates signature chain, drift score, geofence, and tier
1. **Evidence captured** — every decision stored in Guardian Vault X with Merkle proof
1. **Compliance exported** — one-click CEF generates regulator-ready documentation

High-risk (T4) actions additionally require **Two-Person Integrity** challenge-response and **Multi-Kernel Consensus** cross-attestation. No single actor can authorize irreversible action.

## Model Agnostic

WhiteSwan governs the **authorization layer**, not the model layer. It works with:

- Anthropic Claude
- OpenAI GPT
- Google Gemini
- Meta Llama
- Any model accessible via API

The governance kernel doesn’t care what model you use. It cares whether the operator is authorized, the action is within scope, the drift is within bounds, and the evidence chain is intact.

## Key Differentiator

|          |Output Filters        |Policy Frameworks             |**WhiteSwan**                      |
|----------|----------------------|------------------------------|-----------------------------------|
|**When**  |After execution       |Before execution              |**During execution**               |
|**Audit** |No proof              |Manual evidence               |**Cryptographic proof**            |
|**Bypass**|Silent bypass possible|Policy non-compliance possible|**Architectural bypass impossible**|
|**Scope** |Model-specific        |Vendor-specific               |**Model-agnostic middleware**      |

## Documentation

- [Specification (DOCX)](docs/WhiteSwan_OS_v3_5_Specification.docx) — Full v3.5 system specification
- [GSN Assurance Case (DOCX)](docs/GSN_Assurance_Case.docx) — Formal safety proof with 57 evidence items
- [Architecture Guide](docs/ARCHITECTURE.md) — Technical deep-dive
- [API Reference](docs/API.md) — All 52 endpoints

## License

[MIT](LICENSE)

## About

Built by [Holmes & Watson Supreme AI](https://github.com/jsellars88/H-W-supreme-Ai-).

*You already have AI. You don’t have enforcement.*
