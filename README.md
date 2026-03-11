# WhiteSwan Governance Kernel

Constitutional AI governance middleware for regulated environments.

WhiteSwan sits between your application and any model provider (OpenAI, Anthropic, Google, xAI, etc.) and enforces runtime governance with tamper-evident evidence capture.

## Why this repository exists

This project is **not** an AI model and **not** a content-card demo app. It is a governance middleware stack built to answer:

- What decision did the AI make?
- Which governance constraints were enforced?
- Can an external auditor verify that record independently?

The kernel is designed for AI assurance, incident response, and regulator-facing evidence workflows.

## Core components (already in repo)

- Governance kernel v3.4: [`whiteswan/whiteswan_governance_kernel_v3_4.py`](whiteswan/whiteswan_governance_kernel_v3_4.py)
- Governance kernel v3.5: [`whiteswan/kernel_v35.py`](whiteswan/kernel_v35.py)
- API layer: [`whiteswan/whiteswan_api_v35.py`](whiteswan/whiteswan_api_v35.py)
- Integration tests: [`tests/integration_test_v35.py`](tests/integration_test_v35.py)

Supporting verification and ledger tooling:

- Evidence verifier: [`verify_evidence.py`](verify_evidence.py)
- Rekor anchoring utility: [`rekor_anchor.py`](rekor_anchor.py)
- Ledger writers: [`ledger_writer.py`](ledger_writer.py), [`decision_ledger.py`](decision_ledger.py)

## Architecture at a glance

```text
Application / Orchestrator
          |
          v
+-----------------------------------------------+
| WhiteSwan Governance Kernel                   |
| - Constitutional invariant enforcement         |
| - Refusal/escalation path on policy breach    |
| - Evidence packet generation                  |
| - Ed25519 signatures + hash-chained records   |
+-----------------------------------------------+
          |
          v
Provider Model API (LLM of choice)
```

Evidence can be independently validated offline and optionally anchored to Rekor for third-party timestamp transparency.

## Repository structure (governance-focused)

```text
whiteswan/
  whiteswan_governance_kernel_v3_4.py
  kernel_v35.py
  whiteswan_api_v35.py

tests/
  integration_test_v35.py
  test_whiteswan_governance_kernel.py
  test_rekor_anchor.py

.github/workflows/
  ... CI validation workflows
```

## Run locally

```bash
pip install -r requirements.txt
python whiteswan/whiteswan_api_v35.py
```

## Validate locally

```bash
pytest tests/
```

## Evidence verification examples

```bash
python verify_evidence.py packet.json --pubkey <hex_pubkey>
python verify_evidence.py packet.json --pubkey <hex_pubkey> --predecessor prev.json
python verify_evidence.py packet.json --pubkey <hex_pubkey> --rekor
```

## Current test posture

The governance test suite lives in [`tests/`](tests/), including kernel and integration coverage:

- [`tests/test_whiteswan_governance_kernel.py`](tests/test_whiteswan_governance_kernel.py)
- [`tests/integration_test_v35.py`](tests/integration_test_v35.py)
- [`tests/test_rekor_anchor.py`](tests/test_rekor_anchor.py)

Use CI workflows in [`.github/workflows/`](.github/workflows/) plus local `pytest tests/` runs as evaluation entry points.

## Positioning statement

WhiteSwan is governance middleware: enforce constraints, capture signed evidence, and make AI decisions audit-verifiable across model providers.

