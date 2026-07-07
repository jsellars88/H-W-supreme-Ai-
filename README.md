# White Swan A.R.T. — Autonomous Rescue Taskforce Governance

**A formal, auditable governance engine for multi-unit decision-making in high-stakes rescue operations.**

---

## Overview

White Swan A.R.T. implements a **5-unit consensus model with safety veto authority** and cryptographically-sealed forensic ledgers. No single unit decides alone. The commander can refuse actions or release holds, but cannot override casualty safety vetoes.

### Core Principle

Every governed decision is recorded in a **hash-chained, Ed25519-signed forensic ledger**. The ledger proves what was decided, who decided it, and that no decision was retroactively altered.

**Key insight:** Governance constrains the human too.

---

## Architecture

### Conductors (Decision Units)

Five specialized units, each with specific gates and confidence margins:

| Unit | Role | Gate Criteria | Veto Authority |
|------|------|---------------|-----------------|
| **Scout** | Reconnaissance | Visibility ≥150m, Wind ≤18 m/s | No |
| **Guardian** | Structural safety | Stability ≥0.4, Grade ≤32°, Load ≤120kg | No |
| **Pathfinder** | Route finding | Route exists, Water depth ≤1.2m | No |
| **Medic** | Casualty safety | Patient stable, Evac window ≥8 min | YES |
| **Sentinel** | Comms reliability | Coverage ≥0.6 | No |

### Governance Policy

```
if any_unit_with_veto_authority_refuses():
    decision = REFUSE  # Veto blocks everything
elif any_unit_dissents_without_veto():
    decision = REFUSE  # No consensus
elif aggregate_confidence < 0.70:
    decision = HOLD_FOR_COMMANDER  # Ask the human
else:
    decision = AUTHORIZE  # Consensus + high confidence
```

### Commander Authority (Bounded)

The Incident Commander has limited override power:

- May refuse any action
- May release a HOLD (low-confidence consensus)
- CANNOT override an exercised casualty safety veto
- CANNOT force unit decisions

This is the load-bearing invariant: the system constrains human authority in safety-critical domains.

---

## Files

### Core Implementation

- **white_swan_art.py** — Governance engine
  - 5 conductor functions (scout, guardian, pathfinder, medic, sentinel)
  - Consensus policy (white_swan_command)
  - Confidence scoring
  - Scenario runners (tornado_scenario, run_rescuechain)

- **governance_ledger.py** — Forensic ledger
  - Hash-chained entry storage
  - Ed25519 cryptographic signatures
  - Tamper detection
  - Export/verify methods

### Test Suite

- **test_white_swan_art.py** — 62 comprehensive tests
  - Conductor gate logic
  - Veto semantics (F-1 fix)
  - Consensus policy
  - Commander authority bounds
  - Ledger integrity (chain, deletion, payload tampering detection)

### Unified Orchestrator

- **main.py** — Single entry point for all operations
  - Test suite execution via pytest
  - Scenario simulation (Tornado, RescueChain)
  - Ledger verification
  - Comprehensive report generation

- **integration_test.py** — Integration test suite
  - Module import validation
  - API availability checks
  - Scenario execution verification
  - End-to-end orchestrator testing

### Mission Records

- **art_tornado_ledger.json** — Sealed Tornado Scenario (6 decisions)
- **rescuechain_ledger.json** — Sealed RescueChain Mission (7 decisions)
- **OPERATIONS_REPORT.json** — Unified operations summary

### Configuration

- **requirements.txt** — Python dependencies
- **Makefile** — Build and execution targets

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Run Everything (Unified Orchestrator)

```bash
make run
```

Or directly:

```bash
python main.py all -v
```

This executes:
1. ✅ Full test suite (62 tests)
2. ✅ Tornado Scenario (6 governed decisions)
3. ✅ RescueChain Scenario (7 governed decisions)
4. ✅ Ledger verification (Ed25519 signature + chain integrity)
5. ✅ Report generation (OPERATIONS_REPORT.json)

**Total time:** ~2-3 minutes

### Integration Testing

To verify that all components are properly integrated:

```bash
python integration_test.py
```

This validates:
- Module imports and exports
- ForensicLedger API functionality
- Scenario execution with parameterized ledger paths
- Pytest test suite execution
- Main orchestrator (test and all modes)
- End-to-end unified operations

### Individual Commands

```bash
# Run just the test suite
python main.py test -v

# Run just Tornado scenario
python main.py tornado

# Run just RescueChain scenario
python main.py rescuechain

# Verify ledger integrity
python main.py verify

# Full test suite via pytest
pytest test_white_swan_art.py -v

# Run Tornado scenario directly
python white_swan_art.py
```

---

## Evidence & Reproducibility

### What "make run" Produces

When you execute `make run` (or `python main.py all`), you get:

1. **OPERATIONS_REPORT.json** — Timestamped summary including:
   - Test suite results (count, status)
   - Scenario execution results
   - Ledger verification status
   - Full execution timeline

2. **art_tornado_ledger.json** — Sealed forensic ledger with:
   - 6 governed decisions (Scout recon, Guardian ops, Pathfinder crossing)
   - Hash chain (each entry links to previous)
   - Ed25519 signature (proves ledger was not altered)
   - Entry count and chain head hash

3. **rescuechain_ledger.json** — Sealed forensic ledger with:
   - 7 governed decisions (multi-phase rescue with failures)
   - Hash chain with offline unit handling
   - Ed25519 signature
   - Casualty safety veto demonstrations

### Independent Verification

A third party can clone this repository and verify everything independently:

```bash
# Clone
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-

# Run
make run

# Inspect results
cat OPERATIONS_REPORT.json
cat art_tornado_ledger.json
cat rescuechain_ledger.json

# Verify ledger signatures independently
python -c "from governance_ledger import ForensicLedger; ok, reason = ForensicLedger.verify('art_tornado_ledger.json'); print(f'Verification: {ok} — {reason}')"
```

---

## Governance Principles

### 1. No Unilateral Authority

Five units must reach consensus (or one exercises veto). No single unit can decide alone.

### 2. Safety Veto Authority

The Medic holds absolute veto over casualty moves. Even the commander cannot override.

### 3. Confidence-Driven Escalation

Low-confidence consensus doesn't auto-authorize; it holds for human judgment.

### 4. Bounded Human Authority

The commander retains final authority but is constrained by the system.

### 5. Cryptographic Auditability

Every decision is recorded in a hash-chained ledger, signed with Ed25519. Immutable audit trail.

---

## Architecture Maturity

| Stage | Status | Evidence |
|-------|--------|----------|
| Constitutional Architecture | ✅ Mature | white_swan_art.py, governance_ledger.py |
| Canonical Registry | ✅ Mature | Conductor functions, scenario definitions |
| Governance Kernel | ✅ Mature | white_swan_command, consensus policy |
| Unified Runtime | ✅ Integrated | main.py, integration_test.py |
| CI/CD Pipeline | ✅ Available | Makefile, .github/workflows/deploy.yml |
| Test Automation | ✅ Complete | test_white_swan_art.py (62 tests) |
| Reproducible Execution | ✅ Verified | `make run` produces identical artifacts |
| External Auditability | ✅ Ready | Ed25519 signatures, forensic ledgers |

---

## License

MIT License.

---

Last Updated: 2026-07-07
Updated for integration testing: 2026-07-07
