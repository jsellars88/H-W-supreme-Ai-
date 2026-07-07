# White Swan A.R.T. — Autonomous Rescue Taskforce Governance

**A formal, auditable governance engine for multi-unit decision-making in high-stakes rescue operations.**

---

## Overview

White Swan A.R.T. implements a **5-unit consensus model with safety veto authority** and cryptographically-sealed forensic ledgers. No single unit decides alone. The commander can refuse actions or release low-confidence holds—but **cannot override casualty safety vetoes**.

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

### Mission Records

- **art_tornado_ledger.json** — Sealed Tornado Scenario (6 decisions)
- **rescuechain_ledger.json** — Sealed RescueChain Mission (7 decisions)

### Configuration

- **requirements.txt** — Python dependencies

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Run Tornado Scenario

```bash
python white_swan_art.py
```

### Run Full Test Suite

```bash
pytest test_white_swan_art.py -v
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

## License

MIT License.

---

Last Updated: 2026-07-07
