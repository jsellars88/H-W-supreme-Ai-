# White Swan A.R.T. — Quick Start Guide

**Get the governance engine running in 5 minutes.**

---

## Prerequisites

- Python 3.9+
- pip (Python package manager)
- Git

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-
```

### 2. Install Dependencies

```bash
make install
```

Or manually:

```bash
pip install -r requirements.txt
```

---

## Running the Unified Operations

### Option A: Run Everything (Recommended)

```bash
python main.py all
```

This will:
- ✅ Run 62 comprehensive tests
- ✅ Execute Tornado Scenario (6 decisions)
- ✅ Execute RescueChain Scenario (7 decisions)
- ✅ Verify all ledger integrity
- ✅ Generate `OPERATIONS_REPORT.json`

**Time:** ~2-3 minutes

### Option B: Run Individual Operations

```bash
# Run test suite only
python main.py test

# Run Tornado scenario
python main.py tornado

# Run RescueChain scenario
python main.py rescuechain

# Verify ledger integrity
python main.py verify
```

### Option C: Using Makefile

```bash
# Everything
make run-all

# Individual tasks
make test
make tornado
make rescuechain
make verify
```

---

## Understanding the Output

### Test Suite Output

```
test_white_swan_art.py::test_consensus_all_authorize PASSED
test_white_swan_art.py::test_medic_veto_absolute PASSED
...
======================== 62 passed in 1.23s ========================
```

### Scenario Output

```
╔════════════════════════════════════════════════════════╗
║  Tornado Scenario: High-Risk Rescue with 6 Decisions  ║
╚════════════════════════════════════════════════════════╝

Decision 1: Launch Air Recon
  Command: AUTHORIZE (confidence: 0.88)
  Basis: consensus, confidence 0.88
  
...

✓ Scenario complete — ledger saved to art_tornado_ledger.json
```

### Ledger Verification Output

```
art_tornado_ledger.json: ✓ PASS
  Reason: Chain integrity verified, signature valid

rescuechain_ledger.json: ✓ PASS
  Reason: Chain integrity verified, signature valid
```

---

## Operations Report

After running operations, a detailed JSON report is generated:

```bash
cat OPERATIONS_REPORT.json
```

**Contents:**
- Timestamp of execution
- Status of each operation (PASS/FAIL)
- Test statistics
- Ledger verification results
- Error messages (if any)

---

## Key Concepts

### The 5-Unit Consensus Model

| Unit | Role | Veto Authority |
|------|------|----------------|
| **Scout** | Visibility & environmental conditions | ❌ No |
| **Guardian** | Structural integrity & hazards | ❌ No |
| **Pathfinder** | Route viability & traversal | ❌ No |
| **Medic** | Casualty health & safety | ✅ **YES (Absolute)** |
| **Sentinel** | Communications reliability | ❌ No |

### Decision States

- **AUTHORIZE** — Consensus reached, confidence ≥ 0.70
- **HOLD_FOR_COMMANDER** — Consensus but confidence < 0.70 (awaiting human judgment)
- **REFUSE** — Dissent or veto exercised (blocks action)

### The Medic's Veto

The Medic can **unconditionally refuse** any action to protect casualty safety. The commander **cannot override** this veto—it is absolute and final.

---

## Exploring the Code

### Core Files

```
white_swan_art.py          # Governance engine (5 conductors, consensus logic)
governance_ledger.py       # Hash-chained forensic ledger with Ed25519
test_white_swan_art.py     # 62 comprehensive tests (all invariants)
main.py                    # Unified operations orchestrator
```

### Documentation

```
README.md                  # Overview and architecture
GOVERNANCE.md              # Technical deep dive (17 KB)
QUICKSTART.md             # This file
```

### Key Functions

**Governance Decision:**
```python
from white_swan_art import white_swan_command

decision, basis, confidence = white_swan_command(
    action="move casualty",
    votes=[...],
    commander_override=None
)
```

**Ledger Verification:**
```python
from governance_ledger import ForensicLedger

ok, reason = ForensicLedger.verify("mission_ledger.json")
print(f"Integrity: {'PASS' if ok else 'FAIL'} — {reason}")
```

---

## Common Tasks

### Run Tests with Verbose Output

```bash
pytest test_white_swan_art.py -v -s
```

### Run a Specific Test

```bash
pytest test_white_swan_art.py::test_medic_veto_absolute -v
```

### Clean All Artifacts

```bash
make clean
```

### Check Code Style

```bash
make lint
```

---

## Troubleshooting

### ImportError: No module named 'white_swan_art'

**Solution:** Ensure you're in the repository root and dependencies are installed:
```bash
pip install -r requirements.txt
```

### pytest: command not found

**Solution:** Install test dependencies:
```bash
pip install pytest
```

### Ledger verification fails

**Solution:** Ensure ledger files exist and haven't been manually edited:
```bash
python main.py verify
```

---

## Next Steps

1. **Read GOVERNANCE.md** — Understand the technical model in depth
2. **Explore white_swan_art.py** — Study the implementation
3. **Run scenarios** — Execute Tornado and RescueChain to see governance in action
4. **Review tests** — Check test_white_swan_art.py for invariant specifications

---

## Support

For issues or questions:
- Check the repository [Issues](https://github.com/jsellars88/H-W-supreme-Ai-/issues)
- Review GOVERNANCE.md for technical details
- Run `python main.py -h` for command help

---

**Last Updated:** 2026-07-07  
**Status:** Production-ready governance engine with cryptographic audit trail.
