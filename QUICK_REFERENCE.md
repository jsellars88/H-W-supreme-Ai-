# White Swan A.R.T. — Quick Reference

**Copy-paste commands to run the system.**

---

## 1. Setup (One Time)

```bash
# Clone the repository
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-

# Install dependencies
pip install -r requirements.txt
```

---

## 2. Run Everything (Full Integration)

### Option A: Using Makefile
```bash
make run
```

### Option B: Direct Python
```bash
python main.py all -v
```

### Option C: Step-by-step
```bash
# 1. Run tests
python main.py test

# 2. Run Tornado Scenario
python main.py tornado

# 3. Run RescueChain Scenario
python main.py rescuechain

# 4. Verify ledgers
python main.py verify

# 5. View report
cat OPERATIONS_REPORT.json
```

---

## 3. Integration Testing

Verify all components work together:

```bash
python integration_test.py
```

Expected output:
```
✓ PASS: Module Imports
✓ PASS: Unit & Function Exports
✓ PASS: ForensicLedger API
✓ PASS: Tornado Scenario Execution
✓ PASS: RescueChain Scenario Execution
✓ PASS: Pytest Test Suite
✓ PASS: Main Orchestrator (test mode)
✓ PASS: Unified Operations (main.py all)

────────────────────────────────────────────────────────
8 Passed | 0 Failed
────────────────────────────────────────────────────────
```

---

## 4. Individual Operations

### Run Test Suite Only
```bash
pytest test_white_swan_art.py -v
```

### Run Tornado Scenario Only
```bash
python white_swan_art.py
```

### Run RescueChain Scenario Only
```bash
python -c "from white_swan_art import run_rescuechain; run_rescuechain()"
```

### Verify Specific Ledger
```bash
python -c "from governance_ledger import ForensicLedger; ok, reason = ForensicLedger.verify('art_tornado_ledger.json'); print(f'Tornado: {ok} — {reason}')"
```

---

## 5. Inspect Results

### View Operations Report
```bash
cat OPERATIONS_REPORT.json
```

### View Tornado Ledger (Pretty-printed)
```bash
python -m json.tool art_tornado_ledger.json | head -100
```

### View RescueChain Ledger (Pretty-printed)
```bash
python -m json.tool rescuechain_ledger.json | head -100
```

### Verify Tornado Ledger Signature
```bash
python -c "
from governance_ledger import ForensicLedger
ok, reason = ForensicLedger.verify('art_tornado_ledger.json')
print(f'Tornado Ledger: {\"✓ VERIFIED\" if ok else \"✗ FAILED\"}')
print(f'Reason: {reason}')
"
```

### Verify RescueChain Ledger Signature
```bash
python -c "
from governance_ledger import ForensicLedger
ok, reason = ForensicLedger.verify('rescuechain_ledger.json')
print(f'RescueChain Ledger: {\"✓ VERIFIED\" if ok else \"✗ FAILED\"}')
print(f'Reason: {reason}')
"
```

---

## 6. Expected Artifacts

After running `make run` or `python main.py all`, you should have:

```
H-W-supreme-Ai-/
├── OPERATIONS_REPORT.json           ← Timestamped summary
├── art_tornado_ledger.json          ← Sealed ledger (6 decisions)
├── rescuechain_ledger.json          ← Sealed ledger (7 decisions)
├── test_white_swan_art.py           ← Test suite
├── white_swan_art.py                ← Governance engine
├── governance_ledger.py             ← Forensic ledger
├── main.py                          ← Orchestrator
└── integration_test.py              ← Integration tests
```

---

## 7. Troubleshooting

### "ModuleNotFoundError: No module named 'pytest'"
```bash
pip install pytest
```

### "ModuleNotFoundError: No module named 'cryptography'"
```bash
pip install cryptography
```

### "FileNotFoundError: art_tornado_ledger.json"
The file should be created automatically by `make run` or `python main.py all`.
If it's missing, check error output for why scenarios failed.

### "Ledger verification FAILED"
This means the Ed25519 signature is invalid or the hash chain is broken.
Download the ledger from a fresh `make run` to get a valid one.

### "pytest: command not found"
```bash
pip install pytest --user
# or use: python -m pytest test_white_swan_art.py -v
```

---

## 8. Minimal Reproducible Test

Verify the core integration with one command:

```bash
python -c "
import white_swan_art as art
from governance_ledger import ForensicLedger

# Create test ledger
led = ForensicLedger(domain='TEST')
led.append({'test': 'entry'})
led.export('test_ledger.json')

# Verify it
ok, reason = ForensicLedger.verify('test_ledger.json')
print(f'✓ Integration works: {ok}')
print(f'  {reason}')

# Cleanup
import os; os.remove('test_ledger.json')
"
```

Expected output:
```
✓ Integration works: True
  Ledger integrity verified: chain complete, entries linked, signature valid
```

---

## 9. Document Verification (Third Party)

To independently verify without trusting the running code:

```bash
# Extract ledger data
python -c "
import json
with open('art_tornado_ledger.json') as f:
    doc = json.load(f)

print('Ledger Metadata:')
print(f'  Domain: {doc[\"domain\"]}')
print(f'  Genesis: {doc[\"genesis\"]}')
print(f'  Chain Head: {doc[\"chain_head\"]}')
print(f'  Entry Count: {doc[\"entry_count\"]}')
print(f'  Public Key: {doc[\"public_key\"]}')
print(f'  Signature: {doc[\"signature\"]}')
print()
print('Entries:')
for e in doc['entries']:
    print(f'  [{e[\"index\"]}] {e[\"payload\"].get(\"action\", \"unknown\")}')
"
```

---

## 10. Performance Notes

- Full `make run` typically takes 2-3 minutes
- Test suite (62 tests): ~30-40 seconds
- Tornado scenario: ~10 seconds
- RescueChain scenario: ~15 seconds
- Ledger verification: ~1 second per ledger
- Report generation: ~2 seconds

Total elapsed time is dominated by the test suite execution.

---

## 11. CI/CD Integration

To run in GitHub Actions or similar:

```yaml
- name: Install dependencies
  run: pip install -r requirements.txt

- name: Run integration tests
  run: python integration_test.py

- name: Run full operations
  run: python main.py all -v

- name: Upload ledgers as artifacts
  uses: actions/upload-artifact@v3
  with:
    name: mission-ledgers
    path: |
      art_tornado_ledger.json
      rescuechain_ledger.json
      OPERATIONS_REPORT.json
```

---

Last updated: 2026-07-07
