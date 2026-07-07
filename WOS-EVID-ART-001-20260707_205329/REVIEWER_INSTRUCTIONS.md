# Reviewer Instructions: WOS-EVID-ART-001

## Purpose

This evidence package allows you to independently verify that WhiteSwan A.R.T.:
1. Is reproducible (identical execution on any system)
2. Has cryptographically valid ledgers (Ed25519 signatures verified)
3. Implements working governance (all tests pass)
4. Can be audited by third parties (artifacts are verifiable)

## Prerequisites

- Python 3.9 or later
- Git
- pip
- A few minutes to run the reproduction

## Step 1: Verify Package Integrity

Before proceeding, verify that the files in this package have not been tampered with:

```bash
sha256sum -c VERIFICATION_HASHES.txt
```

All files should show "OK". If any fail, the package has been corrupted or modified.

## Step 2: Extract Repository at Recorded Commit

The evidence was generated from Git commit: a834c94a344b9c6c3af666e68336c01bc0fbaa98

Clone the repository and check out that exact commit:

```bash
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-
git checkout a834c94a344b9c6c3af666e68336c01bc0fbaa98
```

Verify you're at the right commit:
```bash
git rev-parse HEAD
# Should output: a834c94a344b9c6c3af666e68336c01bc0fbaa98
```

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 4: Run Integration Tests

```bash
python integration_test.py
```

You should see:
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

## Step 5: Run Full Operations

This is the critical step. Run the exact command that generated this evidence:

```bash
python main.py all -v
```

This will:
- Run all 62 pytest tests
- Execute Tornado Scenario (6 decisions)
- Execute RescueChain Scenario (7 decisions)
- Verify ledger signatures
- Generate OPERATIONS_REPORT.json

Expected output includes:
```
Tornado Scenario: PASS
RescueChain Scenario: PASS
Tornado Ledger Verification: PASS
RescueChain Ledger Verification: PASS
```

## Step 6: Compare Artifacts

Compare the ledger files you just generated against those in this evidence package:

```bash
# Compare Tornado ledger
sha256sum art_tornado_ledger.json
# Should match the hash in VERIFICATION_HASHES.txt

# Compare RescueChain ledger
sha256sum rescuechain_ledger.json
# Should match the hash in VERIFICATION_HASHES.txt

# Compare Operations Report
sha256sum OPERATIONS_REPORT.json
# Should match the hash in VERIFICATION_HASHES.txt
```

If all hashes match, the system is fully reproducible.

## Step 7: Verify Ledger Signatures

Independently verify that the Ed25519 signatures on the ledgers are valid:

```bash
python -c "
from governance_ledger import ForensicLedger

print('Verifying Tornado Ledger...')
ok, reason = ForensicLedger.verify('art_tornado_ledger.json')
print(f'  Result: {"✓ VALID" if ok else "✗ INVALID"}')
print(f'  Reason: {reason}')

print()
print('Verifying RescueChain Ledger...')
ok, reason = ForensicLedger.verify('rescuechain_ledger.json')
print(f'  Result: {"✓ VALID" if ok else "✗ INVALID"}')
print(f'  Reason: {reason}')
"
```

Both should show "VALID" and reason "Ledger integrity verified: ...".

## Step 8: Inspect Ledger Contents

View the human-readable contents of the ledgers to understand what decisions were made:

```bash
python -m json.tool art_tornado_ledger.json | head -100
python -m json.tool rescuechain_ledger.json | head -100
```

Each entry in the ledger has:
- index: Decision number
- payload: The governance decision details
- entry_hash: SHA256 hash of the payload
- prior_hash: Hash of the previous entry (forms the chain)

## Step 9: Verify Hash Chain Manually (Optional)

For extra confidence, you can independently verify that the hash chain is intact:

```bash
python -c "
import json
import hashlib

with open('art_tornado_ledger.json') as f:
    doc = json.load(f)

print(f'Verifying chain for {doc["domain"]}...')
print(f'Genesis: {doc["genesis"][:16]}...')
print(f'Chain Head: {doc["chain_head"][:16]}...')
print(f'Entry Count: {doc["entry_count"]}')
print()

# Verify each entry links to the next
for e in doc['entries']:
    computed_hash = hashlib.sha256(
        json.dumps(e['payload'], sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()
    stored_hash = e['entry_hash']
    status = '✓' if computed_hash == stored_hash else '✗'
    print(f'Entry {e["index"]}: {status}')

print()
print('Chain verified: all entry hashes are valid')
"
```

## Step 10: Complete Attestation

If you have successfully completed all steps and verified:
- ✓ Files are authentic (SHA256 hashes match)
- ✓ System is reproducible (your outputs match the evidence)
- ✓ Ledger signatures are valid (Ed25519 verified)
- ✓ Hash chains are intact (no entry has been modified)
- ✓ All tests pass (62 pytest tests, 2 scenarios)

Then please complete REVIEWER_ATTESTATION.md and return it to the maintainer.

Your signature confirms:
1. You successfully reproduced the system independently
2. You verified all artifacts cryptographically
3. You found no evidence of tampering or fraud
4. You believe the system performs as claimed

## Troubleshooting

**Q: sha256sum -c fails**
A: The package files may have been corrupted. Request a fresh copy.

**Q: Git checkout fails with "unknown revision"**
A: The commit SHA may be invalid or the repository state has changed. Verify the commit SHA in VERIFICATION_HASHES.txt

**Q: Ledger verification fails with "Signature Invalid"**
A: The ledger file may have been modified. Do not use this package. Request a fresh copy.

**Q: Tests fail with "import error"**
A: You may have an older version of a dependency. Run: pip install --upgrade -r requirements.txt

**Q: Hash mismatch on OPERATIONS_REPORT.json**
A: The report includes timestamps, which may differ between runs. This is expected. Verify the ledger files instead.

## What This Proves

If you complete all steps successfully, you have proven:

1. **Reproducibility**: The system produces identical artifacts on different machines
2. **Authenticity**: Cryptographic signatures confirm no tampering
3. **Completeness**: All tests pass consistently
4. **Auditability**: Third parties can independently verify everything

This is more rigorous than "trust me bro, it works."

This is "here's the evidence, verify it yourself."

---

Thank you for your diligent review.
