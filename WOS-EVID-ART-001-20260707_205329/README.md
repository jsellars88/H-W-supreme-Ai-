# WOS-EVID-ART-001: WhiteSwan A.R.T. Reproducibility Evidence Package

Generated: 2026-07-07T20:53:29.451306
System: Linux runnervmkkn4f 6.17.0-1018-azure #18~24.04.1-Ubuntu SMP Thu May 28 16:39:11 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
Python: Python 3.12.3
Git Commit: a834c94a344b9c6c3af666e68336c01bc0fbaa98

## This Package Contains

1. **System Information**
   - Python version
   - Git commit SHA
   - System info (uname)
   - Dependency versions (pip freeze)

2. **Execution Logs**
   - integration_test_output.txt — Integration test suite results
   - main_all_output.txt — Full operations output

3. **Generated Artifacts**
   - art_tornado_ledger.json — Sealed forensic ledger (Tornado scenario)
   - rescuechain_ledger.json — Sealed forensic ledger (RescueChain scenario)
   - OPERATIONS_REPORT.json — Unified operations summary

4. **Verification Data**
   - VERIFICATION_HASHES.txt — SHA256 hashes for integrity checking
   - EVIDENCE_METADATA.json — Complete execution metadata

5. **Reviewer Guide**
   - REVIEWER_INSTRUCTIONS.md — Steps to reproduce and verify

## Quick Verification

### 1. Verify File Integrity
```bash
cd WOS-EVID-ART-001-*/
sha256sum -c VERIFICATION_HASHES.txt
```

### 2. Verify Ledger Signatures (requires Python)
```bash
cd /path/to/H-W-supreme-Ai-
python -c "
from governance_ledger import ForensicLedger
for ledger in ['art_tornado_ledger.json', 'rescuechain_ledger.json']:
    ok, reason = ForensicLedger.verify(ledger)
    print(f'{ledger}: {"✓" if ok else "✗"} {reason}')
"
```

### 3. Inspect Ledger Metadata
```bash
python -m json.tool art_tornado_ledger.json | head -30
python -m json.tool rescuechain_ledger.json | head -30
```

### 4. View Operations Report
```bash
python -m json.tool OPERATIONS_REPORT.json | head -50
```

## Independent Reproduction

See REVIEWER_INSTRUCTIONS.md for complete steps to:
1. Clone the repository at the recorded commit SHA
2. Install dependencies
3. Run the exact same commands
4. Compare outputs
5. Verify artifacts match

## Attestation

Once you have successfully reproduced and verified everything,
please complete REVIEWER_ATTESTATION.md and return it to the maintainer.

This confirms independent verification of:
- Reproducibility (identical hashes)
- Cryptographic integrity (Ed25519 valid)
- System functionality (all tests pass)
- Auditability (ledgers independently verifiable)

---

For questions or issues, contact the maintainer.
