# WhiteSwan Forensic AI Decision Ledger v0.4

This package adds a single-writer, hash-chained, Ed25519-signed decision ledger.

## Included files
- `decision_ledger.py`
- `ledger_writer.py`
- `verify_evidence.py`
- `stress_test.py`

## Signing invariant
- `signed_payload = canonical_json(record_fields_without_signature)`
- `record_hash = sha256(signed_payload)`
- `signature = ed25519_sign(signed_payload)`

## Quick checks
```bash
python -m py_compile decision_ledger.py ledger_writer.py verify_evidence.py stress_test.py
python stress_test.py --threads 10 --writes 200
```
