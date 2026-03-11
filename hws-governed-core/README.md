# HWS Governed Core

Minimal governed execution core with four components:

1. API Gateway (`src/gateway/main.py`)
2. Identity/Auth stub (`src/identity/auth.py`)
3. Governance Kernel (`src/governance/kernel.py`)
4. Decision Ledger (`src/ledger/ledger.py`)

## Run

```bash
pip install -e .
uvicorn gateway.main:app --reload --app-dir src
```

## Test

```bash
pytest
```

## Flow checks

1. Low risk (`T0_SENSE`) executes without handshake.
2. High risk (`T3_EXECUTE`) blocks without handshake.
3. High risk executes with valid handshake.
4. Ledger chain verifies integrity.
