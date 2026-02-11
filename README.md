# WhiteSwan OS — AI Governance Enforcement Middleware

WhiteSwan OS is a constitutional AI governance layer for regulated systems.
It provides policy-constrained authorization, cryptographic audit trails,
operator identity controls, replayable decision records, and halt-on-violation
mechanisms designed for high-assurance environments.

## Repository layout

```text
whiteswan/                 Python package (governance product)
  __init__.py
  kernel_v34.py            Base governance kernel
  kernel_v35.py            v3.5 subsystem layer
  api.py                   FastAPI HTTP API

tests/                     Integration + unit tests
  integration_test_v35.py
  conftest.py

docs/                      Architecture and API docs
site/                      Marketing/demo website assets
```

## Quick start

```bash
pip install -e ".[dev]"
pytest tests/ -v
uvicorn whiteswan.api:app --port 8000
```

## Package usage

```bash
pip install .
python -c "import whiteswan; print(whiteswan.__version__)"
```

## Compliance positioning

WhiteSwan OS is intended as enforcement middleware aligned to governance and
risk-management frameworks (e.g., NIST AI RMF, regulated-sector controls,
and auditability requirements).

See `docs/ARCHITECTURE.md` and `docs/API.md` for technical details.
