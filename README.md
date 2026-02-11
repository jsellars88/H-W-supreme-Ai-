# WhiteSwan OS v3.5 — Holmes & Watson Supreme AI

WhiteSwan OS is a governance enforcement middleware that authorizes (or blocks) AI actions before they reach a model provider. It enforces constitutional invariants, records cryptographic evidence capsules, and enters Safe Arrest State (SAS) when uncertainty or policy violations are detected.

## What this repository includes

- `whiteswan_api_v35.py` — FastAPI service exposing governance endpoints.
- `kernel_v35.py` — v3.5 constitutional governance kernel implementation.
- `integration_test_v35.py` — end-to-end governance harness covering cross-subsystem checks.
- `tests/test_whiteswan_governance_kernel.py` — focused regression tests for core kernel behavior.
- `WHITE_SWAN_OS_V3_5_ARCHITECTURE_GUIDE.md` — architecture and subsystem guide.
- `RELEASE_NOTES.md` — release and mergeability notes.

Legacy web artifacts (`index.html`, `style.css`, `app.js`, etc.) remain in-repo, but the primary maintained runtime is WhiteSwan OS governance middleware.

## Quick start

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

For full v3.5 API dependencies (FastAPI stack), use:

```bash
pip install -e .
```

### 2) Run the API

```bash
python whiteswan_api_v35.py
```

By default, the API binds to `http://0.0.0.0:8000`.

### 3) Run tests

```bash
PYTHONPATH=. pytest -q
```

Optional full integration harness:

```bash
python integration_test_v35.py
```

## Architecture documentation

See `WHITE_SWAN_OS_V3_5_ARCHITECTURE_GUIDE.md` for the constitutional architecture specification (tiers, invariants, SAS, subsystems, API groups, and deployment model).

## Release notes

See `RELEASE_NOTES.md` for release and mergeability history.
