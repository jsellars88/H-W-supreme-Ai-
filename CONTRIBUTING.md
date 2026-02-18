# Contributing to WhiteSwan OS

Pull requests welcome. Please open an issue first for major changes.

## Development Setup

```bash
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-
pip install -r requirements.txt
```

## Running Tests

```bash
# Unit tests
python -m pytest tests/ -v

# Full integration suite (73 tests, all 11 subsystems)
python integration_test_v35.py
```

## Code Style

This project uses [ruff](https://github.com/astral-sh/ruff) for linting. Configuration is in `pyproject.toml`.

```bash
ruff check .
```

## What We Accept

- Bug fixes with test coverage
- New subsystem implementations following the §-section pattern in `kernel_v35.py`
- API endpoint additions with corresponding integration test assertions
- Documentation improvements
- Compliance framework mappings (NIST, EU AI Act, ISO 42001, SOC 2)

## Commit Messages

Use clear, imperative-mood messages:

```
Add TPI challenge expiry with configurable TTL
Fix CEL risk weight calculation for geofence violations
Update integration tests for MKC quarantine edge case
```

## Architecture Rules

1. Every governance decision must be logged to Guardian Vault X
2. Every new subsystem must be wired into `WhiteSwanKernel35.__init__`
3. Every API endpoint must be guarded by `_require_attr` and `_check_auth`
4. Tests must pass (`pytest` + `integration_test_v35.py`) before merge
