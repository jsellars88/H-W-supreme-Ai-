# WhiteSwan Governance Kernel

This repository contains the core implementation of the WhiteSwan Governance Kernel v3.1, a production reference implementation providing secure, tiered governance using Ed25519 operator signatures.

## Repository Structure

- `src/`: Contains the main governance kernel logic.
- `tests/`: Unit tests for the governance kernel.
- `docs/`: Documentation including threat models, specifications, and deployment guides.

## Features

Key features of the governance kernel include:
- Cryptographic authority enforcement with Ed25519.
- Hash-chained audit logs for tamper evidence.
- Role-based operator authorization with scope limits.

## Getting Started

### Install Dependencies
Run:
```
pip install -r requirements.txt
```

### Run Tests
```
pytest
```

## WhiteSwan v3.5 API Layer

The repository also contains `whiteswan_api_v35.py`, a FastAPI HTTP surface for the WhiteSwan governance kernel.

Before running it, install API dependencies:

```
pip install -r requirements-whiteswan-api.txt
```

And ensure `kernel_v34` and `kernel_v35` are available on `PYTHONPATH` (these kernel modules are not bundled in this repository).
