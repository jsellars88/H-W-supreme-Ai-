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