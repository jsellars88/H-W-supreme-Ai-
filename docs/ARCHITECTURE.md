# WhiteSwan OS Architecture

WhiteSwan OS is organized as a Python package (`whiteswan`) with three main layers:

1. **`kernel_v34.py`** — base constitutional governance kernel, policy, identity, replay, and audit substrate.
2. **`kernel_v35.py`** — v3.5 subsystem orchestration and extensions.
3. **`api.py`** — FastAPI HTTP surface exposing governance controls and telemetry endpoints.

The marketing/demo web assets are separated into `site/` so governance runtime code remains clear for technical evaluators.
