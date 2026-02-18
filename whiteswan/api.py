"""
WhiteSwan OS v3.5 — Package-level API re-export.

Allows ``from whiteswan.api import app`` and ``uvicorn whiteswan.api:app``.
All endpoints are defined in ``whiteswan_api_v35.py`` at repo root.
"""

import sys
from pathlib import Path

# Ensure the repo root is importable when running from the package path
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from whiteswan_api_v35 import app  # noqa: E402, F401

__all__ = ["app"]
