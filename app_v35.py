"""
WhiteSwan OS v3.5 — Application entry point alias.

Re-exports the FastAPI ``app`` from whiteswan_api_v35 so that both
``from app_v35 import app`` and ``from whiteswan_api_v35 import app``
work identically.
"""

from whiteswan_api_v35 import app  # noqa: F401

__all__ = ["app"]
