"""
WhiteSwan OS v3.5 — Application entry point alias.

Re-exports the FastAPI ``app`` from ``whiteswan.whiteswan_api_v35`` so that
``from app_v35 import app`` remains stable for callers.
"""

from whiteswan.whiteswan_api_v35 import app  # noqa: F401

__all__ = ["app"]
