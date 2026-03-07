"""Compatibility shim for legacy imports and CLI execution."""

from whiteswan.verify_evidence import *  # noqa: F401,F403
from whiteswan.verify_evidence import main as _main


if __name__ == "__main__":
    raise SystemExit(_main())
