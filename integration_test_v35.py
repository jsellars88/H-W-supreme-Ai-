"""Compatibility shim for relocated integration tests."""

from tests.integration_test_v35 import *  # noqa: F401,F403
import tests.integration_test_v35 as _it


if __name__ == "__main__":
    print("=" * 70)
    print("WhiteSwan OS v3.5 — Integration Test Suite")
    print("Holmes & Watson Supreme AI™")
    print("=" * 70)
    _it.run_all()
    print("\n" + "=" * 70)
    for t in _it.TESTS:
        print(t)
    print("=" * 70)
    print(f"\nRESULTS: {_it.PASS} passed, {_it.FAIL} failed, {_it.PASS + _it.FAIL} total")
    raise SystemExit(1 if _it.FAIL else 0)
