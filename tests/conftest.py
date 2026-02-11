import os

# Keep tests deterministic and in-memory by default.
os.environ.setdefault("WS_DB_FILE", ":memory:")
os.environ.setdefault("WS_SEAL_INTERVAL", "50")
