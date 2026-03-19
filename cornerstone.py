#!/usr/bin/env python3
"""
cornestone.py - White Swan OS Governance Gate + Decision Ledger
v2.1 — Self-contained reference implementation

Features
- FastAPI governance gateway
- SQLite append-only ledger (WAL)
- Linear hash-chain + Ed25519 signatures
- Merkle tree root + inclusion proofs
- Handshake tokens with TTL
- T0-T4 action tiers
- T4 requires two distinct operators
- Atomic token consumption
- Simple verification endpoints

Install:
  pip install fastapi uvicorn pynacl

Run:
  python cornerstone.py
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Request

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

APP_HOST = os.getenv("HOST", "0.0.0.0")
APP_PORT = int(os.getenv("PORT", "8080"))
DB_PATH = os.getenv("DB_PATH", "cornerstone.db")
KEYS_DIR = Path(os.getenv("KEYS_DIR", ".cornerstone_keys"))
HANDSHAKE_TTL = int(os.getenv("HANDSHAKE_TTL", "300"))

TIER_LEVELS = {
    "T0_SAFE": 0,
    "T1_TRIVIAL": 1,
    "T2_SENSITIVE": 2,
    "T3_HIGH": 3,
    "T4_IRREVERSIBLE": 4,
}
TIERS_REQUIRING_TOKEN = {"T2_SENSITIVE", "T3_HIGH", "T4_IRREVERSIBLE"}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_z() -> str:
    return now_utc().isoformat().replace("+00:00", "Z")


def z_to_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()