from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List


class DecisionLedger:
    def __init__(self, db_path: str = "ledger.db") -> None:
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                actor_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                tier INTEGER NOT NULL,
                allowed INTEGER NOT NULL,
                reason TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def _head(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM decisions ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "0" * 64

    def append(
        self,
        actor_id: str,
        tenant_id: str,
        action: str,
        tier: int,
        allowed: bool,
        reason: str,
        metadata: Dict[str, Any],
    ) -> str:
        decision_id = str(uuid.uuid4())
        ts = time.time()
        prev_hash = self._head()

        canonical = {
            "id": decision_id,
            "ts": ts,
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "action": action,
            "tier": tier,
            "allowed": allowed,
            "reason": reason,
            "metadata": metadata,
            "prev_hash": prev_hash,
        }

        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        self.conn.execute(
            """
            INSERT INTO decisions (
                id, ts, actor_id, tenant_id, action, tier,
                allowed, reason, metadata_json, prev_hash, hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_id,
                ts,
                actor_id,
                tenant_id,
                action,
                tier,
                int(allowed),
                reason,
                json.dumps(metadata, sort_keys=True),
                prev_hash,
                digest,
            ),
        )
        self.conn.commit()
        return decision_id

    def verify_chain(self) -> bool:
        rows = self.conn.execute(
            """
            SELECT id, ts, actor_id, tenant_id, action, tier,
                   allowed, reason, metadata_json, prev_hash, hash
            FROM decisions
            ORDER BY ts ASC
            """
        ).fetchall()

        expected_prev = "0" * 64
        for row in rows:
            (
                decision_id,
                ts,
                actor_id,
                tenant_id,
                action,
                tier,
                allowed,
                reason,
                metadata_json,
                prev_hash,
                stored_hash,
            ) = row
            canonical = {
                "id": decision_id,
                "ts": ts,
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "action": action,
                "tier": tier,
                "allowed": bool(allowed),
                "reason": reason,
                "metadata": json.loads(metadata_json),
                "prev_hash": prev_hash,
            }
            computed = hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

            if prev_hash != expected_prev or computed != stored_hash:
                return False
            expected_prev = stored_hash
        return True

    def list_all(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT id, ts, actor_id, tenant_id, action, tier,
                   allowed, reason, metadata_json, prev_hash, hash
            FROM decisions
            ORDER BY ts ASC
            """
        ).fetchall()

        out = []
        for row in rows:
            out.append(
                {
                    "id": row[0],
                    "ts": row[1],
                    "actor_id": row[2],
                    "tenant_id": row[3],
                    "action": row[4],
                    "tier": row[5],
                    "allowed": bool(row[6]),
                    "reason": row[7],
                    "metadata": json.loads(row[8]),
                    "prev_hash": row[9],
                    "hash": row[10],
                }
            )
        return out
