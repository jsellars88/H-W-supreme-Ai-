#!/usr/bin/env python3
"""ledger_writer.py — Single-Writer Queue for DecisionLedger v0.4."""

from __future__ import annotations

import queue
import threading
from typing import Any

from decision_ledger import DecisionLedger, DecisionRecord

try:
    from rekor_anchor import RekorAnchor, ed25519_verify_key_to_pem

    _REKOR_AVAILABLE = True
except ImportError:
    _REKOR_AVAILABLE = False


class RekorReceipt:
    """Minimal receipt stored per decision."""

    __slots__ = (
        "decision_id",
        "record_hash",
        "log_index",
        "integrated_time",
        "entry_uuid",
        "proof_url",
    )

    def __init__(
        self,
        decision_id,
        record_hash,
        log_index,
        integrated_time,
        entry_uuid,
        proof_url,
    ):
        self.decision_id = decision_id
        self.record_hash = record_hash
        self.log_index = log_index
        self.integrated_time = integrated_time
        self.entry_uuid = entry_uuid
        self.proof_url = proof_url

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "record_hash": self.record_hash,
            "log_index": self.log_index,
            "integrated_time": self.integrated_time,
            "entry_uuid": self.entry_uuid,
            "proof_url": self.proof_url,
            "verification": (
                f"curl {self.proof_url}"
                if self.proof_url and not self.proof_url.startswith("offline")
                else "offline_mode"
            ),
        }


class LedgerWriter:
    """Single-writer enforcement wrapper for DecisionLedger."""

    def __init__(
        self,
        db_path: str = "decisions.db",
        key_path: str | None = None,
        max_queue: int = 10_000,
        enable_rekor: bool = False,
        rekor_server: str = "https://rekor.sigstore.dev",
        rekor_offline: bool = False,
    ):
        self._q: queue.Queue[tuple[dict[str, Any], queue.Queue]] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._pubkey_hex = None
        self._key_id = None
        self._rekor_receipts: list[RekorReceipt] = []
        self._receipts_lock = threading.Lock()

        self.enable_rekor = enable_rekor and (_REKOR_AVAILABLE or rekor_offline)

        if enable_rekor and not _REKOR_AVAILABLE and not rekor_offline:
            print("⚠  rekor_anchor not found — continuing without Rekor.")
            self.enable_rekor = False

        self._thread = threading.Thread(
            target=self._worker,
            args=(db_path, key_path, rekor_server, rekor_offline),
            daemon=True,
            name="LedgerWriterThread",
        )
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("LedgerWriter: writer thread failed to start in 10s")

    @property
    def pubkey_hex(self) -> str | None:
        return self._pubkey_hex

    @property
    def key_id(self) -> str | None:
        return self._key_id

    def submit(self, **kwargs) -> DecisionRecord:
        rq: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._q.put((kwargs, rq))
        result = rq.get()
        if isinstance(result, Exception):
            raise result
        return result

    def verify_chain(self) -> dict[str, Any]:
        rq: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._q.put(({"__verify__": True}, rq))
        result = rq.get()
        if isinstance(result, Exception):
            raise result
        return result

    def export_proof(self, decision_id: str) -> dict[str, Any]:
        rq: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._q.put(({"__export_proof__": decision_id}, rq))
        result = rq.get()
        if isinstance(result, Exception):
            raise result
        return result

    def get_rekor_receipts(self, decision_id: str | None = None) -> list[dict[str, Any]]:
        with self._receipts_lock:
            receipts = list(self._rekor_receipts)
        if decision_id:
            receipts = [r for r in receipts if r.decision_id == decision_id]
        return [r.to_dict() for r in receipts]

    def close(self, timeout: float = 10.0):
        self._stop.set()
        try:
            self._q.put_nowait(({"__shutdown__": True}, queue.Queue(maxsize=1)))
        except queue.Full:
            pass
        self._thread.join(timeout=timeout)

    def _worker(
        self,
        db_path: str,
        key_path: str | None,
        rekor_server: str,
        rekor_offline: bool,
    ):
        ledger = DecisionLedger(db_path=db_path, key_path=key_path)
        self._pubkey_hex = ledger.pubkey_hex
        self._key_id = ledger.key_id

        anchor: RekorAnchor | None = None
        if self.enable_rekor:
            try:
                if _REKOR_AVAILABLE:
                    pem = ed25519_verify_key_to_pem(ledger.pubkey_hex)
                    anchor = RekorAnchor(
                        verify_key_pem=pem,
                        rekor_url=rekor_server,
                        offline_mode=rekor_offline,
                    )
            except Exception as e:
                print(f"⚠  Rekor init failed: {e} — continuing without anchoring.")
                self.enable_rekor = False

        self._ready.set()

        try:
            while not self._stop.is_set():
                try:
                    kwargs, rq = self._q.get(timeout=0.5)
                except queue.Empty:
                    continue

                if kwargs.get("__shutdown__"):
                    break
                if kwargs.get("__verify__"):
                    rq.put(ledger.verify_chain())
                    continue

                export_id = kwargs.get("__export_proof__")
                if export_id:
                    rq.put(ledger.export_proof(export_id))
                    continue

                try:
                    rec = ledger.record(**kwargs)
                    if self.enable_rekor and anchor:
                        self._do_rekor_anchor(anchor, rec)
                    rq.put(rec)
                except Exception as e:
                    rq.put(e)
        finally:
            ledger.close()

    def _do_rekor_anchor(self, anchor: RekorAnchor, rec: DecisionRecord):
        try:
            receipt = anchor.anchor(rec.record_hash, rec.signature)
            rr = RekorReceipt(
                decision_id=rec.decision_id,
                record_hash=rec.record_hash,
                log_index=receipt.log_index,
                integrated_time=receipt.integrated_time,
                entry_uuid=receipt.entry_uuid,
                proof_url=receipt.rekor_url,
            )
            with self._receipts_lock:
                self._rekor_receipts.append(rr)
        except Exception as e:
            print(f"⚠  Rekor anchor failed [{rec.decision_id[:8]}]: {e}")
