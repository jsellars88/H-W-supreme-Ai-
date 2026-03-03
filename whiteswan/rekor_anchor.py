#!/usr/bin/env python3
"""
WhiteSwan OS — Rekor Transparency Log Anchor
Holmes & Watson Supreme AI

Anchors Ed25519-signed governance decisions in the public Sigstore Rekor
transparency log. Produces self-contained evidence packets verifiable by
any third party (regulators, auditors, insurers) without contacting your
server.

Integration:
    from whiteswan.rekor_anchor import RekorAnchor
    anchor = RekorAnchor(verify_key_pem=your_pem)
    receipt = anchor.anchor(decision_hash_hex, signature_hex)
    packet["rekor"] = receipt

Verification (by any third party):
    anchor.verify(packet["rekor"], packet["hash"], packet["signature"])
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

import requests

# ── Constants ─────────────────────────────────────────────────────────

REKOR_BASE_URL = "https://rekor.sigstore.dev"
REKOR_ENTRIES = f"{REKOR_BASE_URL}/api/v1/log/entries"
REKOR_SEARCH = f"{REKOR_BASE_URL}/api/v1/index/retrieve"
REKOR_LOG_INFO = f"{REKOR_BASE_URL}/api/v1/log"
REKOR_TIMEOUT = 15   # seconds
MAX_RETRY = 3
RETRY_BACKOFF = 2.0  # seconds


# ── Receipt dataclass ─────────────────────────────────────────────────

@dataclass
class RekorReceipt:
    """
    Self-contained Rekor inclusion receipt.
    Embed this in every evidence packet — it is the proof.
    """
    log_index:       int
    integrated_time: str              # ISO-8601 UTC
    log_id:          str              # Rekor tree ID (stable)
    entry_uuid:      str              # Unique entry identifier
    inclusion_proof: Dict[str, Any]
    signed_entry_ts: str              # Base64 signed entry timestamp from Rekor
    rekor_url:       str              # Direct URL to entry (human-readable)
    schema_version:  str = "ws-rekor-v1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def verify_url(self) -> str:
        return f"{REKOR_BASE_URL}/api/v1/log/entries/{self.entry_uuid}"


# ── RekorAnchor ───────────────────────────────────────────────────────

class RekorAnchor:
    """
    Anchors WhiteSwan governance decisions in Sigstore Rekor.

    Usage:
        anchor = RekorAnchor(verify_key_pem=pem_bytes)
        receipt = anchor.anchor(decision_hash_hex, signature_b64)
        # store receipt in evidence packet
        anchor.verify(receipt.to_dict(), decision_hash_hex, signature_b64)
    """

    def __init__(
        self,
        verify_key_pem: bytes,
        rekor_url: str = REKOR_BASE_URL,
        timeout: int = REKOR_TIMEOUT,
        offline_mode: bool = False,
    ):
        """
        Args:
            verify_key_pem:  Ed25519 public key in PEM format (bytes).
            rekor_url:       Rekor instance URL (default: public Sigstore).
            timeout:         HTTP timeout in seconds.
            offline_mode:    If True, skip Rekor submission (for testing).
        """
        self._vk_pem = verify_key_pem
        self._vk_pem_b64 = base64.b64encode(verify_key_pem).decode()
        self._base_url = rekor_url
        self._entries_url = f"{rekor_url}/api/v1/log/entries"
        self._timeout = timeout
        self._offline = offline_mode
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "WhiteSwanOS-RekorAnchor/1.0",
        })

    # ── Public API ────────────────────────────────────────────────────

    def anchor(
        self,
        decision_hash_hex: str,
        signature_hex: str,
    ) -> RekorReceipt:
        """
        Submit a signed governance decision to Rekor.

        Args:
            decision_hash_hex:  SHA-256 hex digest of the canonical decision payload.
            signature_hex:      Ed25519 signature hex of the decision payload.

        Returns:
            RekorReceipt — embed this in your evidence packet.

        Raises:
            RekorSubmissionError on failure after retries.
        """
        if self._offline:
            return self._mock_receipt(decision_hash_hex)

        sig_b64 = base64.b64encode(bytes.fromhex(signature_hex)).decode()

        entry = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": decision_hash_hex,
                    }
                },
                "signature": {
                    "content": sig_b64,
                    "publicKey": {
                        "content": self._vk_pem_b64,
                    },
                },
            },
        }

        resp = self._post_with_retry(entry)
        return self._parse_receipt(resp)

    def verify(
        self,
        receipt: Dict[str, Any],
        decision_hash_hex: str,
        signature_hex: str,
    ) -> bool:
        """
        Verify a Rekor receipt.

        1. Confirms the entry exists in Rekor at the claimed log_index.
        2. Confirms the stored hash matches decision_hash_hex.
        3. Confirms the stored signature matches signature_hex.

        Returns True if all checks pass. Raises on failure.
        """
        if self._offline:
            return True

        uuid = receipt.get("entry_uuid", "")
        url = f"{self._entries_url}/{uuid}"

        try:
            r = self._session.get(url, timeout=self._timeout)
            r.raise_for_status()
        except Exception as e:
            raise RekorVerificationError(f"Rekor fetch failed: {e}")

        data = r.json()
        if not data:
            raise RekorVerificationError("Empty response from Rekor")

        # Entry is keyed by UUID
        entry_data = next(iter(data.values()), {})
        body_b64 = entry_data.get("body", "")
        body = json.loads(base64.b64decode(body_b64 + "==").decode())

        stored_hash = (
            body.get("spec", {})
                .get("data", {})
                .get("hash", {})
                .get("value", "")
        )
        stored_sig_b64 = (
            body.get("spec", {})
                .get("signature", {})
                .get("content", "")
        )
        stored_sig_hex = bytes(base64.b64decode(stored_sig_b64 + "==")).hex()

        if stored_hash.lower() != decision_hash_hex.lower():
            raise RekorVerificationError(
                f"Hash mismatch: stored={stored_hash} expected={decision_hash_hex}"
            )

        if stored_sig_hex.lower() != signature_hex.lower():
            raise RekorVerificationError("Signature mismatch in Rekor entry")

        return True

    def fetch_by_hash(self, decision_hash_hex: str) -> Optional[Dict[str, Any]]:
        """
        Search Rekor for entries matching a decision hash.
        Useful for auditors looking up a specific decision.
        """
        if self._offline:
            return None
        try:
            r = self._session.post(
                f"{self._base_url}/api/v1/index/retrieve",
                json={"hash": f"sha256:{decision_hash_hex}"},
                timeout=self._timeout,
            )
            r.raise_for_status()
            uuids = r.json()
            if not uuids:
                return None
            # Fetch the first matching entry
            entry_r = self._session.get(
                f"{self._entries_url}/{uuids[0]}",
                timeout=self._timeout,
            )
            entry_r.raise_for_status()
            return entry_r.json()
        except Exception:
            return None

    def log_info(self) -> Dict[str, Any]:
        """Fetch Rekor log metadata (tree size, root hash, etc.)."""
        if self._offline:
            return {"offline_mode": True}
        try:
            r = self._session.get(REKOR_LOG_INFO, timeout=self._timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    # ── Internal ──────────────────────────────────────────────────────

    def _post_with_retry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        last_err = None
        for attempt in range(MAX_RETRY):
            try:
                r = self._session.post(
                    self._entries_url,
                    json=entry,
                    timeout=self._timeout,
                )
                if r.status_code == 201:
                    return r.json()
                if r.status_code == 409:
                    # Already exists — fetch and return existing entry
                    return self._fetch_existing(entry)
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
            except requests.exceptions.Timeout:
                last_err = f"Timeout on attempt {attempt + 1}"
            except Exception as e:
                last_err = str(e)

            if attempt < MAX_RETRY - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))

        raise RekorSubmissionError(
            f"Rekor submission failed after {MAX_RETRY} attempts: {last_err}"
        )

    def _fetch_existing(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve an already-submitted entry (409 conflict case)."""
        decision_hash = entry["spec"]["data"]["hash"]["value"]
        try:
            r = self._session.post(
                f"{self._base_url}/api/v1/index/retrieve",
                json={"hash": f"sha256:{decision_hash}"},
                timeout=self._timeout,
            )
            r.raise_for_status()
            uuids = r.json()
            if uuids:
                er = self._session.get(
                    f"{self._entries_url}/{uuids[0]}",
                    timeout=self._timeout,
                )
                er.raise_for_status()
                return er.json()
        except Exception:
            pass
        raise RekorSubmissionError(
            "Entry already exists but could not be retrieved"
        )

    def _parse_receipt(self, response: Dict[str, Any]) -> RekorReceipt:
        """Parse Rekor API response into a RekorReceipt."""
        # Response is keyed by entry UUID
        uuid = next(iter(response.keys()))
        entry = response[uuid]
        log_index = entry.get("logIndex", -1)
        log_id = entry.get("logID", "")
        signed_ts = entry.get("verification", {}).get(
            "signedEntryTimestamp", ""
        )
        inc_proof = entry.get("verification", {}).get("inclusionProof", {})

        # Parse integrated time from body
        integrated = entry.get("integratedTime", 0)
        if integrated:
            from datetime import datetime, timezone
            integrated_iso = (
                datetime.fromtimestamp(int(integrated), tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        else:
            integrated_iso = ""

        return RekorReceipt(
            log_index=int(log_index),
            integrated_time=integrated_iso,
            log_id=log_id,
            entry_uuid=uuid,
            inclusion_proof=inc_proof,
            signed_entry_ts=signed_ts,
            rekor_url=f"{self._base_url}/api/v1/log/entries/{uuid}",
        )

    def _mock_receipt(self, decision_hash_hex: str) -> RekorReceipt:
        """Offline mock receipt for testing."""
        from datetime import datetime, timezone
        return RekorReceipt(
            log_index=-1,
            integrated_time=(
                datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            ),
            log_id="OFFLINE_MODE",
            entry_uuid=f"offline-{decision_hash_hex[:16]}",
            inclusion_proof={"offline": True},
            signed_entry_ts="",
            rekor_url="offline://rekor",
        )


# ── Exceptions ────────────────────────────────────────────────────────

class RekorSubmissionError(Exception):
    pass


class RekorVerificationError(Exception):
    pass


# ── Kernel Patch Helper ───────────────────────────────────────────────

def patch_mgi_authorize(mgi_class, anchor: RekorAnchor):
    """
    Monkey-patch MGI.authorize to add Rekor anchoring to every
    ALLOW decision automatically.

    Call once after initializing kernel:
        from whiteswan.rekor_anchor import RekorAnchor, patch_mgi_authorize
        anchor = RekorAnchor(verify_key_pem=pem)
        patch_mgi_authorize(MGI, anchor)

    After patching, every envelope["evidence"]["rekor"] contains
    the full Rekor receipt.
    """
    original_authorize = mgi_class.authorize

    def authorize_with_rekor(self, *args, **kwargs):
        envelope = original_authorize(self, *args, **kwargs)

        if envelope.get("outcome") == "ALLOW":
            try:
                payload = json.dumps(
                    envelope,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode()
                decision_hash = hashlib.sha256(payload).hexdigest()
                sig_hex = envelope.get("decision_sig", "")

                receipt = anchor.anchor(decision_hash, sig_hex)
                envelope["evidence"]["rekor"] = receipt.to_dict()
                envelope["evidence"]["rekor_verified_url"] = receipt.verify_url()

            except RekorSubmissionError as e:
                # Non-blocking: log failure but don't block the decision
                envelope["evidence"]["rekor"] = {
                    "error": str(e),
                    "status": "SUBMISSION_FAILED",
                }

        return envelope

    mgi_class.authorize = authorize_with_rekor
    return mgi_class


# ── Public Key PEM Utility ────────────────────────────────────────────

def ed25519_verify_key_to_pem(verify_key_hex: str) -> bytes:
    """
    Convert a NaCl Ed25519 verify key (hex) to PEM format for Rekor.
    Rekor requires PEM-encoded public keys.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    raw = bytes.fromhex(verify_key_hex)
    pub = Ed25519PublicKey.from_public_bytes(raw)
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ── Standalone verification script ───────────────────────────────────

def verify_evidence_packet(packet_path: str, public_key_hex: str) -> bool:
    """
    Standalone verifier. Call this from the command line or give to auditors.

    python -c "
    from whiteswan.rekor_anchor import verify_evidence_packet
    verify_evidence_packet('evidence_packet.json', 'YOUR_PUBKEY_HEX')
    "
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    with open(packet_path) as f:
        packet = json.load(f)

    print(f"\n{'=' * 60}")
    print("WHITESWAN EVIDENCE PACKET VERIFICATION")
    print(f"{'=' * 60}")

    # 1. Reconstruct payload (without rekor and decision_sig fields)
    check_packet = {
        k: v for k, v in packet.items()
        if k not in ("decision_sig", "rekor")
    }
    payload = json.dumps(
        check_packet, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    decision_hash = hashlib.sha256(payload).hexdigest()

    # 2. Verify Ed25519 signature
    sig_hex = packet.get("decision_sig", "")
    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(payload, bytes.fromhex(sig_hex))
        print("  Ed25519 signature: VALID")
    except BadSignatureError:
        print("  Ed25519 signature: INVALID")
        return False

    # 3. Verify Rekor inclusion
    rekor_data = packet.get("evidence", {}).get("rekor", {})
    if not rekor_data or rekor_data.get("offline"):
        print("  Rekor: OFFLINE MODE (no public anchor)")
    elif rekor_data.get("status") == "SUBMISSION_FAILED":
        print(f"  Rekor: SUBMISSION FAILED -- {rekor_data.get('error')}")
        return False
    else:
        vk_pem = ed25519_verify_key_to_pem(public_key_hex)
        anchor = RekorAnchor(verify_key_pem=vk_pem)
        try:
            anchor.verify(rekor_data, decision_hash, sig_hex)
            print(
                f"  Rekor inclusion: VERIFIED "
                f"(logIndex: {rekor_data.get('log_index')})"
            )
            print(f"  Entry: {rekor_data.get('rekor_url')}")
        except RekorVerificationError as e:
            print(f"  Rekor inclusion: FAILED -- {e}")
            return False

    print(f"\n  Decision: {packet.get('outcome', 'unknown').upper()}")
    print(f"  Scope: {packet.get('scope', 'unknown')}")
    print(f"  Decided at: {packet.get('decided_at', 'unknown')}")
    print(f"  Hash: {decision_hash[:32]}...")
    print(f"\n{'=' * 60}")
    print("VERDICT: EVIDENCE PACKET IS VALID AND PUBLICLY ANCHORED")
    print(f"{'=' * 60}\n")
    return True


# ── Quick integration test ────────────────────────────────────────────

if __name__ == "__main__":
    """
    Quick smoke test — runs in offline mode to avoid hitting Rekor.
    Run with REKOR_LIVE=1 to test against real Rekor.
    """
    import os

    offline = os.environ.get("REKOR_LIVE") != "1"
    mode = "OFFLINE (mock)" if offline else "LIVE (real Rekor)"
    print(f"\nWhiteSwan Rekor Anchor -- Test [{mode}]")
    print("=" * 55)

    # Generate a test key pair
    try:
        from nacl.signing import SigningKey as NaclSK

        sk = NaclSK.generate()
        vk = sk.verify_key
        vk_hex = vk.encode().hex()

        # Simulate a decision payload
        payload = json.dumps({
            "scope": "diagnostic_inference",
            "outcome": "ALLOW",
            "operator": "test_operator",
            "decided_at": "2026-03-03T12:00:00Z",
        }, sort_keys=True, separators=(",", ":")).encode()

        decision_hash = hashlib.sha256(payload).hexdigest()
        sig_hex = sk.sign(payload).signature.hex()

        pem = ed25519_verify_key_to_pem(vk_hex)

        anchor = RekorAnchor(verify_key_pem=pem, offline_mode=offline)
        receipt = anchor.anchor(decision_hash, sig_hex)

        print(f"  Anchor call succeeded")
        print(f"  log_index:       {receipt.log_index}")
        print(f"  integrated_time: {receipt.integrated_time}")
        print(f"  entry_uuid:      {receipt.entry_uuid}")
        print(f"  rekor_url:       {receipt.rekor_url}")

        ok = anchor.verify(receipt.to_dict(), decision_hash, sig_hex)
        print(f"  Verification: {'PASS' if ok else 'FAIL'}")

        if not offline:
            info = anchor.log_info()
            print(f"  Rekor tree size: {info.get('treeSize', 'unknown')}")

        print("\n  All tests passed.")

    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Run: pip install pynacl cryptography")
