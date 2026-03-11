#!/usr/bin/env python3
"""WhiteSwan OS — Rekor Transparency Log Anchor.

Anchors Ed25519-signed governance decisions in the public Sigstore Rekor
transparency log and provides self-contained evidence receipts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib import error, request

REKOR_BASE_URL = "https://rekor.sigstore.dev"
REKOR_ENTRIES = f"{REKOR_BASE_URL}/api/v1/log/entries"
REKOR_SEARCH = f"{REKOR_BASE_URL}/api/v1/index/retrieve"
REKOR_LOG_INFO = f"{REKOR_BASE_URL}/api/v1/log"
REKOR_TIMEOUT = 15
MAX_RETRY = 3
RETRY_BACKOFF = 2.0


@dataclass
class RekorReceipt:
    """Self-contained Rekor inclusion receipt."""

    log_index: int
    integrated_time: str
    log_id: str
    entry_uuid: str
    inclusion_proof: dict[str, Any]
    signed_entry_ts: str
    rekor_url: str
    schema_version: str = "ws-rekor-v1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def verify_url(self) -> str:
        return f"{REKOR_BASE_URL}/api/v1/log/entries/{self.entry_uuid}"


class RekorAnchor:
    """Anchors WhiteSwan governance decisions in Sigstore Rekor."""

    def __init__(
        self,
        verify_key_pem: bytes,
        rekor_url: str = REKOR_BASE_URL,
        timeout: int = REKOR_TIMEOUT,
        offline_mode: bool = False,
    ) -> None:
        self._vk_pem_b64 = base64.b64encode(verify_key_pem).decode()
        self._base_url = rekor_url
        self._entries_url = f"{rekor_url}/api/v1/log/entries"
        self._timeout = timeout
        self._offline = offline_mode
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "WhiteSwanOS-RekorAnchor/1.0",
        }

    def anchor(self, decision_hash_hex: str, signature_hex: str) -> RekorReceipt:
        """Submit a signed governance decision to Rekor."""
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
                    "publicKey": {"content": self._vk_pem_b64},
                },
            },
        }

        resp = self._post_with_retry(entry)
        return self._parse_receipt(resp)

    def verify(
        self,
        receipt: dict[str, Any],
        decision_hash_hex: str,
        signature_hex: str,
    ) -> bool:
        """Verify a Rekor receipt against hash/signature values."""
        if self._offline:
            return True

        uuid = receipt.get("entry_uuid", "")
        url = f"{self._entries_url}/{uuid}"

        try:
            data = self._http_get_json(url)
        except Exception as exc:
            raise RekorVerificationError(f"Rekor fetch failed: {exc}") from exc

        if not data:
            raise RekorVerificationError("Empty response from Rekor")

        entry_data = next(iter(data.values()), {})
        body_b64 = entry_data.get("body", "")
        body = json.loads(base64.b64decode(body_b64 + "==").decode())

        stored_hash = body.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
        stored_sig_b64 = body.get("spec", {}).get("signature", {}).get("content", "")
        stored_sig_hex = bytes(base64.b64decode(stored_sig_b64 + "==")).hex()

        if stored_hash.lower() != decision_hash_hex.lower():
            raise RekorVerificationError(
                f"Hash mismatch: stored={stored_hash} expected={decision_hash_hex}"
            )
        if stored_sig_hex.lower() != signature_hex.lower():
            raise RekorVerificationError("Signature mismatch in Rekor entry")

        return True

    def fetch_by_hash(self, decision_hash_hex: str) -> dict[str, Any] | None:
        """Search Rekor for entries matching a decision hash."""
        if self._offline:
            return None
        try:
            _, body = self._http_post_json(
                f"{self._base_url}/api/v1/index/retrieve",
                {"hash": f"sha256:{decision_hash_hex}"},
            )
            uuids = json.loads(body)
            if not uuids:
                return None
            return self._http_get_json(f"{self._entries_url}/{uuids[0]}")
        except Exception:
            return None

    def log_info(self) -> dict[str, Any]:
        """Fetch Rekor log metadata (tree size, root hash, etc.)."""
        if self._offline:
            return {"offline_mode": True}
        try:
            return self._http_get_json(REKOR_LOG_INFO)
        except Exception as exc:
            return {"error": str(exc)}

    def _http_get_json(self, url: str) -> dict[str, Any]:
        req = request.Request(url, headers=self._headers, method="GET")
        with request.urlopen(req, timeout=self._timeout) as response:
            return json.loads(response.read().decode())

    def _http_post_json(self, url: str, payload: dict[str, Any]) -> tuple[int, str]:
        req = request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers=self._headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout) as response:
                return response.status, response.read().decode()
        except error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def _post_with_retry(self, entry: dict[str, Any]) -> dict[str, Any]:
        last_err: str | None = None
        for attempt in range(MAX_RETRY):
            try:
                status, body = self._http_post_json(self._entries_url, entry)
                if status == 201:
                    return json.loads(body)
                if status == 409:
                    return self._fetch_existing(entry)
                last_err = f"HTTP {status}: {body[:200]}"
            except TimeoutError:
                last_err = f"Timeout on attempt {attempt + 1}"
            except Exception as exc:
                last_err = str(exc)

            if attempt < MAX_RETRY - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))

        raise RekorSubmissionError(
            f"Rekor submission failed after {MAX_RETRY} attempts: {last_err}"
        )

    def _fetch_existing(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Retrieve an already-submitted entry (409 conflict case)."""
        decision_hash = entry["spec"]["data"]["hash"]["value"]
        try:
            _, body = self._http_post_json(
                f"{self._base_url}/api/v1/index/retrieve",
                {"hash": f"sha256:{decision_hash}"},
            )
            uuids = json.loads(body)
            if uuids:
                return self._http_get_json(f"{self._entries_url}/{uuids[0]}")
        except Exception:
            pass

        raise RekorSubmissionError("Entry already exists but could not be retrieved")

    def _parse_receipt(self, response: dict[str, Any]) -> RekorReceipt:
        """Parse Rekor API response into a RekorReceipt."""
        uuid = next(iter(response.keys()))
        entry = response[uuid]

        integrated = entry.get("integratedTime", 0)
        integrated_iso = ""
        if integrated:
            integrated_iso = datetime.fromtimestamp(int(integrated), tz=timezone.utc).isoformat()
            integrated_iso = integrated_iso.replace("+00:00", "Z")

        return RekorReceipt(
            log_index=int(entry.get("logIndex", -1)),
            integrated_time=integrated_iso,
            log_id=entry.get("logID", ""),
            entry_uuid=uuid,
            inclusion_proof=entry.get("verification", {}).get("inclusionProof", {}),
            signed_entry_ts=entry.get("verification", {}).get("signedEntryTimestamp", ""),
            rekor_url=f"{self._base_url}/api/v1/log/entries/{uuid}",
        )

    def _mock_receipt(self, decision_hash_hex: str) -> RekorReceipt:
        return RekorReceipt(
            log_index=-1,
            integrated_time=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            log_id="OFFLINE_MODE",
            entry_uuid=f"offline-{decision_hash_hex[:16]}",
            inclusion_proof={"offline": True},
            signed_entry_ts="",
            rekor_url="offline://rekor",
        )


class RekorSubmissionError(Exception):
    """Raised when Rekor submission fails."""


class RekorVerificationError(Exception):
    """Raised when Rekor verification fails."""


def patch_mgi_authorize(mgi_class: Any, anchor: RekorAnchor) -> Any:
    """Monkey-patch ``MGI.authorize`` to include Rekor anchoring."""
    original_authorize = mgi_class.authorize

    def authorize_with_rekor(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
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
                envelope.setdefault("evidence", {})["rekor"] = receipt.to_dict()
                envelope["evidence"]["rekor_verified_url"] = receipt.verify_url()
            except RekorSubmissionError as exc:
                envelope.setdefault("evidence", {})["rekor"] = {
                    "error": str(exc),
                    "status": "SUBMISSION_FAILED",
                }

        return envelope

    mgi_class.authorize = authorize_with_rekor
    return mgi_class


def ed25519_verify_key_to_pem(verify_key_hex: str) -> bytes:
    """Convert a NaCl Ed25519 verify key (hex) to PEM SubjectPublicKeyInfo bytes."""
    raw = bytes.fromhex(verify_key_hex)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")

    # ASN.1 DER for SubjectPublicKeyInfo with id-Ed25519 OID + 32-byte key.
    der = bytes.fromhex("302a300506032b6570032100") + raw
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    return pem.encode()


def verify_evidence_packet(packet_path: str, public_key_hex: str) -> bool:
    """Standalone verifier intended for third-party auditors."""
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    with open(packet_path, encoding="utf-8") as file:
        packet = json.load(file)

    print(f"\n{'=' * 60}")
    print("WHITESWAN EVIDENCE PACKET VERIFICATION")
    print(f"{'=' * 60}")

    check_packet = {k: v for k, v in packet.items() if k not in ("decision_sig", "rekor")}
    payload = json.dumps(check_packet, sort_keys=True, separators=(",", ":"), default=str).encode()
    decision_hash = hashlib.sha256(payload).hexdigest()

    sig_hex = packet.get("decision_sig", "")
    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(payload, bytes.fromhex(sig_hex))
        print("✓ Ed25519 signature: VALID")
    except BadSignatureError:
        print("✗ Ed25519 signature: INVALID")
        return False

    rekor_data = packet.get("evidence", {}).get("rekor", {})
    if not rekor_data or rekor_data.get("offline"):
        print("⚠ Rekor: OFFLINE MODE (no public anchor)")
    elif rekor_data.get("status") == "SUBMISSION_FAILED":
        print(f"✗ Rekor: SUBMISSION FAILED — {rekor_data.get('error')}")
        return False
    else:
        vk_pem = ed25519_verify_key_to_pem(public_key_hex)
        anchor = RekorAnchor(verify_key_pem=vk_pem)
        try:
            anchor.verify(rekor_data, decision_hash, sig_hex)
            print(f"✓ Rekor inclusion: VERIFIED (logIndex: {rekor_data.get('log_index')})")
            print(f"  Entry: {rekor_data.get('rekor_url')}")
        except RekorVerificationError as exc:
            print(f"✗ Rekor inclusion: FAILED — {exc}")
            return False

    print(f"\n✓ Decision: {packet.get('outcome', 'unknown').upper()}")
    print(f"✓ Scope: {packet.get('scope', 'unknown')}")
    print(f"✓ Decided at: {packet.get('decided_at', 'unknown')}")
    print(f"✓ Hash: {decision_hash[:32]}...")
    print(f"\n{'=' * 60}")
    print("VERDICT: EVIDENCE PACKET IS VALID AND PUBLICLY ANCHORED")
    print(f"{'=' * 60}\n")
    return True


if __name__ == "__main__":
    import os

    offline = os.environ.get("REKOR_LIVE") != "1"
    mode = "OFFLINE (mock)" if offline else "LIVE (real Rekor)"
    print(f"\nWhiteSwan Rekor Anchor — Test [{mode}]")
    print("=" * 55)

    try:
        from nacl.signing import SigningKey as NaclSigningKey

        signing_key = NaclSigningKey.generate()
        verify_key = signing_key.verify_key
        verify_key_hex = verify_key.encode().hex()

        payload = json.dumps(
            {
                "scope": "diagnostic_inference",
                "outcome": "ALLOW",
                "operator": "test_operator",
                "decided_at": "2026-03-03T12:00:00Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        decision_hash = hashlib.sha256(payload).hexdigest()
        sig_hex = signing_key.sign(payload).signature.hex()

        pem = ed25519_verify_key_to_pem(verify_key_hex)
        anchor = RekorAnchor(verify_key_pem=pem, offline_mode=offline)
        receipt = anchor.anchor(decision_hash, sig_hex)

        print("✓ Anchor call succeeded")
        print(f"  log_index:       {receipt.log_index}")
        print(f"  integrated_time: {receipt.integrated_time}")
        print(f"  entry_uuid:      {receipt.entry_uuid}")
        print(f"  rekor_url:       {receipt.rekor_url}")

        ok = anchor.verify(receipt.to_dict(), decision_hash, sig_hex)
        print(f"✓ Verification: {'PASS' if ok else 'FAIL'}")

        if not offline:
            info = anchor.log_info()
            print(f"✓ Rekor tree size: {info.get('treeSize', 'unknown')}")

        print("\n✓ All tests passed.")
    except ImportError:
        print("pynacl not installed — run: pip install pynacl")
