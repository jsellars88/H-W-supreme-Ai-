import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from rekor_anchor import (
    RekorAnchor,
    RekorReceipt,
    ed25519_verify_key_to_pem,
    patch_mgi_authorize,
    verify_evidence_packet,
)


def _payload() -> bytes:
    return json.dumps(
        {
            "scope": "diagnostic_inference",
            "outcome": "ALLOW",
            "operator": "tester",
            "decided_at": "2026-03-03T12:00:00Z",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_anchor_offline_generates_mock_receipt():
    sk = SigningKey.generate()
    payload = _payload()
    decision_hash = hashlib.sha256(payload).hexdigest()
    sig_hex = sk.sign(payload).signature.hex()
    pem = ed25519_verify_key_to_pem(sk.verify_key.encode().hex())

    anchor = RekorAnchor(verify_key_pem=pem, offline_mode=True)
    receipt = anchor.anchor(decision_hash, sig_hex)

    assert isinstance(receipt, RekorReceipt)
    assert receipt.log_id == "OFFLINE_MODE"
    assert receipt.entry_uuid.startswith("offline-")
    assert anchor.verify(receipt.to_dict(), decision_hash, sig_hex) is True


def test_patch_mgi_authorize_inserts_rekor_evidence():
    sk = SigningKey.generate()
    pem = ed25519_verify_key_to_pem(sk.verify_key.encode().hex())
    anchor = RekorAnchor(verify_key_pem=pem, offline_mode=True)

    class DummyMgi:
        def authorize(self):
            payload = b"demo"
            return {
                "outcome": "ALLOW",
                "decision_sig": sk.sign(payload).signature.hex(),
                "evidence": {},
            }

    patched = patch_mgi_authorize(DummyMgi, anchor)
    env = patched().authorize()

    assert "rekor" in env["evidence"]
    assert "rekor_verified_url" in env["evidence"]


def test_verify_evidence_packet_offline(tmp_path: Path):
    sk = SigningKey.generate()
    payload_obj = {
        "scope": "diagnostic_inference",
        "outcome": "ALLOW",
        "operator": "tester",
        "decided_at": "2026-03-03T12:00:00Z",
        "evidence": {"rekor": {"offline": True}},
    }
    payload = json.dumps(payload_obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    sig_hex = sk.sign(payload).signature.hex()

    packet = {**payload_obj, "decision_sig": sig_hex}
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    assert verify_evidence_packet(str(packet_path), sk.verify_key.encode().hex()) is True
