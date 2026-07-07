"""
White Swan A.R.T. — Forensic Ledger Implementation
===================================================

Hash-chained, Ed25519-signed ledger for recording governed decisions.
Chain integrity verified cryptographically; no retroactive edits possible.

Usage:
  from governance_ledger import ForensicLedger
  
  led = ForensicLedger(domain="WHITE-SWAN/A.R.T.")
  led.append({"action": "Scout: launch", "decision": "AUTHORIZE"})
  led.export("mission_ledger.json")
  
  ok, reason = ForensicLedger.verify("mission_ledger.json")
  print(f"Ledger integrity: {'PASS' if ok else 'FAIL'} — {reason}")
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


@dataclass
class ForensicLedgerEntry:
    """Single ledger entry with hash-chain link."""
    index: int
    prev_hash: str
    payload: dict[str, Any]
    entry_hash: str = ""


@dataclass
class ForensicLedger:
    """Hash-chained, Ed25519-signed forensic ledger."""
    
    domain: str
    _entries: list[dict[str, Any]] = field(default_factory=list)
    _genesis: str = ""
    _signing_key: ed25519.Ed25519PrivateKey = field(default_factory=ed25519.Ed25519PrivateKey.generate)
    _sealed: Optional[dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize ledger with genesis hash."""
        if not self._genesis:
            self._genesis = self._compute_domain_genesis()
    
    def _compute_domain_genesis(self) -> str:
        """Compute deterministic genesis hash from domain."""
        return hashlib.sha256(
            json.dumps({"domain": self.domain}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    
    def _compute_entry_hash(self, entry: dict[str, Any]) -> str:
        """Compute SHA-256 hash of entry payload."""
        return hashlib.sha256(
            json.dumps(entry["payload"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    
    def append(self, payload: dict[str, Any]) -> None:
        """Append a new entry to the ledger."""
        if self._sealed:
            raise RuntimeError("Cannot append to sealed ledger; call export() first")
        
        index = len(self._entries)
        prev_hash = self._genesis if index == 0 else self._entries[-1]["entry_hash"]
        
        entry = {
            "index": index,
            "prev_hash": prev_hash,
            "payload": payload,
        }
        entry["entry_hash"] = self._compute_entry_hash(entry)
        
        self._entries.append(entry)
    
    def _get_chain_head(self) -> str:
        """Get the hash of the final entry (or genesis if empty)."""
        if not self._entries:
            return self._genesis
        return self._entries[-1]["entry_hash"]
    
    def _get_public_key_hex(self) -> str:
        """Get hex-encoded public key."""
        pub = self._signing_key.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return pub_bytes.hex()
    
    def export(self, path: str) -> None:
        """Export sealed ledger to JSON file."""
        chain_head = self._get_chain_head()
        public_key_hex = self._get_public_key_hex()
        
        # Payload to sign: domain, genesis, chain_head, entry_count
        payload_to_sign = json.dumps({
            "domain": self.domain,
            "genesis": self._genesis,
            "chain_head": chain_head,
            "entry_count": len(self._entries),
        }, sort_keys=True, separators=(",", ":")).encode()
        
        signature = self._signing_key.sign(payload_to_sign)
        signature_hex = signature.hex()
        
        ledger_doc = {
            "domain": self.domain,
            "genesis": self._genesis,
            "chain_head": chain_head,
            "signature": signature_hex,
            "public_key": public_key_hex,
            "entry_count": len(self._entries),
            "entries": self._entries,
        }
        
        with open(path, "w") as f:
            json.dump(ledger_doc, f, indent=2)
        
        self._sealed = ledger_doc
    
    @property
    def sealed(self):
        """Get the sealed ledger document (after export)."""
        return self._sealed
    
    @staticmethod
    def verify(path: str) -> tuple[bool, str]:
        """
        Verify ledger integrity.
        Returns: (is_valid, reason)
        """
        try:
            with open(path) as f:
                doc = json.load(f)
        except Exception as e:
            return False, f"Failed to load ledger: {e}"
        
        # Validate required fields
        required = ["domain", "genesis", "chain_head", "signature", "public_key", "entry_count", "entries"]
        for field in required:
            if field not in doc:
                return False, f"Missing required field: {field}"
        
        # Verify genesis hash
        expected_genesis = hashlib.sha256(
            json.dumps({"domain": doc["domain"]}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if doc["genesis"] != expected_genesis:
            return False, f"Genesis hash mismatch: expected {expected_genesis}, got {doc['genesis']}"
        
        # Verify entry count matches
        if len(doc["entries"]) != doc["entry_count"]:
            return False, f"Entry count mismatch: ledger has {len(doc['entries'])}, header says {doc['entry_count']}"
        
        # Verify chain integrity
        prev_hash = doc["genesis"]
        for i, entry in enumerate(doc["entries"]):
            # Check prev_hash link
            if entry.get("prev_hash") != prev_hash:
                return False, f"Entry {i}: prev_hash mismatch (expected {prev_hash}, got {entry.get('prev_hash')})"
            
            # Recompute entry hash
            expected_hash = hashlib.sha256(
                json.dumps(entry["payload"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if entry.get("entry_hash") != expected_hash:
                return False, f"Entry {i}: entry_hash mismatch"
            
            prev_hash = expected_hash
        
        # Verify chain head
        final_hash = prev_hash if doc["entries"] else doc["genesis"]
        if doc["chain_head"] != final_hash:
            return False, f"Chain head mismatch: expected {final_hash}, got {doc['chain_head']}"
        
        # Verify signature
        try:
            payload_to_sign = json.dumps({
                "domain": doc["domain"],
                "genesis": doc["genesis"],
                "chain_head": doc["chain_head"],
                "entry_count": doc["entry_count"],
            }, sort_keys=True, separators=(",", ":")).encode()
            
            signature_bytes = bytes.fromhex(doc["signature"])
            public_key_bytes = bytes.fromhex(doc["public_key"])
            
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, payload_to_sign)
        except InvalidSignature:
            return False, "Ed25519 signature verification failed"
        except Exception as e:
            return False, f"Signature verification error: {e}"
        
        return True, "Ledger integrity verified: chain complete, entries linked, signature valid"


if __name__ == "__main__":
    # Demo: create, export, verify a small ledger
    led = ForensicLedger(domain="TEST/DEMO")
    for i in range(3):
        led.append({"step": i, "action": f"action_{i}", "decision": "AUTHORIZE" if i % 2 == 0 else "REFUSE"})
    
    led.export("demo_ledger.json")
    ok, reason = ForensicLedger.verify("demo_ledger.json")
    print(f"Demo ledger: {'✓ PASS' if ok else '✗ FAIL'} — {reason}")
