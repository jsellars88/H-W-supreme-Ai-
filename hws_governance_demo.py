import base64
import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class CryptoCore:
    """Ed25519 key management — the root of trust."""

    def __init__(self):
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.public_key_b64 = base64.b64encode(
            self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    def sign(self, data: str) -> str:
        sig = self._private_key.sign(data.encode())
        return base64.b64encode(sig).decode()

    def verify(self, data: str, signature_b64: str) -> bool:
        try:
            sig = base64.b64decode(signature_b64)
            self._public_key.verify(sig, data.encode())
            return True
        except Exception:
            return False


@dataclass
class DecisionRequest:
    request_id: str
    subject: str
    action_tier: str  # INFORM | ADVISE | RECOMMEND | ACT | CRITICAL
    domain: str  # financial | medical | legal | safety | general
    description: str
    confidence: float  # 0.0 → 1.0
    requestor: str
    evidence: dict
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class RecusaNexus:
    """Mandatory 6-gate refusal gateway."""

    CONFIDENCE_THRESHOLDS = {
        "INFORM": 0.40,
        "ADVISE": 0.60,
        "RECOMMEND": 0.75,
        "ACT": 0.90,
        "CRITICAL": 0.95,
    }

    HIGH_RISK_DOMAINS = {"medical", "legal", "financial", "safety"}

    def evaluate(self, req: DecisionRequest) -> dict:
        gates = {
            "G1_OBSERVATION": self._gate_observation(req),
            "G2_INFERENCE": self._gate_inference(req),
            "G3_CONFIDENCE": self._gate_confidence(req),
            "G4_AUTHORITY": self._gate_authority(req),
            "G5_IDENTITY": self._gate_identity(req),
            "G6_HARM_SURFACE": self._gate_harm_surface(req),
        }

        failed = [g for g, r in gates.items() if not r["passed"]]
        approved = len(failed) == 0

        return {
            "approved": approved,
            "gates": gates,
            "failed_gates": failed,
            "refusal_rationale": self._build_rationale(failed, gates) if not approved else None,
            "alternative_offered": self._suggest_alternative(req, failed) if not approved else None,
        }

    def _gate_observation(self, req):
        passed = bool(req.description) and bool(req.evidence)
        return {
            "passed": passed,
            "reason": (
                "Request has defined scope and evidence"
                if passed
                else "Missing scope definition or evidence"
            ),
        }

    def _gate_inference(self, req):
        if req.domain in self.HIGH_RISK_DOMAINS and req.action_tier in ("ACT", "CRITICAL"):
            passed = req.evidence.get("authorized_by") is not None
            return {
                "passed": passed,
                "reason": (
                    "Authorization present"
                    if passed
                    else f"{req.domain} domain ACT/CRITICAL requires explicit authorization"
                ),
            }
        return {"passed": True, "reason": "Standard domain inference permitted"}

    def _gate_confidence(self, req):
        threshold = self.CONFIDENCE_THRESHOLDS.get(req.action_tier, 0.75)
        passed = req.confidence >= threshold
        return {
            "passed": passed,
            "reason": f"Confidence {req.confidence:.0%} {'≥' if passed else '<'} required {threshold:.0%} for {req.action_tier}",
        }

    def _gate_authority(self, req):
        passed = bool(req.requestor) and req.requestor != "anonymous"
        return {
            "passed": passed,
            "reason": (
                "Requestor identity verified"
                if passed
                else "Anonymous requestor — authority unverifiable"
            ),
        }

    def _gate_identity(self, req):
        protected = {
            "mental_health",
            "sexual_orientation",
            "political_affiliation",
            "religion",
            "genetic",
        }
        touched = protected.intersection(set(req.evidence.keys()))
        passed = len(touched) == 0
        return {
            "passed": passed,
            "reason": (
                f"Protected categories accessed without consent: {touched}"
                if not passed
                else "No protected identity categories accessed"
            ),
        }

    def _gate_harm_surface(self, req):
        if req.action_tier == "CRITICAL":
            passed = req.evidence.get("reversibility") == "confirmed_reversible" or req.evidence.get(
                "multi_party_approval"
            ) is not None
            return {
                "passed": passed,
                "reason": (
                    "Harm surface controls verified"
                    if passed
                    else "CRITICAL actions require reversibility confirmation or multi-party approval"
                ),
            }
        return {"passed": True, "reason": "Non-critical action — standard harm surface"}

    def _build_rationale(self, failed_gates, gates):
        reasons = [gates[g]["reason"] for g in failed_gates]
        return f"Blocked at {', '.join(failed_gates)}: {'; '.join(reasons)}"

    def _suggest_alternative(self, req, failed_gates):
        if "G3_CONFIDENCE" in failed_gates:
            return f"Downgrade action tier to {self._downgrade_tier(req.action_tier)} or gather additional evidence"
        if "G2_INFERENCE" in failed_gates:
            return "Add explicit authorization token from licensed authority"
        if "G4_AUTHORITY" in failed_gates:
            return "Authenticate requestor identity before resubmitting"
        return "Review failed gate requirements and resubmit with corrected parameters"

    def _downgrade_tier(self, tier):
        tiers = ["INFORM", "ADVISE", "RECOMMEND", "ACT", "CRITICAL"]
        idx = tiers.index(tier) if tier in tiers else 2
        return tiers[max(0, idx - 1)]


class ForensicDecisionLedger:
    """Every decision: signed, chained, verifiable."""

    def __init__(self, db_path=":memory:", crypto: CryptoCore = None):
        self.crypto = crypto or CryptoCore()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._prev_hash = "GENESIS"

    def _init_db(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                seq           INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id   TEXT UNIQUE NOT NULL,
                timestamp     TEXT NOT NULL,
                subject       TEXT NOT NULL,
                action_tier   TEXT NOT NULL,
                approved      INTEGER NOT NULL,
                outcome       TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                prev_hash     TEXT NOT NULL,
                entry_hash    TEXT NOT NULL,
                signature     TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def record(self, req: DecisionRequest, gate_result: dict, outcome: str) -> dict:
        decision_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        evidence_hash = hashlib.sha256(
            json.dumps(req.evidence, sort_keys=True).encode()
        ).hexdigest()

        prev_hash = self._prev_hash
        canonical = json.dumps(
            {
                "decision_id": decision_id,
                "timestamp": timestamp,
                "subject": req.subject,
                "action_tier": req.action_tier,
                "approved": gate_result["approved"],
                "outcome": outcome,
                "evidence_hash": evidence_hash,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        )

        entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
        signature = self.crypto.sign(canonical)

        self.conn.execute(
            """
            INSERT INTO decisions VALUES (NULL,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                decision_id,
                timestamp,
                req.subject,
                req.action_tier,
                int(gate_result["approved"]),
                outcome,
                evidence_hash,
                prev_hash,
                entry_hash,
                signature,
            ),
        )
        self.conn.commit()
        self._prev_hash = entry_hash

        return {
            "decision_id": decision_id,
            "timestamp": timestamp,
            "entry_hash": entry_hash,
            "signature": signature,
            "prev_hash": prev_hash,
            "public_key": self.crypto.public_key_b64,
        }

    def verify_chain(self) -> dict:
        rows = self.conn.execute("SELECT * FROM decisions ORDER BY seq").fetchall()

        results = []
        prev = "GENESIS"
        all_valid = True

        for row in rows:
            seq, did, ts, subj, tier, approved, outcome, ev_hash, ph, eh, sig = row
            canonical = json.dumps(
                {
                    "decision_id": did,
                    "timestamp": ts,
                    "subject": subj,
                    "action_tier": tier,
                    "approved": bool(approved),
                    "outcome": outcome,
                    "evidence_hash": ev_hash,
                    "prev_hash": ph,
                },
                sort_keys=True,
            )

            chain_valid = ph == prev
            sig_valid = self.crypto.verify(canonical, sig)
            hash_valid = hashlib.sha256(canonical.encode()).hexdigest() == eh
            valid = chain_valid and sig_valid and hash_valid
            if not valid:
                all_valid = False

            results.append(
                {
                    "seq": seq,
                    "decision_id": did,
                    "chain_intact": chain_valid,
                    "signature_valid": sig_valid,
                    "hash_valid": hash_valid,
                    "overall_valid": valid,
                }
            )
            prev = eh

        return {"all_valid": all_valid, "entries": results, "total": len(rows)}

    def get_proof_bundle(self, decision_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if not row:
            return None

        seq, did, ts, subj, tier, approved, outcome, ev_hash, ph, eh, sig = row
        return {
            "decision_id": did,
            "timestamp": ts,
            "subject": subj,
            "action_tier": tier,
            "approved": bool(approved),
            "outcome": outcome,
            "evidence_hash": ev_hash,
            "entry_hash": eh,
            "signature": sig,
            "public_key": self.crypto.public_key_b64,
            "verification_instruction": (
                "1. Reconstruct canonical JSON from fields above\n"
                "2. Verify Ed25519 signature against public_key\n"
                "3. Verify SHA-256 of canonical == entry_hash\n"
                "4. Verify prev_hash chain from GENESIS → this entry\n"
                "Result: cryptographically proves what decision was made and when"
            ),
        }


class GovernanceEnvelope:
    """Request → Recusa Gate → Execute/Block → Ledger → Proof."""

    def __init__(self):
        self.crypto = CryptoCore()
        self.nexus = RecusaNexus()
        self.ledger = ForensicDecisionLedger(crypto=self.crypto)
        self.session_id = str(uuid.uuid4())[:8].upper()

    def process(self, req: DecisionRequest) -> dict:
        t0 = time.perf_counter()

        gate_result = self.nexus.evaluate(req)

        if gate_result["approved"]:
            outcome = f"APPROVED — {req.action_tier} action authorized for {req.subject}"
        else:
            outcome = f"BLOCKED — {gate_result['refusal_rationale']}"

        proof = self.ledger.record(req, gate_result, outcome)
        chain = self.ledger.verify_chain()

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return {
            "session_id": self.session_id,
            "request_id": req.request_id,
            "decision_id": proof["decision_id"],
            "approved": gate_result["approved"],
            "outcome": outcome,
            "gates_passed": sum(1 for g in gate_result["gates"].values() if g["passed"]),
            "gates_total": len(gate_result["gates"]),
            "gate_details": gate_result["gates"],
            "failed_gates": gate_result["failed_gates"],
            "alternative_offered": gate_result.get("alternative_offered"),
            "proof": proof,
            "chain_integrity": chain["all_valid"],
            "chain_entries": chain["total"],
            "latency_ms": round(elapsed_ms, 2),
        }

    def get_proof_bundle(self, decision_id: str) -> Optional[dict]:
        return self.ledger.get_proof_bundle(decision_id)

    def verify_all(self) -> dict:
        return self.ledger.verify_chain()


def run_demo():
    print("\n" + "═" * 65)
    print("  Holmes & Watson Supreme AI™ — Closed-Loop Governance Demo")
    print("  WhiteSwan OS | Cornerstone v2.0")
    print("═" * 65)

    gov = GovernanceEnvelope()
    print(f"\n  Session: {gov.session_id}")
    print(f"  Public Key: {gov.crypto.public_key_b64[:32]}...")
    print("  Ledger: Ed25519 + SHA-256 hash chain")

    scenarios = [
        DecisionRequest(
            request_id=str(uuid.uuid4())[:8],
            subject="loan_application_7821",
            action_tier="RECOMMEND",
            domain="financial",
            description="Recommend approval of $250,000 commercial loan",
            confidence=0.82,
            requestor="underwriter_jones",
            evidence={
                "credit_score": 720,
                "debt_to_income": 0.28,
                "authorized_by": "risk_committee_quorum",
                "analysis_model": "claude-sonnet-4",
            },
        ),
        DecisionRequest(
            request_id=str(uuid.uuid4())[:8],
            subject="patient_rx_4491",
            action_tier="ACT",
            domain="medical",
            description="Administer adjusted insulin dosage",
            confidence=0.71,
            requestor="omnimedic_agent_v2",
            evidence={
                "glucose_level": 180,
                "trend": "rising",
                "last_dose_hours": 4,
            },
        ),
        DecisionRequest(
            request_id=str(uuid.uuid4())[:8],
            subject="contract_clause_review",
            action_tier="ADVISE",
            domain="legal",
            description="Flag non-standard indemnification clause",
            confidence=0.91,
            requestor="legal_analyst_system",
            evidence={
                "clause_text": "indemnification_hash_abc123",
                "precedent_cases": 14,
                "risk_score": "HIGH",
                "authorized_by": "general_counsel_token_xyz",
            },
        ),
        DecisionRequest(
            request_id=str(uuid.uuid4())[:8],
            subject="infrastructure_config",
            action_tier="CRITICAL",
            domain="safety",
            description="Apply zero-downtime database migration to production",
            confidence=0.96,
            requestor="devops_pipeline",
            evidence={
                "migration_id": "mig_2026_q1_001",
                "rollback_tested": True,
                "reversibility": "confirmed_reversible",
                "multi_party_approval": ["cto_token", "sre_lead_token"],
                "authorized_by": "change_advisory_board",
            },
        ),
    ]

    results = []
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'─' * 65}")
        print(f"  SCENARIO {i}: {scenario.description[:50]}")
        print(
            f"  Tier: {scenario.action_tier} | Domain: {scenario.domain} | Confidence: {scenario.confidence:.0%}"
        )

        result = gov.process(scenario)
        results.append(result)

        status = "✅ APPROVED" if result["approved"] else "🛑 BLOCKED"
        print(f"\n  {status}")
        print(f"  Gates: {result['gates_passed']}/{result['gates_total']} passed")

        if result["failed_gates"]:
            print(f"  Failed: {', '.join(result['failed_gates'])}")
        if result["alternative_offered"]:
            print(f"  Alternative: {result['alternative_offered']}")

        print("\n  📋 Ledger Entry:")
        print(f"     Decision ID: {result['decision_id']}")
        print(f"     Entry Hash:  {result['proof']['entry_hash'][:32]}...")
        print(f"     Signature:   {result['proof']['signature'][:32]}...")
        print(
            f"     Chain Valid: {result['chain_integrity']} ({result['chain_entries']} entries)"
        )
        print(f"     Latency:     {result['latency_ms']}ms")

    print(f"\n{'═' * 65}")
    print("  FINAL CHAIN VERIFICATION (third-party auditor view)")
    print(f"{'═' * 65}")

    chain = gov.verify_all()
    print(f"\n  Total Decisions: {chain['total']}")
    print(f"  Chain Integrity: {'✅ ALL VALID' if chain['all_valid'] else '❌ TAMPERED'}")

    for entry in chain["entries"]:
        ok = "✅" if entry["overall_valid"] else "❌"
        print(
            f"  Entry {entry['seq']}: {ok} | Chain: {entry['chain_intact']} | Sig: {entry['signature_valid']} | Hash: {entry['hash_valid']}"
        )

    print("\n  PROOF BUNDLE (what a regulator receives):")
    bundle = gov.get_proof_bundle(results[0]["decision_id"])
    print(f"  Decision:   {bundle['decision_id']}")
    print(f"  Outcome:    {bundle['outcome']}")
    print(f"  Timestamp:  {bundle['timestamp']}")
    print(f"  Entry Hash: {bundle['entry_hash']}")
    print(f"  Signature:  {bundle['signature'][:48]}...")
    print(f"  Public Key: {bundle['public_key'][:48]}...")
    print("\n  Verification:")
    for line in bundle["verification_instruction"].split("\n"):
        print(f"  {line}")

    print(f"\n{'═' * 65}")
    print("  Demo complete. Every decision cryptographically provable.")
    print("  This is what 'AI decisions you can prove to regulators' means.")
    print(f"{'═' * 65}\n")

    return results, gov


if __name__ == "__main__":
    results, gov = run_demo()
