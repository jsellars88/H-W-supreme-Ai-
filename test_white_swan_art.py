"""
White Swan A.R.T. — Formal Test Suite
=====================================
Tests the governance engine (art_command v1.1) and forensic ledger.

Covers:
  - conductor gate logic (per-unit refusals)
  - veto semantics (authority vs. exercise, F-1 fix)
  - consensus policy (veto block, dissent, confidence floor, HOLD)
  - commander authority bounds (may refuse, may release, MUST NOT override veto)
  - ledger integrity (chain, seal, tamper detection, deletion detection)

Run:  pytest test_white_swan_art.py -v
"""

import json
import copy
import pytest

import white_swan_art as art
from governance_ledger import ForensicLedger


# ------------------------------------------------------------------ fixtures
def clear_world(**over):
    """A world state where every unit's gates pass comfortably."""
    w = {
        "visibility_m": 320, "wind_ms": 10, "structure_stability": 0.95,
        "terrain_grade_deg": 5, "payload_kg": 40, "route_found": True,
        "water_depth_m": 0.1, "casualty_stable": True, "evac_window_min": 60,
        "comms_coverage": 0.9,
    }
    w.update(over)
    return w


def all_votes(world):
    return [u("test action", world) for u in art.UNITS]


# ------------------------------------------------------------ conductor gates
class TestConductorGates:
    """Test individual unit evaluation gates."""

    def test_scout_refuses_low_visibility(self):
        v = art.scout("recon", clear_world(visibility_m=100))
        assert v["decision"] == "REFUSE"
        assert "visibility" in v["reason"]

    def test_scout_refuses_high_wind(self):
        v = art.scout("recon", clear_world(wind_ms=25))
        assert v["decision"] == "REFUSE"

    def test_scout_authorizes_clear_conditions(self):
        v = art.scout("recon", clear_world())
        assert v["decision"] == "AUTHORIZE"
        assert v["confidence"] > 0.7

    def test_guardian_refuses_unstable_structure(self):
        v = art.guardian("enter", clear_world(structure_stability=0.25))
        assert v["decision"] == "REFUSE"
        assert "unstable" in v["reason"]

    def test_guardian_refuses_steep_grade(self):
        v = art.guardian("climb", clear_world(terrain_grade_deg=35))
        assert v["decision"] == "REFUSE"

    def test_guardian_refuses_overweight(self):
        v = art.guardian("carry", clear_world(payload_kg=130))
        assert v["decision"] == "REFUSE"

    def test_guardian_authorizes_safe_conditions(self):
        v = art.guardian("enter", clear_world())
        assert v["decision"] == "AUTHORIZE"

    def test_pathfinder_refuses_no_route(self):
        v = art.pathfinder("navigate", clear_world(route_found=False))
        assert v["decision"] == "REFUSE"

    def test_pathfinder_refuses_deep_water(self):
        v = art.pathfinder("cross", clear_world(water_depth_m=1.5))
        assert v["decision"] == "REFUSE"

    def test_pathfinder_authorizes_passable(self):
        v = art.pathfinder("cross", clear_world())
        assert v["decision"] == "AUTHORIZE"

    def test_medic_refuses_unstable_casualty(self):
        v = art.medic("move casualty", clear_world(casualty_stable=False))
        assert v["decision"] == "REFUSE"
        assert "unstable" in v["reason"]
        assert v["veto_exercised"] is True

    def test_medic_refuses_short_evac_window(self):
        v = art.medic("extract", clear_world(evac_window_min=5))
        assert v["decision"] == "REFUSE"

    def test_medic_authorizes_transportable_patient(self):
        v = art.medic("move", clear_world())
        assert v["decision"] == "AUTHORIZE"
        assert v["veto_exercised"] is False

    def test_sentinel_refuses_coverage_gap(self):
        v = art.sentinel("relay", clear_world(comms_coverage=0.3))
        assert v["decision"] == "REFUSE"

    def test_sentinel_authorizes_adequate_coverage(self):
        v = art.sentinel("relay", clear_world())
        assert v["decision"] == "AUTHORIZE"

    def test_confidence_always_bounded(self):
        """All votes must have confidence in [0.0, 1.0]."""
        for unit in art.UNITS:
            for world in (clear_world(),
                          clear_world(visibility_m=0, wind_ms=50,
                                      structure_stability=0.0, casualty_stable=False,
                                      comms_coverage=0.0, route_found=False,
                                      water_depth_m=5.0, evac_window_min=0,
                                      terrain_grade_deg=60, payload_kg=500)):
                v = unit("x", world)
                assert 0.0 <= v["confidence"] <= 1.0, \
                    f"{unit.__name__} returned confidence {v['confidence']}"


# ------------------------------------------------------- veto semantics (F-1)
class TestVetoSemantics:
    """Test F-1 fix: veto_authority vs veto_exercised semantics."""

    def test_medic_authorize_has_authority_not_exercise(self):
        """Medic has veto authority, but AUTHORIZE does not exercise it."""
        v = art.medic("triage", clear_world())
        assert v["decision"] == "AUTHORIZE"
        assert v["veto_authority"] is True
        assert v["veto_exercised"] is False

    def test_medic_refuse_exercises_veto(self):
        """Medic refusing = veto authority + veto exercised."""
        v = art.medic("move", clear_world(casualty_stable=False))
        assert v["veto_authority"] is True
        assert v["veto_exercised"] is True

    def test_non_safety_units_have_no_veto_authority(self):
        """Scout, Guardian, Pathfinder, Sentinel have no veto authority."""
        for unit in (art.scout, art.guardian, art.pathfinder, art.sentinel):
            v = unit("x", clear_world())
            assert v["veto_authority"] is False
            assert v["veto_exercised"] is False

    def test_veto_exercised_implies_refuse(self):
        """veto_exercised can only be True if decision is REFUSE."""
        for unit in art.UNITS:
            v = unit("x", clear_world())
            if v["veto_exercised"]:
                assert v["decision"] == "REFUSE"


# ------------------------------------------------------------ consensus policy
class TestConsensusPolicy:
    """Test white_swan_command governance logic."""

    def test_unanimous_high_confidence_authorizes(self):
        """All units agree, high confidence → AUTHORIZE."""
        decision, basis, agg = art.white_swan_command("go", all_votes(clear_world()))
        assert decision == "AUTHORIZE"
        assert agg >= 0.7
        assert "consensus" in basis

    def test_exercised_veto_blocks(self):
        """Any exercised veto → REFUSE, regardless of other votes."""
        votes = all_votes(clear_world(casualty_stable=False))
        decision, basis, _ = art.white_swan_command("move", votes)
        assert decision == "REFUSE"
        assert "VETO by Medic" in basis

    def test_dissent_without_veto_refuses_no_consensus(self):
        """Dissent without veto → REFUSE (no consensus)."""
        votes = all_votes(clear_world(structure_stability=0.25))  # Guardian dissents
        decision, basis, _ = art.white_swan_command("enter", votes)
        assert decision == "REFUSE"
        assert "no consensus" in basis

    def test_low_confidence_consensus_holds_for_commander(self):
        """All agree but agg_conf < 0.7 → HOLD_FOR_COMMANDER."""
        marginal = clear_world(visibility_m=170, wind_ms=17.5, structure_stability=0.5,
                               terrain_grade_deg=28, payload_kg=100, water_depth_m=1.1,
                               evac_window_min=9, comms_coverage=0.62)
        decision, basis, agg = art.white_swan_command("cross", all_votes(marginal))
        assert decision == "HOLD_FOR_COMMANDER"
        assert agg < 0.7
        assert "confidence" in basis

    def test_aggregate_confidence_computed_correctly(self):
        """agg_conf = mean of all vote confidences, rounded to 2 places."""
        votes = all_votes(clear_world())
        _, _, agg = art.white_swan_command("test", votes)
        confidences = [v["confidence"] for v in votes]
        expected = round(sum(confidences) / len(confidences), 2)
        assert agg == expected


# ------------------------------------------------- commander authority bounds
class TestCommanderAuthority:
    """Test commander override rules and bounds."""

    def test_commander_may_refuse_anything(self):
        """Commander may refuse any action."""
        decision, basis, _ = art.white_swan_command(
            "go", all_votes(clear_world()), commander_override="REFUSE")
        assert decision == "REFUSE"
        assert "Commander" in basis

    def test_commander_may_release_hold(self):
        """Commander may release a HOLD (low confidence consensus)."""
        marginal = clear_world(visibility_m=170, wind_ms=17.5, structure_stability=0.5,
                               terrain_grade_deg=28, payload_kg=100, water_depth_m=1.1,
                               evac_window_min=9, comms_coverage=0.62)
        decision, basis, _ = art.white_swan_command(
            "cross", all_votes(marginal), commander_override="APPROVE")
        assert decision == "AUTHORIZE"
        assert "released" in basis

    def test_commander_MUST_NOT_override_exercised_veto(self):
        """THE LOAD-BEARING INVARIANT: commander cannot override casualty veto."""
        votes = all_votes(clear_world(casualty_stable=False))
        decision, basis, _ = art.white_swan_command(
            "move casualty", votes, commander_override="APPROVE")
        assert decision == "REFUSE"
        assert "BLOCKED" in basis
        assert "cannot override" in basis

    def test_commander_override_none_uses_unit_decision(self):
        """If commander_override is None, use normal governance."""
        votes = all_votes(clear_world())
        decision1, _, _ = art.white_swan_command("go", votes, commander_override=None)
        decision2, _, _ = art.white_swan_command("go", votes)
        assert decision1 == decision2


# ---------------------------------------------------------------- ledger
class TestForensicLedger:
    """Test forensic ledger integrity and tamper detection."""

    _counter = 0

    def _sealed(self, tmp_path):
        """Helper: create a sealed ledger with 5 entries."""
        TestForensicLedger._counter += 1
        led = ForensicLedger(domain="TEST/A.R.T.")
        for i in range(5):
            led.append({"step": i, "decision": "AUTHORIZE" if i % 2 == 0 else "REFUSE"})
        path = str(tmp_path / f"ledger_{TestForensicLedger._counter}.json")
        led.export(path)
        return path

    def test_clean_ledger_verifies(self, tmp_path):
        """A clean ledger passes verification."""
        path = self._sealed(tmp_path)
        ok, reason = ForensicLedger.verify(path)
        assert ok, f"Clean ledger should verify, but: {reason}"

    def test_payload_tamper_detected(self, tmp_path):
        """Changing entry payload breaks chain."""
        path = self._sealed(tmp_path)
        with open(path) as f:
            doc = json.load(f)
        # Entry 1 was REFUSE, change it to AUTHORIZE
        doc["entries"][1]["payload"]["decision"] = "AUTHORIZE"
        tampered = str(tmp_path / "tampered.json")
        with open(tampered, "w") as f:
            json.dump(doc, f)
        ok, reason = ForensicLedger.verify(tampered)
        assert not ok, "Tampered payload should fail verification"
        assert "entry" in reason.lower() or "1" in reason

    def test_entry_deletion_detected(self, tmp_path):
        """Deleting an entry breaks the chain."""
        path = self._sealed(tmp_path)
        with open(path) as f:
            doc = json.load(f)
        del doc["entries"][2]
        cut = str(tmp_path / "cut.json")
        with open(cut, "w") as f:
            json.dump(doc, f)
        ok, reason = ForensicLedger.verify(cut)
        assert not ok, "Deleted entry should fail verification"

    def test_wrong_domain_genesis_detected(self, tmp_path):
        """Changing domain invalidates genesis."""
        path = self._sealed(tmp_path)
        with open(path) as f:
            doc = json.load(f)
        doc["domain"] = "FORGED/DOMAIN"
        forged = str(tmp_path / "forged.json")
        with open(forged, "w") as f:
            json.dump(doc, f)
        ok, reason = ForensicLedger.verify(forged)
        assert not ok, "Forged domain should fail verification"
        assert "genesis" in reason.lower()

    def test_signature_swap_detected(self, tmp_path):
        """Swapping signatures between different ledgers fails."""
        a, b = self._sealed(tmp_path), self._sealed(tmp_path)
        with open(a) as f1, open(b) as f2:
            doc_a, doc_b = json.load(f1), json.load(f2)
        # Swap signature: doc_a's chain signed with doc_b's key
        doc_a["signature"] = doc_b["signature"]
        swapped = str(tmp_path / "swapped.json")
        with open(swapped, "w") as f:
            json.dump(doc_a, f)
        ok, reason = ForensicLedger.verify(swapped)
        assert not ok, "Signature swap should fail verification"

    def test_ledger_export_creates_valid_structure(self, tmp_path):
        """Exported ledger has required fields."""
        led = ForensicLedger(domain="TEST/STRUCTURE")
        led.append({"action": "test"})
        path = str(tmp_path / "struct.json")
        led.export(path)
        with open(path) as f:
            doc = json.load(f)
        assert "domain" in doc
        assert "genesis" in doc
        assert "chain_head" in doc
        assert "signature" in doc
        assert "public_key" in doc
        assert "entry_count" in doc
        assert "entries" in doc
        assert doc["entry_count"] == 1

    def test_ledger_entry_chain_links(self, tmp_path):
        """Each entry links to previous via prev_hash."""
        led = ForensicLedger(domain="TEST/CHAIN")
        for i in range(3):
            led.append({"step": i})
        path = str(tmp_path / "chain.json")
        led.export(path)
        with open(path) as f:
            doc = json.load(f)
        # Entry 0: prev_hash should be genesis
        assert doc["entries"][0]["prev_hash"] == doc["genesis"]
        # Entry 1: prev_hash should be entry 0's hash
        assert doc["entries"][1]["prev_hash"] == doc["entries"][0]["entry_hash"]
        # Entry 2: prev_hash should be entry 1's hash
        assert doc["entries"][2]["prev_hash"] == doc["entries"][1]["entry_hash"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
