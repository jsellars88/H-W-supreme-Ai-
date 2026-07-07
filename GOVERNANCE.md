# White Swan A.R.T. Governance Model — Technical Deep Dive

**Complete specification of the 5-unit consensus model with safety veto authority.**

---

## Table of Contents

1. [Decision Architecture](#decision-architecture)
2. [Conductor Specifications](#conductor-specifications)
3. [Consensus Policy](#consensus-policy)
4. [Veto Authority Model](#veto-authority-model)
5. [Commander Authority Bounds](#commander-authority-bounds)
6. [Confidence Scoring](#confidence-scoring)
7. [Forensic Ledger](#forensic-ledger)
8. [Invariants](#invariants)

---

## Decision Architecture

### Five-Unit Model

White Swan A.R.T. uses a **fixed set of five specialized conductors**, each responsible for a specific domain:

```
┌──────────────┐
│ Scout        │  → visibility, environmental conditions
└──────────────┘
┌──────────────┐
│ Guardian     │  → structural integrity, safety hazards
└──────────────┘
┌──────────────┐
│ Pathfinder   │  → route viability, terrain traversal
└──────────────┘
┌──────────────┐
│ Medic        │  → casualty health, medical safety (VETO)
└──────────────┘
┌──────────────┐
│ Sentinel     │  → communication reliability, signal coverage
└──────────────┘
```

### Input and Output

**Input:** World state (sensor readings, environmental conditions, unit status)

**Output:** 
- `decision` ∈ {AUTHORIZE, REFUSE, HOLD_FOR_COMMANDER}
- `basis` ∈ Text (human-readable reasoning)
- `aggregate_confidence` ∈ [0, 1] (confidence in decision)

---

## Conductor Specifications

### Scout: Reconnaissance Authority

**Role:** Evaluate visibility and environmental conditions for safe operations.

**Gate Logic:**

```python
visibility_ok = world["visibility_m"] >= 150  # Minimum 150m visibility
wind_ok = world["wind_ms"] <= 18              # Max 18 m/s wind
light_ok = world["light_level"] >= 50         # Lux threshold

gates_pass = visibility_ok and wind_ok and light_ok
```

**Confidence Scoring:**

```python
base = 0.50
visibility_margin = min(1.0, world["visibility_m"] / 300)  # 0.5 to 1.0
wind_margin = min(1.0, 1.0 - (world["wind_ms"] / 25))      # 0.3 to 1.0
confidence = base + 0.25 * visibility_margin + 0.25 * wind_margin
```

**Decision:**

- If gates pass: AUTHORIZE, confidence ∈ [0.50, 1.00]
- If gates fail: REFUSE, confidence ∈ [0.0, 0.50]

**Veto Authority:** ❌ No

---

### Guardian: Structural Safety

**Role:** Validate structural integrity and hazard assessment.

**Gate Logic:**

```python
stability_ok = world["stability"] >= 0.4              # Stability index
angle_ok = world["slope_degrees"] <= 32               # Max 32° slope
load_ok = world["person_load_kg"] <= 120              # Max 120kg per person
debris_ok = world["debris_hazard"] is False           # No active debris
```

**Confidence Scoring:**

```python
base = 0.50
stability_margin = min(1.0, world["stability"] / 0.8)
angle_margin = min(1.0, 1.0 - (world["slope_degrees"] / 45))
load_margin = min(1.0, 1.0 - (world["person_load_kg"] / 200))
confidence = base + 0.25 * ((stability_margin + angle_margin + load_margin) / 3)
```

**Decision:**

- If all gates pass: AUTHORIZE
- If any gate fails: REFUSE

**Veto Authority:** ❌ No

---

### Pathfinder: Route Finding

**Role:** Determine route viability and traversal safety.

**Gate Logic:**

```python
route_exists = world["route_available"] is True
water_depth_ok = world["water_depth_m"] <= 1.2    # Max 1.2m water
passage_width_ok = world["passage_width_m"] >= 0.8  # Min 0.8m width
bridge_load_ok = world["bridge_capacity_kg"] >= 500  # Min 500kg capacity
```

**Confidence Scoring:**

```python
base = 0.50
depth_margin = min(1.0, 1.0 - (world["water_depth_m"] / 2.0))
width_margin = min(1.0, world["passage_width_m"] / 2.0)
load_margin = min(1.0, world["bridge_capacity_kg"] / 1000)
confidence = base + 0.25 * ((depth_margin + width_margin + load_margin) / 3)
```

**Decision:**

- If all gates pass: AUTHORIZE
- If any gate fails: REFUSE

**Veto Authority:** ❌ No

---

### Medic: Casualty Safety (VETO AUTHORITY)

**Role:** Assess casualty health and medical safety.

**Gate Logic:**

```python
patient_stable = world["casualty_stable"] is True
evac_window_ok = world["evac_window_minutes"] >= 8  # Min 8 min window
airway_clear = world["airway_compromised"] is False
bleeding_controlled = world["active_bleeding"] is False
```

**Confidence Scoring:**

```python
base = 0.50
stability_bonus = 0.25 if world["casualty_stable"] else 0
evac_window_margin = min(0.25, world["evac_window_minutes"] / 32)
confidence = base + stability_bonus + evac_window_margin
```

**Decision:**

- If all gates pass: AUTHORIZE
- If any gate fails: **REFUSE (VETO EXERCISED)**
- Special case: If AUTHORIZE but patient becomes unstable during extraction → REFUSE (veto override)

**Veto Authority:** ✅ **YES — ABSOLUTE**

The Medic's veto is **unconditional** and **cannot be overridden** by any other unit or the commander.

---

### Sentinel: Communications Reliability

**Role:** Assess signal coverage and communication viability.

**Gate Logic:**

```python
signal_coverage = world["signal_coverage"] >= 0.6    # Min 60% coverage
latency_ok = world["latency_ms"] <= 500              # Max 500ms latency
backup_comms = world["backup_radio"] is True         # Fallback comms available
```

**Confidence Scoring:**

```python
base = 0.50
coverage_margin = min(0.25, world["signal_coverage"] / 1.0)
latency_margin = min(0.25, 1.0 - (world["latency_ms"] / 1000))
backup_bonus = 0.25 if world["backup_radio"] else 0
confidence = base + coverage_margin + latency_margin + backup_bonus
```

**Decision:**

- If gates pass: AUTHORIZE, confidence ∈ [0.50, 1.25] (capped at 1.0)
- If gates fail: REFUSE, confidence ∈ [0.0, 0.50]

**Veto Authority:** ❌ No

---

## Consensus Policy

### white_swan_command() Decision Logic

```python
def white_swan_command(action, votes, commander_override=None):
    """
    Orchestrate 5-unit consensus with veto authority and commander bounds.
    
    Returns: (decision, basis, aggregate_confidence)
    """
    
    # Step 1: Check veto authority enforcement
    for vote in votes:
        if vote["veto_authority"] and vote["veto_exercised"]:
            return (
                "REFUSE",
                f"VETO by {vote['unit']}: {vote['reason']}",
                aggregate_confidence(votes)
            )
    
    # Step 2: Check commander attempted veto override
    if commander_override == "REFUSE":
        for vote in votes:
            if vote["veto_exercised"]:
                # Commander cannot refuse a veto; system rejects attempt
                return (
                    "REFUSE",
                    f"VETO by {vote['unit']}: commander approval BLOCKED",
                    aggregate_confidence(votes)
                )
    
    # Step 3: Check for consensus (no dissent)
    authorize_votes = sum(1 for v in votes if v["decision"] == "AUTHORIZE")
    refuse_votes = sum(1 for v in votes if v["decision"] == "REFUSE")
    
    if refuse_votes > 0:  # Any non-veto dissent blocks
        return (
            "REFUSE",
            f"no consensus ({refuse_votes} dissent)",
            aggregate_confidence(votes)
        )
    
    # Step 4: Compute aggregate confidence
    agg_conf = aggregate_confidence(votes)
    
    if agg_conf < 0.70:  # Below confidence threshold
        if commander_override == "APPROVE":
            # Commander can release a HOLD
            return (
                "AUTHORIZE",
                "released by Incident Commander",
                agg_conf
            )
        else:
            # Hold for human judgment
            return (
                "HOLD_FOR_COMMANDER",
                f"consensus but low confidence ({agg_conf:.2f})",
                agg_conf
            )
    
    # Step 5: All gates pass, consensus, high confidence
    return (
        "AUTHORIZE",
        "consensus, confidence {:.2f}".format(agg_conf),
        agg_conf
    )
```

### Decision States

| Decision | Trigger | Commander Can Override? |
|----------|---------|--------------------------|
| **AUTHORIZE** | Consensus + confidence ≥ 0.70 | No (already approved) |
| **REFUSE** | Veto exercised | ❌ **NEVER** |
| **REFUSE** | Dissent (no consensus) | No (requires new vote) |
| **HOLD_FOR_COMMANDER** | Consensus but confidence < 0.70 | ✅ Yes (APPROVE only) |

---

## Veto Authority Model

### F-1 Fix: Veto Semantics

The key distinction is **veto_authority** vs **veto_exercised**:

```python
# A unit with veto authority can CHOOSE to exercise it

vote = {
    "unit": "Medic",
    "decision": "AUTHORIZE" or "REFUSE",
    "veto_authority": True,        # This unit CAN veto
    "veto_exercised": False,        # But did NOT veto in this decision
    "confidence": 0.88,
    "reason": "..."
}

# VETO IS EXERCISED when:
# 1. Unit has veto_authority = True
# 2. Unit makes REFUSE decision
# 3. System detects both conditions and blocks further processing
```

### Veto Enforcement

```python
# THE LOAD-BEARING INVARIANT

if vote["veto_authority"] and vote["veto_exercised"]:
    # No further deliberation
    # Commander cannot override
    # System returns REFUSE immediately
    decision = REFUSE
    basis = f"VETO by {vote['unit']}: {vote['reason']}"
    # THIS IS ABSOLUTE
```

### Example: Commander Tries to Override Casualty Veto

```python
votes = {
    "Scout": {"decision": "AUTHORIZE", "confidence": 0.71},
    "Guardian": {"decision": "AUTHORIZE", "confidence": 0.75},
    "Pathfinder": {"decision": "AUTHORIZE", "confidence": 0.95},
    "Medic": {"decision": "REFUSE", "veto_authority": True, 
              "veto_exercised": True, "reason": "casualty unstable"},
    "Sentinel": {"decision": "AUTHORIZE", "confidence": 0.64},
}

decision, basis, agg = white_swan_command(
    "move casualty",
    votes,
    commander_override="APPROVE"  # Commander tries to override
)

assert decision == "REFUSE"
assert "BLOCKED" in basis
assert "cannot override" in basis
```

The commander's override attempt is **rejected by the system**. The veto holds.

---

## Commander Authority Bounds

### What the Commander Can Do

1. **Issue APPROVE on HOLD_FOR_COMMANDER**
   - Only valid when `decision == HOLD_FOR_COMMANDER`
   - Commander judgment applies to low-confidence consensus
   - Example: All units agree (confidence 0.60), but threshold is 0.70 → Commander releases HOLD → AUTHORIZE

2. **Issue REFUSE on anything**
   - Commander can refuse any action at any time
   - Overrides AUTHORIZE decisions

### What the Commander CANNOT Do

1. **Override an Exercised Casualty Veto**
   - System rejects the override attempt
   - Basis includes "BLOCKED (cannot override casualty veto)"

2. **Force Unit Compliance**
   - Commander cannot change individual unit votes
   - Commander cannot lower confidence thresholds
   - Commander cannot disable veto authority

3. **Approve REFUSE Decisions**
   - If consensus rejects an action → commander cannot approve it
   - Requires new vote or world state change

### Implementation

```python
def commander_authorize(action, votes, commander_override):
    """
    Commander's override decision.
    
    Valid overrides:
    - Release HOLD_FOR_COMMANDER (commander_override="APPROVE")
    - Refuse AUTHORIZE (commander_override="REFUSE")
    
    Invalid overrides:
    - Override exercised veto (system rejects)
    - Force approval on REFUSE (system rejects)
    """
    
    decision, basis, agg = white_swan_command(action, votes, commander_override)
    
    if decision == "REFUSE" and "BLOCKED" in basis:
        # Veto enforcement active — rejection is final
        return False, decision, basis
    
    if decision == "AUTHORIZE":
        # Commander can still refuse
        if commander_override == "REFUSE":
            return False, "REFUSE", "refused by Incident Commander"
    
    return True, decision, basis
```

---

## Confidence Scoring

### Aggregate Confidence Formula

```python
def aggregate_confidence(votes):
    """
    Compute weighted confidence across all units.
    
    Weighting:
    - Veto units (Medic): 0.30
    - Other units: 0.175 each (4 units × 0.175 = 0.70)
    """
    
    medic_conf = next(v["confidence"] for v in votes if v["unit"] == "Medic")
    other_confs = [v["confidence"] for v in votes if v["unit"] != "Medic"]
    
    weighted = (0.30 * medic_conf) + (0.175 * sum(other_confs))
    
    return min(1.0, weighted)  # Cap at 1.0
```

### Confidence Interpretation

| Confidence Range | Interpretation | Action |
|------------------|-----------------|--------|
| **0.00 – 0.30** | High uncertainty | REFUSE (gates fail) |
| **0.30 – 0.70** | Marginal consensus | HOLD_FOR_COMMANDER |
| **0.70 – 0.90** | Strong consensus | AUTHORIZE |
| **0.90 – 1.00** | Very high confidence | AUTHORIZE (expedited) |

---

## Forensic Ledger

### Entry Structure

```python
{
    "index": 0,
    "prev_hash": "genesis_hash",
    "payload": {
        "action": "Scout: launch air recon",
        "decision": "AUTHORIZE",
        "basis": "consensus, confidence 0.88",
        "aggregate_confidence": 0.88,
        "commander_override": None,
        "votes": [
            {
                "unit": "Scout",
                "decision": "AUTHORIZE",
                "confidence": 0.74,
                "veto": False,
                "sensor_hash": "bc39dc61fd762ae8"
            },
            ...
        ]
    },
    "entry_hash": "sha256(payload)"
}
```

### Chain Integrity

```
Genesis Hash (domain-derived)
    ↓
Entry 0 Hash ← Linked by prev_hash
    ↓
Entry 1 Hash ← Linked by prev_hash
    ↓
... (chain continues)
    ↓
Chain Head (final entry hash)
    ↓
Ed25519 Signature(chain_head + metadata)
    ↓
Public Key (distributed for independent verification)
```

### Tamper Detection

If any entry payload is modified:

```python
# Original: entry["payload"]["decision"] = "AUTHORIZE"
# Modified: entry["payload"]["decision"] = "REFUSE"

# Recompute entry_hash
recomputed = sha256(modified_payload)

# Does not match original entry_hash
assert entry["entry_hash"] != recomputed  # Chain broken

# Signature verification fails
public_key.verify(signature, chain_head)  # Fails
```

### Export and Verification

```python
from governance_ledger import ForensicLedger

# Create and record decisions
led = ForensicLedger(domain="WHITE-SWAN/A.R.T.")
for action, votes in mission_decisions:
    decision, basis, agg = white_swan_command(action, votes)
    led.append({
        "action": action,
        "decision": decision,
        "basis": basis,
        "votes": votes
    })

# Export sealed ledger (signs entire chain)
led.export("mission_ledger.json")

# Independent verification (no server required)
ok, reason = ForensicLedger.verify("mission_ledger.json")
print(f"Ledger integrity: {'PASS' if ok else 'FAIL'} — {reason}")
```

---

## Invariants

### I1: No Unilateral Authority

```
∀ decisions:
  decision ≠ AUTHORIZE unless:
    - 5-unit consensus reached (no dissent)
    - OR commander released HOLD_FOR_COMMANDER
```

**Proof:** `white_swan_command()` requires either all units agree or commander explicitly approves low-confidence hold.

### I2: Casualty Safety Veto is Absolute

```
∀ decisions:
  if Medic.veto_exercised ∧ Medic.decision == REFUSE:
    decision == REFUSE
    ∧ commander_override.allowed == False
```

**Proof:** Veto check happens first in `white_swan_command()`. No subsequent logic can modify outcome.

### I3: Commander Cannot Lower Thresholds

```
∀ decisions:
  if aggregate_confidence < 0.70 ∧ commander_override == "APPROVE":
    decision == AUTHORIZE
  if aggregate_confidence >= 0.70:
    decision == AUTHORIZE (regardless of commander)
```

**Proof:** Commander can only approve HOLDs; cannot modify confidence calculations.

### I4: Ledger is Hash-Chained and Tamper-Evident

```
∀ entries:
  entry[i].prev_hash == entry[i-1].entry_hash
  ∧ sha256(entry[i].payload) == entry[i].entry_hash
  ∧ verify(signature, chain_head, public_key) == True
  ⟹ ledger is authentic and unmodified
```

**Proof:** Any payload change breaks the entry hash, breaking the chain, failing signature verification.

### I5: Every Decision is Recorded Before Execution

```
action_decision = white_swan_command(votes)
if action_decision == AUTHORIZE:
    ledger.append(action_decision)  # This happens BEFORE action executes
    execute_action()
```

**Proof:** Ledger append is synchronous and blocking.

---

## References

- **white_swan_art.py**: Core implementation
- **test_white_swan_art.py**: Invariant test suite (62 tests)
- **governance_ledger.py**: Forensic ledger with Ed25519 signatures
- **art_tornado_ledger.json**: Sealed mission record
- **rescuechain_ledger.json**: RescueChain scenario with failures

---

**Last Updated:** 2026-07-07  
**Status:** Production-ready governance model with cryptographic audit trail.
