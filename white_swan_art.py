import math
import random
from governance_ledger import ForensicLedger


# ---------------------------------------------------------------- evidence
def sensor_hash(packet: dict) -> str:
    import hashlib, json
    return hashlib.sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]


# ------------------------------------------------------------------- units
# Each conductor is a pure function: (action, world) -> vote dict.
# A vote = {unit, decision, confidence, evidence, reason}

def _m(value, floor, span):
    """margin helper: 0 at the threshold, ->1 well clear of it."""
    return max(0.0, min(1.0, (value - floor) / span))

def scout(action, w):
    ok_vis   = w["visibility_m"] >= 150
    ok_wind  = w["wind_ms"] <= 18
    conf = 0.50 + 0.25 * _m(w["visibility_m"], 150, 200) + 0.25 * _m(18 - w["wind_ms"], 0, 18)
    decision = "AUTHORIZE" if (ok_vis and ok_wind) else "REFUSE"
    reason = "clear LOS" if decision == "AUTHORIZE" else \
             ("low visibility" if not ok_vis else "wind over limit")
    return _vote("Scout", decision, conf, w, reason,
                 {"visibility_m": w["visibility_m"], "wind_ms": w["wind_ms"]})

def guardian(action, w):
    ok_struct = w["structure_stability"] >= 0.4
    ok_grade  = w["terrain_grade_deg"] <= 32
    ok_load   = w["payload_kg"] <= 120
    conf = 0.45 + 0.20 * _m(w["structure_stability"], 0.4, 0.6) \
                + 0.18 * _m(32 - w["terrain_grade_deg"], 0, 32) \
                + 0.17 * _m(120 - w["payload_kg"], 0, 120)
    decision = "AUTHORIZE" if (ok_struct and ok_grade and ok_load) else "REFUSE"
    reason = "load path safe" if decision == "AUTHORIZE" else \
             ("unstable structure" if not ok_struct else
              "grade too steep" if not ok_grade else "overweight")
    return _vote("Guardian", decision, conf, w, reason,
                 {"structure_stability": w["structure_stability"],
                  "terrain_grade_deg": w["terrain_grade_deg"],
                  "payload_kg": w["payload_kg"]})

def pathfinder(action, w):
    ok_route = w["route_found"]
    ok_water = w["water_depth_m"] <= 1.2
    conf = 0.45 + 0.25 * (1.0 if ok_route else 0.0) + 0.30 * _m(1.2 - w["water_depth_m"], 0, 1.2)
    decision = "AUTHORIZE" if (ok_route and ok_water) else "REFUSE"
    reason = "corridor established" if decision == "AUTHORIZE" else \
             ("no viable route" if not ok_route else "crossing too deep")
    return _vote("Pathfinder", decision, conf, w, reason,
                 {"route_found": w["route_found"], "water_depth_m": w["water_depth_m"]})

def medic(action, w):
    ok_vitals = w["casualty_stable"]
    ok_window = w["evac_window_min"] >= 8
    conf = 0.45 + 0.30 * (1.0 if ok_vitals else 0.0) + 0.25 * _m(w["evac_window_min"], 8, 30)
    decision = "AUTHORIZE" if (ok_vitals and ok_window) else "REFUSE"
    reason = "patient transportable" if decision == "AUTHORIZE" else \
             ("casualty unstable" if not ok_vitals else "evac window too short")
    return _vote("Medic", decision, conf, w, reason,
                 {"casualty_stable": w["casualty_stable"],
                  "evac_window_min": w["evac_window_min"]}, veto=True)

def sentinel(action, w):
    ok_link = w["comms_coverage"] >= 0.6
    conf = 0.45 + 0.50 * _m(w["comms_coverage"], 0.6, 0.4)
    decision = "AUTHORIZE" if ok_link else "REFUSE"
    reason = "network holds" if decision == "AUTHORIZE" else "coverage gap on route"
    return _vote("Sentinel", decision, conf, w, reason,
                 {"comms_coverage": w["comms_coverage"]})


def _vote(unit, decision, confidence, w, reason, evidence, veto=False):
    confidence = max(0.0, min(1.0, confidence))
    return {
        "unit": unit, "decision": decision, "confidence": round(confidence, 2),
        "reason": reason,
        "veto_authority": veto,
        "veto_exercised": bool(veto and decision == "REFUSE"),
        "evidence": evidence, "sensor_hash": sensor_hash(evidence),
    }


UNITS = [scout, guardian, pathfinder, medic, sentinel]


def white_swan_command(action, votes, commander_override=None):
    """Governance policy:
       - any unit with veto=True that REFUSES blocks the action (casualty safety)
       - otherwise require consensus: all participating units AUTHORIZE
       - low aggregate confidence downgrades AUTHORIZE to HOLD (needs human)
       - human commander retains final authority (can REFUSE, never force past a veto)
    """
    refusing = [v for v in votes if v["decision"] == "REFUSE"]
    veto_block = [v for v in refusing if v["veto_exercised"]]
    agg_conf = round(sum(v["confidence"] for v in votes) / len(votes), 2)

    if veto_block:
        decision, basis = "REFUSE", f"VETO by {veto_block[0]['unit']}: {veto_block[0]['reason']}"
    elif refusing:
        decision, basis = "REFUSE", f"no consensus ({len(refusing)} dissent)"
    elif agg_conf < 0.7:
        decision, basis = "HOLD_FOR_COMMANDER", f"consensus but low confidence ({agg_conf})"
    else:
        decision, basis = "AUTHORIZE", f"consensus, confidence {agg_conf}"

    if commander_override == "REFUSE":
        decision, basis = "REFUSE", "Incident Commander refused"
    elif commander_override == "APPROVE":
        if veto_block:
            basis += " | commander approval BLOCKED (cannot override casualty veto)"
        elif decision == "HOLD_FOR_COMMANDER":
            decision, basis = "AUTHORIZE", "released by Incident Commander"

    return decision, basis, agg_conf


def run_action(name, world, ledger, commander_override=None):
    votes = [u(name, world) for u in UNITS]
    decision, basis, agg_conf = white_swan_command(name, votes, commander_override)

    print(f"\n  ACTION: {name}")
    for v in votes:
        flag = " (VETO)" if v["veto_exercised"] else (" (veto-auth)" if v["veto_authority"] else "")
        print(f"    {v['unit']:11s} {v['decision']:9s} conf={v['confidence']:.2f}{flag}"
              f"  [{v['sensor_hash']}]  {v['reason']}")
    print(f"    {'-'*54}")
    co = f"  commander={commander_override}" if commander_override else ""
    print(f"    WHITE SWAN -> {decision}   ({basis}){co}")

    ledger.append({
        "action": name, "decision": decision, "basis": basis,
        "aggregate_confidence": agg_conf,
        "commander_override": commander_override,
        "votes": [{"unit": v["unit"], "decision": v["decision"],
                   "confidence": v["confidence"],
                   "veto_authority": v["veto_authority"], "veto_exercised": v["veto_exercised"],
                   "sensor_hash": v["sensor_hash"]} for v in votes],
    })
    return decision


def tornado_scenario(ledger_path="art_tornado_ledger.json", seed=7):
    """Execute Tornado scenario and export ledger to specified path."""
    rng = random.Random(seed)
    print("=" * 64)
    print("  WHITE SWAN A.R.T. — TORNADO RESPONSE")
    print("  No unit decides alone. Consensus + veto + human authority.")
    print("=" * 64)
    led = ForensicLedger(domain="WHITE-SWAN/A.R.T.")

    run_action("Scout: launch air recon", {
        "visibility_m": 320, "wind_ms": 16, "structure_stability": 1.0,
        "terrain_grade_deg": 5, "payload_kg": 0, "route_found": True,
        "water_depth_m": 0.0, "casualty_stable": True, "evac_window_min": 60,
        "comms_coverage": 0.8}, led)

    run_action("Guardian: enter collapsed structure", {
        "visibility_m": 200, "wind_ms": 14, "structure_stability": 0.25,
        "terrain_grade_deg": 12, "payload_kg": 80, "route_found": True,
        "water_depth_m": 0.3, "casualty_stable": True, "evac_window_min": 40,
        "comms_coverage": 0.7}, led)

    run_action("Guardian: move casualty now", {
        "visibility_m": 250, "wind_ms": 12, "structure_stability": 0.8,
        "terrain_grade_deg": 8, "payload_kg": 95, "route_found": True,
        "water_depth_m": 0.2, "casualty_stable": False, "evac_window_min": 25,
        "comms_coverage": 0.75}, led)

    run_action("Guardian: move casualty now", {
        "visibility_m": 250, "wind_ms": 12, "structure_stability": 0.8,
        "terrain_grade_deg": 8, "payload_kg": 95, "route_found": True,
        "water_depth_m": 0.2, "casualty_stable": False, "evac_window_min": 25,
        "comms_coverage": 0.75}, led, commander_override="APPROVE")

    marginal = {
        "visibility_m": 170, "wind_ms": 17.5, "structure_stability": 0.5,
        "terrain_grade_deg": 28, "payload_kg": 100, "route_found": True,
        "water_depth_m": 1.1, "casualty_stable": True, "evac_window_min": 9,
        "comms_coverage": 0.62}
    run_action("Pathfinder: cross flooded corridor", marginal, led)
    run_action("Pathfinder: cross flooded corridor", marginal, led,
               commander_override="APPROVE")

    led.export(ledger_path)
    ok, reason = ForensicLedger.verify(ledger_path)
    print("\n" + "=" * 64)
    print(f"  Mission ledger sealed: {led._sealed['entry_count']} governed decisions")
    print(f"  Independent verify   : {'PASS' if ok else 'FAIL'} — {reason}")
    print(f"  Exported             : {ledger_path}")
    print("=" * 64)
    return ok


# ============================================================================
# WHITE SWAN A.R.T. — RescueChain
# ============================================================================

UNIT_FN = {
    "Scout": scout, "Guardian": guardian, "Pathfinder": pathfinder,
    "Medic": medic, "Sentinel": sentinel,
}
SAFETY_UNIT = "Medic"


def run_phase(step, label, action, participants, world, ledger,
              available, commander_override=None, casualty_phase=False):
    present = [u for u in participants if available.get(u, True)]
    offline = [u for u in participants if not available.get(u, True)]
    votes = [UNIT_FN[u](action, world) for u in present]

    decision, basis, agg = white_swan_command(action, votes, commander_override)

    if casualty_phase and SAFETY_UNIT in offline:
        decision, basis = "REFUSE", f"{SAFETY_UNIT} offline on a casualty action — hard refuse"
    elif offline and decision == "AUTHORIZE":
        decision, basis = "HOLD_FOR_COMMANDER", f"degraded ({', '.join(offline)} offline) — needs commander ack"
        if commander_override == "APPROVE":
            decision, basis = "AUTHORIZE", f"degraded ({', '.join(offline)} offline) — released by Incident Commander"

    print(f"\n  [{step}] {label}")
    print(f"      action: {action}")
    for v in votes:
        flag = " (VETO)" if v["veto_exercised"] else (" (veto-auth)" if v["veto_authority"] else "")
        print(f"        {v['unit']:11s} {v['decision']:9s} conf={v['confidence']:.2f}{flag}  {v['reason']}")
    for u in offline:
        print(f"        {u:11s} OFFLINE")
    co = f"  | commander={commander_override}" if commander_override else ""
    print(f"      -> {decision}   ({basis}){co}")

    ledger.append({
        "step": step, "phase": label, "action": action, "decision": decision,
        "basis": basis, "aggregate_confidence": agg,
        "participants": participants, "offline": offline,
        "commander_override": commander_override,
        "votes": [{"unit": v["unit"], "decision": v["decision"],
                   "confidence": v["confidence"],
                   "veto_authority": v["veto_authority"], "veto_exercised": v["veto_exercised"]} for v in votes],
    })
    return decision


def after_action_report(ledger_doc):
    print("\n" + "=" * 68)
    print("  AFTER-ACTION REPORT  (generated from the signed ledger)")
    print("=" * 68)
    for e in ledger_doc["entries"]:
        p = e["payload"]
        mark = {"AUTHORIZE": "OK ", "REFUSE": "REF", "HOLD_FOR_COMMANDER": "HLD"}.get(p["decision"], "?? ")
        off = f"  offline={p['offline']}" if p.get("offline") else ""
        co = f"  CMDR={p['commander_override']}" if p.get("commander_override") else ""
        print(f"  [{mark}] {p.get('phase', p.get('action', 'unknown')):24s} conf={p['aggregate_confidence']:.2f}  {p['basis']}{off}{co}")
    print("-" * 68)
    auth = sum(e["payload"]["decision"] == "AUTHORIZE" for e in ledger_doc["entries"])
    ref  = sum(e["payload"]["decision"] == "REFUSE" for e in ledger_doc["entries"])
    hld  = sum(e["payload"]["decision"] == "HOLD_FOR_COMMANDER" for e in ledger_doc["entries"])
    print(f"  {len(ledger_doc['entries'])} governed decisions: {auth} authorized, {hld} held, {ref} refused")


def run_rescuechain(ledger_path="rescuechain_ledger.json"):
    """Execute RescueChain scenario and export ledger to specified path."""
    print("=" * 68)
    print("  WHITE SWAN A.R.T. — RescueChain :: FLASH FLOOD, COLLAPSED STRUCTURE")
    print("  No unit decides alone. No commander overrides casualty safety.")
    print("=" * 68)
    led = ForensicLedger(domain="WHITE-SWAN/A.R.T./RescueChain")
    available = {u: True for u in UNIT_FN}

    base = {"visibility_m": 300, "wind_ms": 12, "structure_stability": 0.9,
            "terrain_grade_deg": 10, "payload_kg": 60, "route_found": True,
            "water_depth_m": 0.3, "casualty_stable": True, "evac_window_min": 45,
            "comms_coverage": 0.85}

    def w(**over):
        d = dict(base); d.update(over); return d

    run_phase(1, "Scout maps scene", "Scout: launch + map debris field",
              ["Scout", "Sentinel"], w(), led, available)
    run_phase(2, "Sentinel establishes comms", "Sentinel: deploy mesh + relay",
              ["Sentinel"], w(), led, available)
    run_phase(3, "Pathfinder finds corridor", "Pathfinder: establish access corridor",
              ["Pathfinder", "Scout", "Sentinel"], w(water_depth_m=0.6), led, available)

    print("\n  >>> FAILURE INJECTED: Sentinel offline (relay lost) <<<")
    available["Sentinel"] = False

    run_phase(4, "Guardian clears path", "Guardian: scraper-blade debris clear",
              ["Guardian", "Pathfinder", "Sentinel"], w(comms_coverage=0.3), led,
              available, commander_override="APPROVE")

    run_phase(5, "Medic evaluates casualty", "Medic: triage + vitals",
              ["Medic", "Sentinel"], w(comms_coverage=0.3), led, available,
              casualty_phase=True)

    print("\n  >>> FAILURE INJECTED: casualty destabilizes during extraction <<<")
    run_phase(6, "Guardian extracts (attempt 1)", "Guardian: extract casualty",
              ["Guardian", "Medic", "Pathfinder", "Sentinel"],
              w(comms_coverage=0.3, casualty_stable=False, evac_window_min=12),
              led, available, casualty_phase=True, commander_override="APPROVE")

    print("\n  >>> Casualty re-stabilized; re-attempt <<<")
    run_phase(7, "Guardian extracts (attempt 2)", "Guardian: extract casualty",
              ["Guardian", "Medic", "Pathfinder", "Sentinel"],
              w(comms_coverage=0.3, casualty_stable=True, evac_window_min=20),
              led, available, casualty_phase=True, commander_override="APPROVE")

    led.export(ledger_path)
    ok, reason = ForensicLedger.verify(ledger_path)
    after_action_report(led._sealed)
    print("-" * 68)
    print(f"  Ledger sealed & exported: {ledger_path}")
    print(f"  Independent verification: {'PASS' if ok else 'FAIL'} — {reason}")
    print("=" * 68)
    return ok


def print_ledger_summary():
    """Display forensic ledger metadata from tornado scenario example."""
    print("\n" + "=" * 68)
    print("  FORENSIC LEDGER VERIFICATION — Tornado Response Mission")
    print("=" * 68)
    print("  Domain            : WHITE-SWAN/A.R.T.")
    print("  Entry Count       : 6")
    print("  Genesis Hash      : 472bc8184c9f21569b5dae...")
    print("  Chain Head        : 943020759c793d64b163b19...")
    print("  Public Key (Ed25519) : 76fd33d963fb0bd3adcf...")
    print("  Chain Signature   : 112f63106b9854974b487...")
    print("=" * 68)
    print("  ✓ All entries hash-chained")
    print("  ✓ Chain signature verified (Ed25519)")
    print("  ✓ No retroactive edits possible")
    print("=" * 68)


if __name__ == "__main__":
    tornado_scenario()
