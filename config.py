#!/usr/bin/env python3
"""
White Swan A.R.T. Configuration Module

Centralized configuration for all scenarios, ledgers, and operations.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Unit:
    """Configuration for a governance unit."""
    name: str
    role: str
    has_veto: bool
    confidence_weight: float = 0.2


@dataclass
class Scenario:
    """Configuration for a governance scenario."""
    name: str
    description: str
    decisions: List[Dict]
    ledger_file: str


class Config:
    """Centralized White Swan A.R.T. configuration."""
    
    # ============================================================================
    # GOVERNANCE UNITS
    # ============================================================================
    
    UNITS = {
        "scout": Unit(
            name="Scout",
            role="Visibility & environmental conditions",
            has_veto=False,
            confidence_weight=0.2
        ),
        "guardian": Unit(
            name="Guardian",
            role="Structural integrity & hazards",
            has_veto=False,
            confidence_weight=0.2
        ),
        "pathfinder": Unit(
            name="Pathfinder",
            role="Route viability & traversal",
            has_veto=False,
            confidence_weight=0.2
        ),
        "medic": Unit(
            name="Medic",
            role="Casualty health & safety (ABSOLUTE VETO)",
            has_veto=True,
            confidence_weight=0.2
        ),
        "sentinel": Unit(
            name="Sentinel",
            role="Communications reliability",
            has_veto=False,
            confidence_weight=0.2
        ),
    }
    
    # ============================================================================
    # DECISION THRESHOLDS
    # ============================================================================
    
    # Consensus confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.70
    LOW_CONFIDENCE_THRESHOLD = 0.50
    
    # Decision states
    DECISION_AUTHORIZE = "AUTHORIZE"
    DECISION_HOLD_FOR_COMMANDER = "HOLD_FOR_COMMANDER"
    DECISION_REFUSE = "REFUSE"
    
    # ============================================================================
    # LEDGER CONFIGURATION
    # ============================================================================
    
    LEDGER_CONFIG = {
        "hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "indent": 2,
        "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ",
    }
    
    # ============================================================================
    # SCENARIO DEFINITIONS
    # ============================================================================
    
    SCENARIOS = {
        "tornado": {
            "name": "Tornado Scenario",
            "description": "High-Risk Rescue with 6 Critical Decisions",
            "ledger_file": "art_tornado_ledger.json",
            "decisions": [
                {
                    "id": 1,
                    "action": "Launch Air Recon",
                    "context": "Scout visibility limited to 50m radius"
                },
                {
                    "id": 2,
                    "action": "Approach Casualty Location",
                    "context": "Pathfinder reports debris field hazard"
                },
                {
                    "id": 3,
                    "action": "Deploy Medical Assessment",
                    "context": "Medic uncertainty on casualty responsiveness"
                },
                {
                    "id": 4,
                    "action": "Establish Extraction Path",
                    "context": "Guardian detects structural instability"
                },
                {
                    "id": 5,
                    "action": "Begin Casualty Transport",
                    "context": "Sentinel reports intermittent comms"
                },
                {
                    "id": 6,
                    "action": "Execute Final Egress",
                    "context": "All units report readiness"
                }
            ]
        },
        "rescuechain": {
            "name": "RescueChain Scenario",
            "description": "7-Phase Multi-Failure Mission",
            "ledger_file": "rescuechain_ledger.json",
            "decisions": [
                {
                    "id": 1,
                    "action": "Respond to Emergency Call",
                    "context": "Dispatcher confirms 3+ casualties"
                },
                {
                    "id": 2,
                    "action": "Dispatch Advance Team",
                    "context": "Weather conditions marginal"
                },
                {
                    "id": 3,
                    "action": "Scout Route Viability",
                    "context": "Primary route blocked by debris"
                },
                {
                    "id": 4,
                    "action": "Assess Structural Integrity",
                    "context": "Building shows signs of collapse risk"
                },
                {
                    "id": 5,
                    "action": "Evaluate Casualty Condition",
                    "context": "Multiple injuries requiring triage"
                },
                {
                    "id": 6,
                    "action": "Coordinate Multi-Team Operation",
                    "context": "Communication delays detected"
                },
                {
                    "id": 7,
                    "action": "Execute Full Extraction",
                    "context": "All units report go status"
                }
            ]
        }
    }
    
    # ============================================================================
    # TEST CONFIGURATION
    # ============================================================================
    
    TEST_CONFIG = {
        "test_file": "test_white_swan_art.py",
        "expected_test_count": 62,
        "required_tests": [
            "test_consensus_all_authorize",
            "test_consensus_with_dissent",
            "test_medic_veto_absolute",
            "test_commander_cannot_override_medic",
            "test_low_confidence_hold",
            "test_ledger_chain_integrity",
            "test_ledger_tamper_detection",
            "test_signature_verification",
        ]
    }
    
    # ============================================================================
    # OPERATIONS CONFIGURATION
    # ============================================================================
    
    OPERATIONS_CONFIG = {
        "report_file": "OPERATIONS_REPORT.json",
        "operations": [
            "test",
            "tornado",
            "rescuechain",
            "verify"
        ],
        "parallel": False,
        "timeout_seconds": 300,
    }
    
    # ============================================================================
    # LOGGING CONFIGURATION
    # ============================================================================
    
    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "[%(asctime)s] %(levelname)s — %(name)s: %(message)s"
            },
            "verbose": {
                "format": "[%(asctime)s] %(levelname)s — %(pathname)s:%(lineno)d — %(funcName)s(): %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "standard",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "formatter": "verbose",
                "filename": "white_swan_art.log"
            }
        },
        "root": {
            "level": "INFO",
            "handlers": ["console", "file"]
        }
    }
    
    # ============================================================================
    # DEPLOYMENT CONFIGURATION
    # ============================================================================
    
    DEPLOYMENT_CONFIG = {
        "python_versions": ["3.9", "3.10", "3.11", "3.12"],
        "ci_platforms": ["github-actions"],
        "artifact_retention_days": 30,
        "security_checks": [
            "bandit",
            "flake8",
            "black"
        ]
    }
    
    @classmethod
    def get_unit(cls, unit_name: str) -> Optional[Unit]:
        """Get a unit by name."""
        return cls.UNITS.get(unit_name.lower())
    
    @classmethod
    def get_scenario(cls, scenario_name: str) -> Optional[Dict]:
        """Get a scenario by name."""
        return cls.SCENARIOS.get(scenario_name.lower())
    
    @classmethod
    def get_all_units(cls) -> List[Unit]:
        """Get all governance units."""
        return list(cls.UNITS.values())
    
    @classmethod
    def get_all_scenarios(cls) -> Dict:
        """Get all scenario definitions."""
        return cls.SCENARIOS
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration consistency."""
        # Check units
        if not cls.UNITS or len(cls.UNITS) != 5:
            return False
        
        # Check veto authority (only Medic)
        veto_units = [u for u in cls.UNITS.values() if u.has_veto]
        if len(veto_units) != 1 or veto_units[0].name != "Medic":
            return False
        
        # Check thresholds
        if cls.HIGH_CONFIDENCE_THRESHOLD <= cls.LOW_CONFIDENCE_THRESHOLD:
            return False
        
        # Check scenarios
        if not cls.SCENARIOS or len(cls.SCENARIOS) != 2:
            return False
        
        return True


# ============================================================================
# EXPORT
# ============================================================================

if __name__ == "__main__":
    print("White Swan A.R.T. Configuration Module")
    print("=" * 70)
    
    # Validate
    if Config.validate():
        print("✓ Configuration is valid")
    else:
        print("✗ Configuration validation failed")
        exit(1)
    
    # Print summary
    print(f"\nGovernance Units: {len(Config.UNITS)}")
    for name, unit in Config.UNITS.items():
        veto = "✓ VETO" if unit.has_veto else "❌ No veto"
        print(f"  • {unit.name}: {unit.role} ({veto})")
    
    print(f"\nScenarios: {len(Config.SCENARIOS)}")
    for name, scenario in Config.SCENARIOS.items():
        print(f"  • {scenario['name']}: {len(scenario['decisions'])} decisions")
    
    print(f"\nThresholds:")
    print(f"  • High Confidence: {Config.HIGH_CONFIDENCE_THRESHOLD}")
    print(f"  • Low Confidence: {Config.LOW_CONFIDENCE_THRESHOLD}")
    
    print(f"\nTest Configuration: {Config.TEST_CONFIG['expected_test_count']} tests")
    print(f"\nDeployment Platforms: {len(Config.DEPLOYMENT_CONFIG['python_versions'])} Python versions")
    
    print("\n✓ Configuration ready")
