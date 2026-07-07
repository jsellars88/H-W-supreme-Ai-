#!/usr/bin/env python3
"""
White Swan A.R.T. — Unified Operations Orchestrator

Single entry point for all governance engine operations:
- Test suite execution
- Scenario simulation (Tornado, RescueChain)
- Ledger verification
- Report generation
"""

import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

# Import core modules
from white_swan_art import (
    white_swan_command,
    tornado_scenario,
    run_rescuechain,
    UNITS
)
from governance_ledger import ForensicLedger


class WhiteSwan:
    """Unified operations orchestrator for White Swan A.R.T."""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.timestamp = datetime.now().isoformat()
        self.results = {}
        
    def log(self, message):
        """Print if verbose mode enabled."""
        if self.verbose:
            print(f"[{self.timestamp}] {message}")
    
    def run_tests(self):
        """Execute pytest test suite."""
        self.log("Starting test suite execution...")
        import subprocess
        result = subprocess.run(
            ["pytest", "test_white_swan_art.py", "-v", "--tb=short"],
            capture_output=True,
            text=True
        )
        self.results["tests"] = {
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "returncode": result.returncode,
            "stdout_lines": len(result.stdout.split("\n"))
        }
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)
        return result.returncode == 0
    
    def run_tornado(self):
        """Execute Tornado scenario."""
        self.log("Starting Tornado scenario...")
        try:
            print("\n" + "="*70)
            print("TORNADO SCENARIO: 6-Decision High-Risk Rescue")
            print("="*70)
            tornado_scenario()
            self.results["tornado"] = {"status": "PASS"}
            return True
        except Exception as e:
            self.results["tornado"] = {"status": "FAIL", "error": str(e)}
            print(f"ERROR: Tornado scenario failed: {e}")
            return False
    
    def run_rescuechain(self):
        """Execute RescueChain scenario."""
        self.log("Starting RescueChain scenario...")
        try:
            print("\n" + "="*70)
            print("RESCUECHAIN SCENARIO: 7-Phase Multi-Failure Mission")
            print("="*70)
            run_rescuechain()
            self.results["rescuechain"] = {"status": "PASS"}
            return True
        except Exception as e:
            self.results["rescuechain"] = {"status": "FAIL", "error": str(e)}
            print(f"ERROR: RescueChain scenario failed: {e}")
            return False
    
    def verify_ledgers(self):
        """Verify all mission ledger integrity."""
        self.log("Verifying ledger integrity...")
        print("\n" + "="*70)
        print("LEDGER VERIFICATION: Cryptographic Integrity Check")
        print("="*70)
        
        ledgers = [
            "art_tornado_ledger.json",
            "rescuechain_ledger.json"
        ]
        
        all_verified = True
        for ledger_path in ledgers:
            if os.path.exists(ledger_path):
                ok, reason = ForensicLedger.verify(ledger_path)
                status = "✓ PASS" if ok else "✗ FAIL"
                print(f"\n{ledger_path}: {status}")
                print(f"  Reason: {reason}")
                self.results.setdefault("ledgers", {})[ledger_path] = {
                    "status": "PASS" if ok else "FAIL",
                    "reason": reason
                }
                all_verified = all_verified and ok
            else:
                print(f"\n{ledger_path}: SKIP (not found)")
        
        return all_verified
    
    def generate_report(self, output_file="OPERATIONS_REPORT.json"):
        """Generate comprehensive operations report."""
        self.log(f"Generating report: {output_file}")
        
        report = {
            "timestamp": self.timestamp,
            "operation": "White Swan A.R.T. Unified Operations",
            "results": self.results,
            "summary": {
                "tests": self.results.get("tests", {}).get("status"),
                "tornado": self.results.get("tornado", {}).get("status"),
                "rescuechain": self.results.get("rescuechain", {}).get("status"),
                "ledger_verification": self.results.get("ledgers", {})
            }
        }
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✓ Report saved to {output_file}")
        return report
    
    def run_all(self):
        """Execute complete operations sequence."""
        print("\n" + "╔" + "="*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  White Swan A.R.T. — Unified Operations Orchestrator".center(68) + "║")
        print("║" + f"  {self.timestamp}".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "="*68 + "╝\n")
        
        operations = [
            ("Test Suite", self.run_tests),
            ("Tornado Scenario", self.run_tornado),
            ("RescueChain Scenario", self.run_rescuechain),
            ("Ledger Verification", self.verify_ledgers),
        ]
        
        passed = 0
        failed = 0
        
        for op_name, op_func in operations:
            try:
                success = op_func()
                if success:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"ERROR in {op_name}: {e}")
                failed += 1
        
        # Generate report
        self.generate_report()
        
        # Print summary
        print("\n" + "╔" + "="*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  OPERATIONS COMPLETE".center(68) + "║")
        print("║" + f"  {passed} Passed | {failed} Failed".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "="*68 + "╝\n")
        
        return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="White Swan A.R.T. — Unified Operations Orchestrator"
    )
    parser.add_argument(
        "operation",
        nargs="?",
        default="all",
        choices=["all", "test", "tornado", "rescuechain", "verify"],
        help="Operation to perform (default: all)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "-o", "--output",
        default="OPERATIONS_REPORT.json",
        help="Output report file (default: OPERATIONS_REPORT.json)"
    )
    
    args = parser.parse_args()
    
    orchestrator = WhiteSwan(verbose=args.verbose)
    
    if args.operation == "all":
        success = orchestrator.run_all()
    elif args.operation == "test":
        success = orchestrator.run_tests()
    elif args.operation == "tornado":
        success = orchestrator.run_tornado()
    elif args.operation == "rescuechain":
        success = orchestrator.run_rescuechain()
    elif args.operation == "verify":
        success = orchestrator.verify_ledgers()
    
    orchestrator.generate_report(args.output)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
