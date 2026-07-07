#!/usr/bin/env python3
"""
White Swan A.R.T. — Integration Test Runner
=============================================

Validates the complete integration between all components:
- Imports and module resolution
- File path assumptions
- Scenario execution
- Ledger generation and verification
- Report generation

Run: python integration_test.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path


class IntegrationTestRunner:
    """Test runner for White Swan A.R.T. integration."""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.errors = []
        
    def test(self, name, func):
        """Run a single test."""
        print(f"\n{'='*70}")
        print(f"TEST: {name}")
        print(f"{'='*70}")
        try:
            func()
            print(f"✓ PASS")
            self.tests_passed += 1
            return True
        except AssertionError as e:
            print(f"✗ FAIL: {e}")
            self.tests_failed += 1
            self.errors.append((name, str(e)))
            return False
        except Exception as e:
            print(f"✗ ERROR: {e}")
            self.tests_failed += 1
            self.errors.append((name, str(e)))
            import traceback
            traceback.print_exc()
            return False
    
    def test_imports(self):
        """Test that all modules can be imported."""
        print("Testing module imports...")
        try:
            import white_swan_art
            print("  ✓ white_swan_art imported")
        except ImportError as e:
            raise AssertionError(f"Failed to import white_swan_art: {e}")
        
        try:
            import governance_ledger
            print("  ✓ governance_ledger imported")
        except ImportError as e:
            raise AssertionError(f"Failed to import governance_ledger: {e}")
        
        try:
            import main
            print("  ✓ main imported")
        except ImportError as e:
            raise AssertionError(f"Failed to import main: {e}")
    
    def test_unit_availability(self):
        """Test that UNITS and functions are exported."""
        print("Testing exported symbols...")
        import white_swan_art as art
        
        assert hasattr(art, 'UNITS'), "UNITS not found in white_swan_art"
        assert len(art.UNITS) == 5, f"Expected 5 UNITS, got {len(art.UNITS)}"
        print(f"  ✓ UNITS exported ({len(art.UNITS)} units)")
        
        assert hasattr(art, 'white_swan_command'), "white_swan_command not found"
        print("  ✓ white_swan_command exported")
        
        assert hasattr(art, 'tornado_scenario'), "tornado_scenario not found"
        print("  ✓ tornado_scenario exported")
        
        assert hasattr(art, 'run_rescuechain'), "run_rescuechain not found"
        print("  ✓ run_rescuechain exported")
    
    def test_governance_ledger_api(self):
        """Test ForensicLedger API."""
        print("Testing ForensicLedger API...")
        from governance_ledger import ForensicLedger
        
        # Create a test ledger
        led = ForensicLedger(domain="TEST/INTEGRATION")
        print("  ✓ ForensicLedger instantiated")
        
        # Test append
        led.append({"test": "entry"})
        assert len(led._entries) == 1, "Append failed"
        print("  ✓ append() works")
        
        # Test export
        test_path = "integration_test_ledger.json"
        led.export(test_path)
        assert os.path.exists(test_path), "Export failed"
        print(f"  ✓ export() works ({test_path})")
        
        # Test sealed property
        assert led.sealed is not None, "sealed property is None"
        assert "entry_count" in led.sealed, "sealed missing entry_count"
        print("  ✓ sealed property accessible")
        
        # Test verify
        ok, reason = ForensicLedger.verify(test_path)
        assert ok, f"Verification failed: {reason}"
        print(f"  ✓ verify() works")
        
        # Cleanup
        os.remove(test_path)
        print("  ✓ Cleanup complete")
    
    def test_scenario_execution(self):
        """Test scenario execution without ledger path conflicts."""
        print("Testing scenario execution...")
        import white_swan_art as art
        
        # Test tornado_scenario with custom path
        ledger_path = "test_tornado.json"
        try:
            ok = art.tornado_scenario(ledger_path=ledger_path)
            assert os.path.exists(ledger_path), f"Ledger not created at {ledger_path}"
            print(f"  ✓ tornado_scenario() executed ({ledger_path})")
            
            # Verify the ledger
            from governance_ledger import ForensicLedger
            ok, reason = ForensicLedger.verify(ledger_path)
            assert ok, f"Ledger verification failed: {reason}"
            print(f"  ✓ tornado_scenario ledger verified")
            
            os.remove(ledger_path)
        except Exception as e:
            raise AssertionError(f"tornado_scenario failed: {e}")
    
    def test_rescuechain_execution(self):
        """Test RescueChain scenario execution."""
        print("Testing RescueChain scenario...")
        import white_swan_art as art
        
        ledger_path = "test_rescuechain.json"
        try:
            ok = art.run_rescuechain(ledger_path=ledger_path)
            assert os.path.exists(ledger_path), f"Ledger not created at {ledger_path}"
            print(f"  ✓ run_rescuechain() executed ({ledger_path})")
            
            # Verify the ledger
            from governance_ledger import ForensicLedger
            ok, reason = ForensicLedger.verify(ledger_path)
            assert ok, f"Ledger verification failed: {reason}"
            print(f"  ✓ run_rescuechain ledger verified")
            
            os.remove(ledger_path)
        except Exception as e:
            raise AssertionError(f"run_rescuechain failed: {e}")
    
    def test_pytest_suite(self):
        """Test that pytest suite runs."""
        print("Testing pytest suite...")
        result = subprocess.run(
            ["pytest", "test_white_swan_art.py", "-v", "--tb=short"],
            capture_output=True,
            text=True
        )
        
        test_count = result.stdout.count(" PASSED")
        print(f"  ✓ pytest executed ({test_count} tests passed)")
        assert result.returncode == 0, f"pytest failed with return code {result.returncode}\n{result.stderr}"
    
    def test_main_orchestrator(self):
        """Test main.py orchestrator."""
        print("Testing main.py orchestrator...")
        result = subprocess.run(
            ["python", "main.py", "test", "-v"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(f"  stdout: {result.stdout[:500]}")
        assert result.returncode == 0, f"main.py test failed: {result.stderr}"
        print("  ✓ main.py test operation passed")
    
    def test_unified_operations(self):
        """Test unified 'make run' equivalent via main.py."""
        print("Testing unified operations (main.py all)...")
        result = subprocess.run(
            ["python", "main.py", "all"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        print(f"  Return code: {result.returncode}")
        
        # Check for OPERATIONS_REPORT.json
        assert os.path.exists("OPERATIONS_REPORT.json"), "OPERATIONS_REPORT.json not created"
        print("  ✓ OPERATIONS_REPORT.json created")
        
        # Parse and validate report
        with open("OPERATIONS_REPORT.json") as f:
            report = json.load(f)
        
        assert "timestamp" in report, "Report missing timestamp"
        assert "results" in report, "Report missing results"
        assert "summary" in report, "Report missing summary"
        print("  ✓ Report structure valid")
        
        # Check for ledger files
        ledgers = ["art_tornado_ledger.json", "rescuechain_ledger.json"]
        for ledger in ledgers:
            if os.path.exists(ledger):
                print(f"  ✓ {ledger} generated")
        
        print("  ✓ Unified operations completed")
    
    def run_all(self):
        """Run all integration tests."""
        print("\n" + "╔" + "="*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  White Swan A.R.T. — Integration Test Suite".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "="*68 + "╝")
        
        self.test("Module Imports", self.test_imports)
        self.test("Unit & Function Exports", self.test_unit_availability)
        self.test("ForensicLedger API", self.test_governance_ledger_api)
        self.test("Tornado Scenario Execution", self.test_scenario_execution)
        self.test("RescueChain Scenario Execution", self.test_rescuechain_execution)
        self.test("Pytest Test Suite", self.test_pytest_suite)
        self.test("Main Orchestrator (test mode)", self.test_main_orchestrator)
        self.test("Unified Operations (main.py all)", self.test_unified_operations)
        
        # Summary
        print("\n" + "╔" + "="*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  INTEGRATION TEST SUMMARY".center(68) + "║")
        print("║" + f"  {self.tests_passed} Passed | {self.tests_failed} Failed".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "="*68 + "╝\n")
        
        if self.errors:
            print("Failures:\n")
            for name, error in self.errors:
                print(f"  • {name}")
                print(f"    {error}\n")
        
        return self.tests_failed == 0


if __name__ == "__main__":
    runner = IntegrationTestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
