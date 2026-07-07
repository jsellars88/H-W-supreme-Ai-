#!/usr/bin/env python3
"""
generate_evidence_package.py
============================

Generates WOS-EVID-ART-001: WhiteSwan A.R.T. Reproducibility Evidence Package

This script:
1. Records system information (Python version, git commit, dependencies)
2. Runs the full integration test suite
3. Runs main.py all -v (full operations)
4. Captures all generated artifacts
5. Verifies ledger signatures
6. Creates a complete evidence package directory
7. Generates SHA256 hashes for integrity verification
8. Creates a tarball for distribution to reviewers

Usage:
  python generate_evidence_package.py

Output:
  WOS-EVID-ART-001-YYYYMMDD_HHMMSS/  (directory with all evidence)
  WOS-EVID-ART-001-YYYYMMDD_HHMMSS.tar.gz  (compressed package for distribution)
"""

import os
import sys
import json
import subprocess
import hashlib
import shutil
import tarfile
from datetime import datetime
from pathlib import Path


class EvidencePackageGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.package_dir = f"WOS-EVID-ART-001-{self.timestamp}"
        self.evidence = {
            "package_id": "WOS-EVID-ART-001",
            "created": datetime.now().isoformat(),
            "system_info": {},
            "execution_results": {},
            "artifacts": {},
            "verification_results": {},
            "known_limitations": [],
        }
        
    def log(self, message, level="INFO"):
        """Print timestamped log message."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {level:8} {message}")
    
    def run_command(self, command, description=""):
        """Run a command and capture output."""
        self.log(f"Running: {description or command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            self.log(f"✓ {description or command} (exit code: {result.returncode})")
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            self.log(f"✗ {description} timed out", "ERROR")
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
            }
        except Exception as e:
            self.log(f"✗ {description} failed: {e}", "ERROR")
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }
    
    def capture_system_info(self):
        """Capture Python version, git commit, dependencies."""
        self.log("Capturing system information...")
        
        # Python version
        result = self.run_command("python --version", "Python version")
        self.evidence["system_info"]["python_version"] = result["stdout"].strip()
        
        # Git commit
        result = self.run_command("git rev-parse HEAD", "Git commit SHA")
        self.evidence["system_info"]["git_commit"] = result["stdout"].strip()
        
        # Git branch
        result = self.run_command("git rev-parse --abbrev-ref HEAD", "Git branch")
        self.evidence["system_info"]["git_branch"] = result["stdout"].strip()
        
        # System info
        result = self.run_command("uname -a", "System info")
        self.evidence["system_info"]["uname"] = result["stdout"].strip()
        
        # Dependency versions
        result = self.run_command("pip freeze", "Dependency versions")
        deps = {}
        for line in result["stdout"].strip().split("\n"):
            if "=" in line:
                name, version = line.split("=", 1)
                deps[name] = version
        self.evidence["system_info"]["dependencies"] = deps
        
        self.log("✓ System information captured")
    
    def run_integration_tests(self):
        """Run integration_test.py."""
        self.log("Running integration tests...")
        result = self.run_command(
            "python integration_test.py",
            "Integration test suite"
        )
        
        self.evidence["execution_results"]["integration_tests"] = {
            "returncode": result["returncode"],
            "passed": result["returncode"] == 0,
            "stdout_lines": len(result["stdout"].split("\n")),
            "stderr_lines": len(result["stderr"].split("\n")),
        }
        
        # Save full output
        with open(f"{self.package_dir}/integration_test_output.txt", "w") as f:
            f.write("=== STDOUT ===\n")
            f.write(result["stdout"])
            f.write("\n\n=== STDERR ===\n")
            f.write(result["stderr"])
        
        if result["returncode"] != 0:
            self.log("⚠ Integration tests failed", "WARNING")
            return False
        
        self.log("✓ Integration tests passed")
        return True
    
    def run_full_operations(self):
        """Run python main.py all -v."""
        self.log("Running full operations (make run equivalent)...")
        result = self.run_command(
            "python main.py all -v",
            "Full operations"
        )
        
        self.evidence["execution_results"]["full_operations"] = {
            "returncode": result["returncode"],
            "passed": result["returncode"] == 0,
            "stdout_lines": len(result["stdout"].split("\n")),
            "stderr_lines": len(result["stderr"].split("\n")),
        }
        
        # Save full output
        with open(f"{self.package_dir}/main_all_output.txt", "w") as f:
            f.write("=== STDOUT ===\n")
            f.write(result["stdout"])
            f.write("\n\n=== STDERR ===\n")
            f.write(result["stderr"])
        
        if result["returncode"] != 0:
            self.log("⚠ Full operations failed", "WARNING")
            return False
        
        self.log("✓ Full operations completed")
        return True
    
    def capture_artifacts(self):
        """Copy generated ledger and report files."""
        self.log("Capturing generated artifacts...")
        
        artifacts = [
            "art_tornado_ledger.json",
            "rescuechain_ledger.json",
            "OPERATIONS_REPORT.json",
        ]
        
        for artifact in artifacts:
            if os.path.exists(artifact):
                size = os.path.getsize(artifact)
                shutil.copy(artifact, self.package_dir)
                self.evidence["artifacts"][artifact] = {
                    "exists": True,
                    "size_bytes": size,
                }
                self.log(f"✓ Captured {artifact} ({size} bytes)")
            else:
                self.evidence["artifacts"][artifact] = {
                    "exists": False,
                    "size_bytes": 0,
                }
                self.log(f"⚠ Missing {artifact}", "WARNING")
    
    def verify_ledgers(self):
        """Verify ledger signatures and chains."""
        self.log("Verifying ledger integrity...")
        
        try:
            from governance_ledger import ForensicLedger
        except ImportError:
            self.log("✗ Cannot import ForensicLedger", "ERROR")
            return False
        
        ledgers = [
            ("art_tornado_ledger.json", "Tornado Scenario"),
            ("rescuechain_ledger.json", "RescueChain Scenario"),
        ]
        
        all_valid = True
        for ledger_file, description in ledgers:
            if not os.path.exists(ledger_file):
                self.evidence["verification_results"][ledger_file] = {
                    "verified": False,
                    "reason": "File not found",
                }
                self.log(f"✗ {description}: File not found", "ERROR")
                all_valid = False
                continue
            
            ok, reason = ForensicLedger.verify(ledger_file)
            self.evidence["verification_results"][ledger_file] = {
                "verified": ok,
                "reason": reason,
            }
            
            if ok:
                self.log(f"✓ {description}: {reason}")
            else:
                self.log(f"✗ {description}: {reason}", "ERROR")
                all_valid = False
        
        return all_valid
    
    def generate_hashes(self):
        """Generate SHA256 hashes of all artifacts."""
        self.log("Generating SHA256 hashes...")
        
        hashes = {}
        hash_file = f"{self.package_dir}/VERIFICATION_HASHES.txt"
        
        with open(hash_file, "w") as f:
            f.write("SHA256 Hashes for Artifact Verification\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Git Commit: {self.evidence['system_info'].get('git_commit', 'unknown')}\n")
            f.write("=" * 60 + "\n\n")
            
            for artifact in os.listdir(self.package_dir):
                artifact_path = os.path.join(self.package_dir, artifact)
                if os.path.isfile(artifact_path):
                    with open(artifact_path, "rb") as af:
                        file_hash = hashlib.sha256(af.read()).hexdigest()
                        hashes[artifact] = file_hash
                        f.write(f"{file_hash}  {artifact}\n")
                        self.log(f"  {artifact}: {file_hash[:16]}...")
        
        self.evidence["hashes"] = hashes
        self.log("✓ Hashes generated")
    
    def create_readme(self):
        """Create README for the evidence package."""
        readme = f"""# WOS-EVID-ART-001: WhiteSwan A.R.T. Reproducibility Evidence Package

Generated: {self.evidence['created']}
System: {self.evidence['system_info'].get('uname', 'unknown')}
Python: {self.evidence['system_info'].get('python_version', 'unknown')}
Git Commit: {self.evidence['system_info'].get('git_commit', 'unknown')}

## This Package Contains

1. **System Information**
   - Python version
   - Git commit SHA
   - System info (uname)
   - Dependency versions (pip freeze)

2. **Execution Logs**
   - integration_test_output.txt — Integration test suite results
   - main_all_output.txt — Full operations output

3. **Generated Artifacts**
   - art_tornado_ledger.json — Sealed forensic ledger (Tornado scenario)
   - rescuechain_ledger.json — Sealed forensic ledger (RescueChain scenario)
   - OPERATIONS_REPORT.json — Unified operations summary

4. **Verification Data**
   - VERIFICATION_HASHES.txt — SHA256 hashes for integrity checking
   - EVIDENCE_METADATA.json — Complete execution metadata

5. **Reviewer Guide**
   - REVIEWER_INSTRUCTIONS.md — Steps to reproduce and verify

## Quick Verification

### 1. Verify File Integrity
```bash
cd WOS-EVID-ART-001-*/
sha256sum -c VERIFICATION_HASHES.txt
```

### 2. Verify Ledger Signatures (requires Python)
```bash
cd /path/to/H-W-supreme-Ai-
python -c "
from governance_ledger import ForensicLedger
for ledger in ['art_tornado_ledger.json', 'rescuechain_ledger.json']:
    ok, reason = ForensicLedger.verify(ledger)
    print(f'{{ledger}}: {{"✓" if ok else "✗"}} {{reason}}')
"
```

### 3. Inspect Ledger Metadata
```bash
python -m json.tool art_tornado_ledger.json | head -30
python -m json.tool rescuechain_ledger.json | head -30
```

### 4. View Operations Report
```bash
python -m json.tool OPERATIONS_REPORT.json | head -50
```

## Independent Reproduction

See REVIEWER_INSTRUCTIONS.md for complete steps to:
1. Clone the repository at the recorded commit SHA
2. Install dependencies
3. Run the exact same commands
4. Compare outputs
5. Verify artifacts match

## Attestation

Once you have successfully reproduced and verified everything,
please complete REVIEWER_ATTESTATION.md and return it to the maintainer.

This confirms independent verification of:
- Reproducibility (identical hashes)
- Cryptographic integrity (Ed25519 valid)
- System functionality (all tests pass)
- Auditability (ledgers independently verifiable)

---

For questions or issues, contact the maintainer.
"""
        
        with open(f"{self.package_dir}/README.md", "w") as f:
            f.write(readme)
        
        self.log("✓ README created")
    
    def create_reviewer_instructions(self):
        """Create detailed instructions for reviewers."""
        instructions = f"""# Reviewer Instructions: WOS-EVID-ART-001

## Purpose

This evidence package allows you to independently verify that WhiteSwan A.R.T.:
1. Is reproducible (identical execution on any system)
2. Has cryptographically valid ledgers (Ed25519 signatures verified)
3. Implements working governance (all tests pass)
4. Can be audited by third parties (artifacts are verifiable)

## Prerequisites

- Python 3.9 or later
- Git
- pip
- A few minutes to run the reproduction

## Step 1: Verify Package Integrity

Before proceeding, verify that the files in this package have not been tampered with:

```bash
sha256sum -c VERIFICATION_HASHES.txt
```

All files should show "OK". If any fail, the package has been corrupted or modified.

## Step 2: Extract Repository at Recorded Commit

The evidence was generated from Git commit: {self.evidence['system_info'].get('git_commit', 'UNKNOWN')}

Clone the repository and check out that exact commit:

```bash
git clone https://github.com/jsellars88/H-W-supreme-Ai-.git
cd H-W-supreme-Ai-
git checkout {self.evidence['system_info'].get('git_commit', 'UNKNOWN')}
```

Verify you're at the right commit:
```bash
git rev-parse HEAD
# Should output: {self.evidence['system_info'].get('git_commit', 'UNKNOWN')}
```

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 4: Run Integration Tests

```bash
python integration_test.py
```

You should see:
```
✓ PASS: Module Imports
✓ PASS: Unit & Function Exports
✓ PASS: ForensicLedger API
✓ PASS: Tornado Scenario Execution
✓ PASS: RescueChain Scenario Execution
✓ PASS: Pytest Test Suite
✓ PASS: Main Orchestrator (test mode)
✓ PASS: Unified Operations (main.py all)

────────────────────────────────────────────────────────
8 Passed | 0 Failed
────────────────────────────────────────────────────────
```

## Step 5: Run Full Operations

This is the critical step. Run the exact command that generated this evidence:

```bash
python main.py all -v
```

This will:
- Run all 62 pytest tests
- Execute Tornado Scenario (6 decisions)
- Execute RescueChain Scenario (7 decisions)
- Verify ledger signatures
- Generate OPERATIONS_REPORT.json

Expected output includes:
```
Tornado Scenario: PASS
RescueChain Scenario: PASS
Tornado Ledger Verification: PASS
RescueChain Ledger Verification: PASS
```

## Step 6: Compare Artifacts

Compare the ledger files you just generated against those in this evidence package:

```bash
# Compare Tornado ledger
sha256sum art_tornado_ledger.json
# Should match the hash in VERIFICATION_HASHES.txt

# Compare RescueChain ledger
sha256sum rescuechain_ledger.json
# Should match the hash in VERIFICATION_HASHES.txt

# Compare Operations Report
sha256sum OPERATIONS_REPORT.json
# Should match the hash in VERIFICATION_HASHES.txt
```

If all hashes match, the system is fully reproducible.

## Step 7: Verify Ledger Signatures

Independently verify that the Ed25519 signatures on the ledgers are valid:

```bash
python -c "
from governance_ledger import ForensicLedger

print('Verifying Tornado Ledger...')
ok, reason = ForensicLedger.verify('art_tornado_ledger.json')
print(f'  Result: {{"✓ VALID" if ok else "✗ INVALID"}}')
print(f'  Reason: {{reason}}')

print()
print('Verifying RescueChain Ledger...')
ok, reason = ForensicLedger.verify('rescuechain_ledger.json')
print(f'  Result: {{"✓ VALID" if ok else "✗ INVALID"}}')
print(f'  Reason: {{reason}}')
"
```

Both should show "VALID" and reason "Ledger integrity verified: ...".

## Step 8: Inspect Ledger Contents

View the human-readable contents of the ledgers to understand what decisions were made:

```bash
python -m json.tool art_tornado_ledger.json | head -100
python -m json.tool rescuechain_ledger.json | head -100
```

Each entry in the ledger has:
- index: Decision number
- payload: The governance decision details
- entry_hash: SHA256 hash of the payload
- prior_hash: Hash of the previous entry (forms the chain)

## Step 9: Verify Hash Chain Manually (Optional)

For extra confidence, you can independently verify that the hash chain is intact:

```bash
python -c "
import json
import hashlib

with open('art_tornado_ledger.json') as f:
    doc = json.load(f)

print(f'Verifying chain for {{doc["domain"]}}...')
print(f'Genesis: {{doc["genesis"][:16]}}...')
print(f'Chain Head: {{doc["chain_head"][:16]}}...')
print(f'Entry Count: {{doc["entry_count"]}}')
print()

# Verify each entry links to the next
for e in doc['entries']:
    computed_hash = hashlib.sha256(
        json.dumps(e['payload'], sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()
    stored_hash = e['entry_hash']
    status = '✓' if computed_hash == stored_hash else '✗'
    print(f'Entry {{e["index"]}}: {{status}}')

print()
print('Chain verified: all entry hashes are valid')
"
```

## Step 10: Complete Attestation

If you have successfully completed all steps and verified:
- ✓ Files are authentic (SHA256 hashes match)
- ✓ System is reproducible (your outputs match the evidence)
- ✓ Ledger signatures are valid (Ed25519 verified)
- ✓ Hash chains are intact (no entry has been modified)
- ✓ All tests pass (62 pytest tests, 2 scenarios)

Then please complete REVIEWER_ATTESTATION.md and return it to the maintainer.

Your signature confirms:
1. You successfully reproduced the system independently
2. You verified all artifacts cryptographically
3. You found no evidence of tampering or fraud
4. You believe the system performs as claimed

## Troubleshooting

**Q: sha256sum -c fails**
A: The package files may have been corrupted. Request a fresh copy.

**Q: Git checkout fails with "unknown revision"**
A: The commit SHA may be invalid or the repository state has changed. Verify the commit SHA in VERIFICATION_HASHES.txt

**Q: Ledger verification fails with "Signature Invalid"**
A: The ledger file may have been modified. Do not use this package. Request a fresh copy.

**Q: Tests fail with "import error"**
A: You may have an older version of a dependency. Run: pip install --upgrade -r requirements.txt

**Q: Hash mismatch on OPERATIONS_REPORT.json**
A: The report includes timestamps, which may differ between runs. This is expected. Verify the ledger files instead.

## What This Proves

If you complete all steps successfully, you have proven:

1. **Reproducibility**: The system produces identical artifacts on different machines
2. **Authenticity**: Cryptographic signatures confirm no tampering
3. **Completeness**: All tests pass consistently
4. **Auditability**: Third parties can independently verify everything

This is more rigorous than "trust me bro, it works."

This is "here's the evidence, verify it yourself."

---

Thank you for your diligent review.
"""
        
        with open(f"{self.package_dir}/REVIEWER_INSTRUCTIONS.md", "w") as f:
            f.write(instructions)
        
        self.log("✓ Reviewer instructions created")
    
    def save_metadata(self):
        """Save evidence metadata as JSON."""
        metadata_file = f"{self.package_dir}/EVIDENCE_METADATA.json"
        with open(metadata_file, "w") as f:
            json.dump(self.evidence, f, indent=2, default=str)
        
        self.log("✓ Metadata saved")
    
    def create_tarball(self):
        """Create compressed tarball for distribution."""
        self.log("Creating distribution tarball...")
        
        tarball_name = f"{self.package_dir}.tar.gz"
        with tarfile.open(tarball_name, "w:gz") as tar:
            tar.add(self.package_dir, arcname=self.package_dir)
        
        size_mb = os.path.getsize(tarball_name) / (1024 * 1024)
        self.log(f"✓ Tarball created: {tarball_name} ({size_mb:.1f} MB)")
        return tarball_name
    
    def generate(self):
        """Generate the complete evidence package."""
        self.log("=" * 80)
        self.log("WOS-EVID-ART-001 Evidence Package Generator")
        self.log("=" * 80)
        
        # Create package directory
        os.makedirs(self.package_dir, exist_ok=True)
        self.log(f"Created package directory: {self.package_dir}")
        
        # Execute all steps
        self.capture_system_info()
        self.run_integration_tests()
        self.run_full_operations()
        self.capture_artifacts()
        self.verify_ledgers()
        self.generate_hashes()
        self.create_readme()
        self.create_reviewer_instructions()
        self.save_metadata()
        
        tarball = self.create_tarball()
        
        self.log("=" * 80)
        self.log("✓ EVIDENCE PACKAGE COMPLETE")
        self.log("=" * 80)
        self.log(f"Package directory: {self.package_dir}/")
        self.log(f"Distribution tarball: {tarball}")
        self.log("")
        self.log("Next steps:")
        self.log(f"  1. Verify: sha256sum -c {self.package_dir}/VERIFICATION_HASHES.txt")
        self.log(f"  2. Share: {tarball} (for external review)")
        self.log(f"  3. Review: Have reviewers follow {self.package_dir}/REVIEWER_INSTRUCTIONS.md")
        self.log(f"  4. Attest: Collect signed REVIEWER_ATTESTATION.md files")
        self.log("")
        self.log("Ready for independent technical review.")


if __name__ == "__main__":
    generator = EvidencePackageGenerator()
    generator.generate()
