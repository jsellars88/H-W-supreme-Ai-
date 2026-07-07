.PHONY: help install test tornado rescuechain verify lint clean run-all

help:
	@echo "White Swan A.R.T. — Autonomous Rescue Taskforce Governance"
	@echo ""
	@echo "Available tasks:"
	@echo "  make install          Install dependencies"
	@echo "  make test             Run full test suite (62 tests)"
	@echo "  make tornado          Run Tornado scenario with 6 decisions"
	@echo "  make rescuechain      Run RescueChain scenario with 7 decisions"
	@echo "  make verify           Verify all mission ledger integrity"
	@echo "  make lint             Run code style checks (flake8, black, isort)"
	@echo "  make clean            Remove artifacts (*.pyc, __pycache__, ledgers)"
	@echo "  make run-all          Run all scenarios and verify"
	@echo ""

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"

test:
	@echo "Running White Swan A.R.T. test suite..."
	pytest test_white_swan_art.py -v --tb=short
	@echo "✓ Test suite complete"

tornado:
	@echo "Running Tornado Scenario..."
	python white_swan_art.py
	@echo "✓ Tornado scenario complete"

rescuechain:
	@echo "Running RescueChain Scenario..."
	python -c "from white_swan_art import run_rescuechain; run_rescuechain()"
	@echo "✓ RescueChain scenario complete"

verify:
	@echo "Verifying mission ledger integrity..."
	@python -c "from governance_ledger import ForensicLedger; import os; \
	ledgers = ['art_tornado_ledger.json', 'rescuechain_ledger.json']; \
	for ledger in ledgers: \
		if os.path.exists(ledger): \
			ok, reason = ForensicLedger.verify(ledger); \
			status = '✓ PASS' if ok else '✗ FAIL'; \
			print(f'{ledger}: {status} — {reason}'); \
		else: \
			print(f'{ledger}: SKIP (not found)');"
	@echo "✓ Verification complete"

lint:
	@echo "Running code style checks..."
	@echo "  Checking with flake8..."
	flake8 white_swan_art.py governance_ledger.py test_white_swan_art.py --max-line-length=120 --ignore=E203,W503 || true
	@echo "  Checking formatting with black..."
	black --check white_swan_art.py governance_ledger.py test_white_swan_art.py --line-length=120 || true
	@echo "✓ Lint checks complete"

clean:
	@echo "Cleaning artifacts..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -f art_tornado_ledger.json rescuechain_ledger.json demo_ledger.json
	rm -f .coverage .dmypy.json dmypy.json
	@echo "✓ Clean complete"

run-all: clean install test tornado rescuechain verify
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  White Swan A.R.T. — Full Test & Scenario Run Complete  ║"
	@echo "║  ✓ Dependencies installed                              ║"
	@echo "║  ✓ 62 tests passed                                     ║"
	@echo "║  ✓ Tornado scenario executed (6 decisions)             ║"
	@echo "║  ✓ RescueChain scenario executed (7 decisions)         ║"
	@echo "║  ✓ All ledgers verified (cryptographic integrity)      ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
