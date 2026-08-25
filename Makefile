PYTHON ?= python3
export PYTHONPATH := src

.PHONY: help test offline audit bench gui install clean exe exe-cli exe-fast verify-exe

help:
	@echo "make test     - run the full test suite"
	@echo "make offline  - run only the offline/no-network tests"
	@echo "make audit    - dependency + static checks"
	@echo "make bench    - measure this machine"
	@echo "make gui      - launch the desktop app"
	@echo "make exe      - build standalone executables (this platform only)"
	@echo "make exe-cli  - build only the console executable (no Tk needed)"
	@echo "make exe-fast - one-directory build: ~3x faster to start"

test:
	$(PYTHON) run_tests.py

offline:
	$(PYTHON) run_tests.py offline -v

audit:
	$(PYTHON) -m pip list --format=freeze | grep -Ei 'cryptography|argon2' || true
	$(PYTHON) -m lockbox check --offline || true
	$(PYTHON) run_tests.py offline

bench:
	$(PYTHON) tools/benchmark.py

gui:
	$(PYTHON) -m lockbox gui

install:
	$(PYTHON) -m pip install -e .

exe:
	$(PYTHON) build.py

exe-cli:
	$(PYTHON) build.py --cli-only

exe-fast:
	$(PYTHON) build.py --onedir

verify-exe:
	$(PYTHON) verify_binary.py dist/lockbox

clean:
	$(PYTHON) build.py --clean
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
