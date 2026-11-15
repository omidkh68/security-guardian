PYTHON ?= python3
SKILL := plugins/security-guardian/skills/security-guardian
.PHONY: test validate scan clean

test:
	$(PYTHON) -m unittest discover -s $(SKILL)/tests -v

validate:
	$(PYTHON) scripts/validate_package.py

scan:
	$(PYTHON) $(SKILL)/scripts/security_scan.py --root . --format markdown

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
