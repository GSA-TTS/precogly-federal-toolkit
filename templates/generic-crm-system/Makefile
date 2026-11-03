# Generic CRM System Template Pipeline

# Override UV to use a different runner (e.g. UV='mise exec -- uv run python').
UV ?= uv run --with pyyaml python
SCRIPTS := scripts
# Override CATALOG with the path to your NIST 800-53r5 catalog.json
CATALOG ?= $(error CATALOG is not set. Pass CATALOG=/path/to/catalog.json)

# Override each OSCAL_SOURCES entry with your agency component-definition paths
OSCAL_SOURCES ?= $(error OSCAL_SOURCES is not set. See README.md for format)

.PHONY: all help pack shell-cdx validate clean cold-start

help:
	@echo "Available targets:"
	@echo "  make all        - Runs convert, shell-cdx, and validate"
	@echo "  make pack       - Transforms OSCAL files into Precogly library packs"
	@echo "  make shell-cdx  - Combines library packs and generic-dfd into generic-crm-shell.cdx.json"
	@echo "  make validate   - Runs enums, bidirectional-linkage, and privacy redaction checks"
	@echo "  make clean      - Removes generated files and clean workspaces"
	@echo "  make cold-start - Copy this template to a temp dir and run 'all' on synthetic fixtures"

all: pack shell-cdx validate

pack:
	$(UV) $(SCRIPTS)/oscal_to_precogly_pack.py --catalog $(CATALOG) $(OSCAL_SOURCES)

shell-cdx:
	$(UV) $(SCRIPTS)/build_shell_cdx.py

validate:
	$(UV) $(SCRIPTS)/validate.py

clean:
	rm -rf pack pack-oscal-800-53r5 build/generic-crm-shell.cdx.json

# Quick-start smoke test: copy the template, run the full pipeline against the
# synthetic fixtures, and assert the outputs exist. Never touches this tree.
cold-start:
	@set -e; start=$$(date +%s); tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	cp -r . "$$tmp/system"; \
	$(MAKE) --no-print-directory -C "$$tmp/system" clean; \
	$(MAKE) --no-print-directory -C "$$tmp/system" all UV='$(UV)' \
	  CATALOG="$$tmp/system/examples/synthetic/catalog.json" \
	  OSCAL_SOURCES="$$tmp/system/examples/synthetic/component-definition.json"; \
	test -s "$$tmp/system/build/generic-crm-shell.cdx.json"; \
	test -s "$$tmp/system/pack/pack.yaml"; \
	test -s "$$tmp/system/pack-oscal-800-53r5/pack.yaml"; \
	echo "Cold-start completed in $$(( $$(date +%s) - start )) seconds"
