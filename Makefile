SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
RENOVATE_VERSION := 44.167.5
SMOKE_IMAGE := localhost/linux-compliance-runner:smoke
GRYPE_VERSION := 0.121.0
GRYPE_SHA256_LINUX_AMD64 := 64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
GRYPE_DB_SCHEMA := 6
GRYPE_DB_MAX_AGE_HOURS := 120
GRYPE_DB_URL := https://grype.anchore.io/databases/v$(GRYPE_DB_SCHEMA)
GRYPE_RELEASE_URL := https://github.com/anchore/grype/releases/download/v$(GRYPE_VERSION)
GRYPE_ARCHIVE := grype_$(GRYPE_VERSION)_linux_amd64.tar.gz
GRYPE_DIR := build/tools/grype-$(GRYPE_VERSION)
GRYPE := $(GRYPE_DIR)/grype
GRYPE_CONFIG := security/grype.yaml
GRYPE_EXPECTED_CONFIG := security/grype-expected-config.json
GRYPE_DB_DIR := build/grype-db
GRYPE_ENV_PASSTHROUGH := PATH HOME TMPDIR DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY \
	CONTAINER_HOST XDG_RUNTIME_DIR
GRYPE_RUN = env -i $(foreach name,$(GRYPE_ENV_PASSTHROUGH),$(name)="$${$(name)-}") \
	GRYPE_DB_CACHE_DIR='$(CURDIR)/$(GRYPE_DB_DIR)/cache' GRYPE_DB_MAX_ALLOWED_BUILT_AGE=$(GRYPE_DB_MAX_AGE_HOURS)h \
	$(GRYPE) --config $(GRYPE_CONFIG)
ALPINE_MINOR := $(shell sed -n 's|^FROM docker\.io/library/alpine:\([0-9.]*\)@sha256:.*|\1|p' Containerfile)
SCAN_IMAGE := $(SMOKE_IMAGE)
SCAN_DIR := build/image-scan
VULNERABILITY_EXCEPTIONS := security/vulnerability-exceptions.yaml
CURL := curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 30
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct)
BUILD_DATE := $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ)
CONTAINER_ENGINE := $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)
TRACKED := git ls-files -z --cached --others --exclude-standard
ZIZMOR_PERSONA := pedantic
REQUIRED_SKILLS := architecture aws-infrastructure github-actions container-security python-quality \
	security-review jira-management documentation release-engineering dependency-management code-review
EXTERNAL_SKILLS := ansible-collection ansible-modules compliance-frameworks molecule-testing packer-images \
	reporting-dashboard

NOT_IMPLEMENTED = @printf 'not implemented yet: %s (tracked in %s)\n' '$(1)' '$(2)' >&2; exit 2

define HELP_TEXT
Usage: make <target>

Setup
  help                  Show this help
  bootstrap             Install tooling and git hooks, then verify the environment
  install               Sync the locked Python environment and install pre-commit and pre-push hooks

Formatting and linting
  format                Apply Ruff fixes and formatting
  lint                  Run every implemented linter (repo, skills, python, yaml, actions, container)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-repo             Repository source rules (document start, comments, banned modules)
  lint-skills           Validate agent skills under .agents/skills
  lint-renovate         renovate-config-validator (pinned Renovate, needs Node.js 24)
  lint-container        hadolint on every Containerfile and a check that toolbox/uv.lock matches its pyproject
  lint-iac              [pending FREES-30] OpenTofu validation and Checkov

Security and types
  security              Bandit, gitleaks history scan and zizmor
  typecheck             mypy strict and Pyright strict

Tests
  test                  Alias for test-unit
  test-unit             Unit tests
  test-coverage         Unit tests with branch coverage thresholds

Image and AWS
  aws-bootstrap         [pending FREES-33] Bootstrap AWS prerequisites
  image-build           [pending FREES-36] Build the runner image on AWS
  image-scan            Scan the local test image with the pinned Grype and apply the exception gate
  grype-expected-config Rewrite security/grype-expected-config.json from the last scan (after a Grype bump)
  sbom                  [pending FREES-37] Generate the image SBOM
  sign                  [pending FREES-37] Sign the image and attest the SBOM
  image-smoke           Build the toolbox image locally (never published) and run the smoke tests

Docs and release
  docs                  markdownlint and relative link check
  release-check         [pending FREES-84] Verify release readiness

Housekeeping
  clean                 Remove caches and generated files
  ci                    Run the credential-free CI stages locally
endef
export HELP_TEXT

.PHONY: help bootstrap install format lint lint-python lint-yaml lint-actions lint-repo \
	lint-skills lint-container lint-renovate lint-iac security typecheck test test-unit test-coverage \
	aws-bootstrap image-build image-scan sbom sign image-smoke toolbox-lock-check docs release-check clean ci \
	require-uv require-container-engine grype-db grype-expected-config

help:
	@printf '%s\n' "$$HELP_TEXT"

require-uv:
	@if [ -z "$(UV)" ]; then \
		printf 'error: uv is required but was not found on PATH\n' >&2; \
		printf 'install it from https://docs.astral.sh/uv/getting-started/installation/\n' >&2; \
		exit 1; \
	fi

install: require-uv
	uv sync --frozen
	$(RUN) pre-commit install

bootstrap: install
	@command -v git >/dev/null || { printf 'error: git is required\n' >&2; exit 1; }
	$(RUN) python --version
	$(RUN) pre-commit --version

format: require-uv
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

lint: lint-repo lint-skills lint-python lint-yaml lint-actions lint-container lint-renovate

lint-renovate:
	@node_major="$$(node --version 2>/dev/null | sed -e 's/^v//' -e 's/\..*//')"; \
	if [ -z "$$node_major" ] || [ "$$node_major" -lt 24 ]; then \
		printf 'error: lint-renovate needs Node.js 24 or newer on PATH (found: %s); Renovate %s does not run on older versions\n' \
			"$${node_major:-none}" '$(RENOVATE_VERSION)' >&2; \
		exit 1; \
	fi
	npx --yes --package renovate@$(RENOVATE_VERSION) renovate-config-validator --strict --no-global .renovaterc.json

lint-python: require-uv
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) pylint tools tests

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-repo: require-uv
	$(TRACKED) -- '*.yml' '*.yaml' '*.py' | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py

lint-skills: require-uv
	$(RUN) python tools/skills/validate_skills.py \
		--required $(REQUIRED_SKILLS) \
		--external $(EXTERNAL_SKILLS)

lint-container: require-uv toolbox-lock-check
	@containerfiles="$$(git ls-files --cached --others --exclude-standard -- 'Containerfile' '*/Containerfile')"; \
	if [ -z "$$containerfiles" ]; then \
		printf 'lint-container: no Containerfile in the repository, nothing to lint\n'; \
	else \
		printf '%s\n' "$$containerfiles" | xargs $(RUN) hadolint; \
	fi

toolbox-lock-check: require-uv
	uv lock --check --directory toolbox

lint-iac:
	$(call NOT_IMPLEMENTED,lint-iac,FREES-30)

security: require-uv
	$(RUN) bandit -c pyproject.toml -r tools -q
	$(RUN) pre-commit run gitleaks-history --hook-stage manual --all-files
	$(RUN) zizmor --persona $(ZIZMOR_PERSONA) .github/workflows

typecheck: require-uv
	$(RUN) mypy
	$(RUN) pyright

test: test-unit

test-unit: require-uv
	$(RUN) pytest tests/unit

test-coverage: require-uv
	$(RUN) pytest tests/unit --cov --cov-report=term-missing --cov-report=xml
	$(RUN) coverage report --include='tools/*' --fail-under=100

aws-bootstrap:
	$(call NOT_IMPLEMENTED,aws-bootstrap,FREES-33)

image-build:
	$(call NOT_IMPLEMENTED,image-build,FREES-36)

require-container-engine:
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		printf 'error: docker or podman is required for the image targets\n' >&2; \
		exit 1; \
	fi

$(GRYPE):
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the pinned Grype download is linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(GRYPE_DIR).download
	mkdir -p $(GRYPE_DIR).download
	$(CURL) --max-time 120 --output $(GRYPE_DIR).download/checksums.txt \
		$(GRYPE_RELEASE_URL)/grype_$(GRYPE_VERSION)_checksums.txt
	$(CURL) --max-time 600 --output $(GRYPE_DIR).download/$(GRYPE_ARCHIVE) $(GRYPE_RELEASE_URL)/$(GRYPE_ARCHIVE)
	@if ! grep -Fqx '$(GRYPE_SHA256_LINUX_AMD64)  $(GRYPE_ARCHIVE)' $(GRYPE_DIR).download/checksums.txt; then \
		printf 'error: the pinned Grype checksum is not in the release checksums file\n' >&2; \
		exit 1; \
	fi
	cd $(GRYPE_DIR).download && \
		printf '%s  %s\n' '$(GRYPE_SHA256_LINUX_AMD64)' '$(GRYPE_ARCHIVE)' | sha256sum --check --strict - && \
		tar -xzf $(GRYPE_ARCHIVE) grype
	test "$$($(GRYPE_DIR).download/grype version -o json | jq -r .version)" = '$(GRYPE_VERSION)'
	test "$$($(GRYPE_DIR).download/grype version -o json | jq -r .supportedDbSchema)" = '$(GRYPE_DB_SCHEMA)'
	install -D -m 0755 $(GRYPE_DIR).download/grype $(GRYPE)
	rm -rf $(GRYPE_DIR).download

grype-db: $(GRYPE)
	mkdir -p $(SCAN_DIR) $(GRYPE_DB_DIR)/archives
	$(CURL) --max-time 60 --output $(SCAN_DIR)/db-listing.json $(GRYPE_DB_URL)/latest.json
	@if ! jq -e '.status == "active"' $(SCAN_DIR)/db-listing.json >/dev/null; then \
		printf 'error: the vulnerability database listing is not active\n' >&2; \
		exit 1; \
	fi; \
	archive="$$(jq -er .path $(SCAN_DIR)/db-listing.json)"; \
	checksum="$$(jq -er .checksum $(SCAN_DIR)/db-listing.json)"; \
	if ! printf '%s\n' "$$archive" | grep -Eqx \
		'vulnerability-db_v$(GRYPE_DB_SCHEMA)\.[0-9]+\.[0-9]+_[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z_[0-9]+\.tar\.zst'; then \
		printf 'error: unexpected vulnerability database archive name in the listing\n' >&2; \
		exit 1; \
	fi; \
	if ! printf '%s\n' "$$checksum" | grep -Eqx 'sha256:[0-9a-f]{64}'; then \
		printf 'error: unexpected vulnerability database checksum format in the listing\n' >&2; \
		exit 1; \
	fi; \
	target="$(GRYPE_DB_DIR)/archives/$$archive"; \
	if [ ! -f "$$target" ]; then \
		printf 'downloading %s\n' "$$archive"; \
		$(CURL) --max-time 900 --output "$$target.part" "$(GRYPE_DB_URL)/$$archive"; \
		mv "$$target.part" "$$target"; \
	fi; \
	if ! printf '%s  %s\n' "$${checksum#sha256:}" "$$target" | sha256sum --check --strict -; then \
		rm -f "$$target"; \
		printf 'error: the vulnerability database archive does not match the listing checksum\n' >&2; \
		exit 1; \
	fi; \
	find $(GRYPE_DB_DIR)/archives -type f ! -name "$$archive" -delete; \
	$(GRYPE_RUN) db import "$$target"
	$(GRYPE_RUN) db status --output json > $(SCAN_DIR)/db-status.json

image-scan: require-uv require-container-engine $(GRYPE)
	@if ! [ '$(GRYPE_DB_MAX_AGE_HOURS)' -ge 1 ] 2>/dev/null || [ '$(GRYPE_DB_MAX_AGE_HOURS)' -gt 120 ]; then \
		printf 'error: GRYPE_DB_MAX_AGE_HOURS must be an integer from 1 to 120 (the gate ceiling)\n' >&2; \
		exit 1; \
	fi
	@if ! $(CONTAINER_ENGINE) image inspect '$(SCAN_IMAGE)' >/dev/null 2>&1; then \
		printf 'error: image %s not found; run make image-smoke first\n' '$(SCAN_IMAGE)' >&2; \
		exit 1; \
	fi
	rm -rf $(SCAN_DIR)
	$(MAKE) --no-print-directory grype-db
	$(CONTAINER_ENGINE) image inspect --format '{{.Id}}' '$(SCAN_IMAGE)' > $(SCAN_DIR)/image-id.txt
	$(CONTAINER_ENGINE) run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges --network=none \
		--user 10001 --entrypoint /bin/cat '$(SCAN_IMAGE)' /etc/alpine-release > $(SCAN_DIR)/alpine-release.txt
	@if ! grep -Eqx '$(subst .,\.,$(ALPINE_MINOR))\.[0-9]+' $(SCAN_DIR)/alpine-release.txt; then \
		printf 'error: the image Alpine release does not match the pinned base image alpine:%s\n' '$(ALPINE_MINOR)' >&2; \
		exit 1; \
	fi
	$(GRYPE_RUN) '$(notdir $(CONTAINER_ENGINE)):$(SCAN_IMAGE)' --output json --file $(SCAN_DIR)/grype.json
	$(RUN) python -m tools.security.grype_gate \
		--report $(SCAN_DIR)/grype.json \
		--exceptions $(VULNERABILITY_EXCEPTIONS) \
		--summary $(SCAN_DIR)/summary.md \
		--grype-version $(GRYPE_VERSION) \
		--db-schema $(GRYPE_DB_SCHEMA) \
		--max-db-age-hours $(GRYPE_DB_MAX_AGE_HOURS) \
		--image-id "$$(cat $(SCAN_DIR)/image-id.txt)" \
		--expected-config $(GRYPE_EXPECTED_CONFIG) \
		--distro alpine \
		--distro-version "$$(cat $(SCAN_DIR)/alpine-release.txt)"

grype-expected-config:
	@if [ ! -f $(SCAN_DIR)/grype.json ]; then \
		printf 'error: run make image-scan first; %s is missing\n' '$(SCAN_DIR)/grype.json' >&2; \
		exit 1; \
	fi
	jq '.descriptor.configuration | .file = "" | .db["cache-dir"] = ""' $(SCAN_DIR)/grype.json > $(GRYPE_EXPECTED_CONFIG).tmp
	mv $(GRYPE_EXPECTED_CONFIG).tmp $(GRYPE_EXPECTED_CONFIG)
	@printf 'review the diff of %s before committing it\n' '$(GRYPE_EXPECTED_CONFIG)'

sbom:
	$(call NOT_IMPLEMENTED,sbom,FREES-37)

sign:
	$(call NOT_IMPLEMENTED,sign,FREES-37)

image-smoke: require-uv require-container-engine
	$(CONTAINER_ENGINE) build --file Containerfile --tag $(SMOKE_IMAGE) \
		--build-arg VCS_REF="$$(git rev-parse HEAD)" --build-arg BUILD_DATE=$(BUILD_DATE) .
	SMOKE_IMAGE=$(SMOKE_IMAGE) SMOKE_ENGINE=$(notdir $(CONTAINER_ENGINE)) $(RUN) pytest tests/smoke

docs: require-uv
	$(RUN) pre-commit run markdownlint-cli2 --all-files
	$(TRACKED) -- '*.md' | xargs -0 -r $(RUN) python tools/docs/check_links.py

release-check:
	$(call NOT_IMPLEMENTED,release-check,FREES-84)

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov build
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test-coverage security docs
