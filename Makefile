SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
RENOVATE_VERSION := 44.181.5
SMOKE_IMAGE := localhost/linux-compliance-runner:smoke
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
  image-scan            [pending FREES-37] Scan the image for vulnerabilities
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
	require-uv

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

image-scan:
	$(call NOT_IMPLEMENTED,image-scan,FREES-37)

sbom:
	$(call NOT_IMPLEMENTED,sbom,FREES-37)

sign:
	$(call NOT_IMPLEMENTED,sign,FREES-37)

image-smoke: require-uv
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		printf 'error: docker or podman is required to build the smoke test image\n' >&2; \
		exit 1; \
	fi
	$(CONTAINER_ENGINE) build --file Containerfile --tag $(SMOKE_IMAGE) \
		--build-arg VCS_REF="$$(git rev-parse HEAD)" --build-arg BUILD_DATE=$(BUILD_DATE) .
	SMOKE_IMAGE=$(SMOKE_IMAGE) SMOKE_ENGINE=$(notdir $(CONTAINER_ENGINE)) $(RUN) pytest tests/smoke

docs: require-uv
	$(RUN) pre-commit run markdownlint-cli2 --all-files
	$(TRACKED) -- '*.md' | xargs -0 -r $(RUN) python tools/docs/check_links.py

release-check:
	$(call NOT_IMPLEMENTED,release-check,FREES-84)

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test-coverage security docs
