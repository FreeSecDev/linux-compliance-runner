SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
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
  lint-container        hadolint on every Containerfile; reports and skips while none exists
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
  image-smoke           [pending FREES-38] Smoke test the image

Docs and release
  docs                  markdownlint and relative link check
  release-check         [pending FREES-84] Verify release readiness

Housekeeping
  clean                 Remove caches and generated files
  ci                    Run the credential-free CI stages locally
endef
export HELP_TEXT

.PHONY: help bootstrap install format lint lint-python lint-yaml lint-actions lint-repo \
	lint-skills lint-container lint-iac security typecheck test test-unit test-coverage \
	aws-bootstrap image-build image-scan sbom sign image-smoke docs release-check clean ci \
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

lint: lint-repo lint-skills lint-python lint-yaml lint-actions lint-container

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

lint-container: require-uv
	@containerfiles="$$(git ls-files --cached --others --exclude-standard -- 'Containerfile' '*/Containerfile')"; \
	if [ -z "$$containerfiles" ]; then \
		printf 'lint-container: no Containerfile in the repository yet, nothing to lint (Containerfile tracked in FREES-35)\n'; \
	else \
		printf '%s\n' "$$containerfiles" | xargs $(RUN) hadolint; \
	fi

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

image-smoke:
	$(call NOT_IMPLEMENTED,image-smoke,FREES-38)

docs: require-uv
	$(RUN) pre-commit run markdownlint-cli2 --all-files
	$(TRACKED) -- '*.md' | xargs -0 -r $(RUN) python tools/docs/check_links.py

release-check:
	$(call NOT_IMPLEMENTED,release-check,FREES-84)

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test-coverage security docs
