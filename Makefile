SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
RENOVATE_PROJECT := tools/renovate
RENOVATE_DIR := build/tools/renovate
RENOVATE_VALIDATOR := $(RENOVATE_DIR)/node_modules/.bin/renovate-config-validator
NODE_MINIMUM_MAJOR := 24
NPM_MINIMUM_VERSION := 11.19.1
NPM_CI := npm ci --ignore-scripts --no-audit --no-fund --allow-git=none --allow-remote=none \
	--allow-file=none --allow-directory=none
NPM_LOCK_CHECK = $(RUN) python -m tools.security.npm_lock --manifest $(RENOVATE_PROJECT)/package.json \
	--lockfile $(RENOVATE_PROJECT)/package-lock.json
SMOKE_IMAGE := localhost/linux-compliance-runner:smoke
GRYPE_VERSION := 0.121.0
GRYPE_SHA256_LINUX_AMD64 := 64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
GRYPE_DB_SCHEMA := 6
GRYPE_DB_MAX_AGE_HOURS := 120
GRYPE_DB_URL := https://grype.anchore.io/databases/v$(GRYPE_DB_SCHEMA)
GRYPE_RELEASE_URL := https://github.com/anchore/grype/releases/download/v$(GRYPE_VERSION)
GRYPE_CHECKSUMS := grype_$(GRYPE_VERSION)_checksums.txt
GRYPE_SIGNER_IDENTITY := ^https://github\.com/anchore/grype/\.github/workflows/release\.yaml@refs/heads/main$$
GRYPE_SIGNER_REPOSITORY := anchore/grype
GRYPE_SIGNER_TRIGGER := workflow_dispatch
GRYPE_SIGNER_REF := refs/heads/main
SIGSTORE_OIDC_ISSUER := https://token.actions.githubusercontent.com
COSIGN_VERSION := 3.1.4
COSIGN_SHA256_LINUX_AMD64 := 424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
COSIGN_RELEASE_URL := https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)
COSIGN_DIR := build/tools/cosign-$(COSIGN_VERSION)
COSIGN := $(COSIGN_DIR)/cosign
SIGSTORE_TUF_DIR := build/sigstore-tuf
COSIGN_ENV_PASSTHROUGH := PATH HOME TMPDIR HTTPS_PROXY https_proxy NO_PROXY no_proxy
COSIGN_RUN = env -i $(foreach name,$(COSIGN_ENV_PASSTHROUGH),$(name)="$${$(name)-}") \
	TUF_ROOT='$(CURDIR)/$(SIGSTORE_TUF_DIR)' $(COSIGN)
SYFT_VERSION := 1.55.0
SYFT_SHA256_LINUX_AMD64 := bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
SYFT_RELEASE_URL := https://github.com/anchore/syft/releases/download/v$(SYFT_VERSION)
SYFT_CHECKSUMS := syft_$(SYFT_VERSION)_checksums.txt
SYFT_ARCHIVE := syft_$(SYFT_VERSION)_linux_amd64.tar.gz
SYFT_SIGNER_IDENTITY := ^https://github\.com/anchore/syft/\.github/workflows/release\.yaml@refs/heads/main$$
SYFT_SIGNER_REPOSITORY := anchore/syft
SYFT_DIR := build/tools/syft-$(SYFT_VERSION)
SYFT := $(SYFT_DIR)/syft
CRANE_VERSION := 0.22.1
CRANE_SHA256_LINUX_AMD64 := 0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0
CRANE_RELEASE_URL := https://github.com/google/go-containerregistry/releases/download/v$(CRANE_VERSION)
CRANE_ARCHIVE := go-containerregistry_Linux_x86_64.tar.gz
CRANE_DIR := build/tools/crane-$(CRANE_VERSION)
CRANE := $(CRANE_DIR)/crane
REGISTRY_ENV_PASSTHROUGH := PATH HOME TMPDIR DOCKER_CONFIG
SYFT_RUN = env -i $(foreach name,$(REGISTRY_ENV_PASSTHROUGH),$(name)="$${$(name)-}") \
	SYFT_CHECK_FOR_APP_UPDATE=false $(SYFT)
CRANE_RUN = env -i $(foreach name,$(REGISTRY_ENV_PASSTHROUGH),$(name)="$${$(name)-}") $(CRANE)
COSIGN_SIGN_ENV_PASSTHROUGH := $(COSIGN_ENV_PASSTHROUGH) DOCKER_CONFIG ACTIONS_ID_TOKEN_REQUEST_URL \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN
COSIGN_SIGN_RUN = env -i $(foreach name,$(COSIGN_SIGN_ENV_PASSTHROUGH),$(name)="$${$(name)-}") \
	TUF_ROOT='$(CURDIR)/$(SIGSTORE_TUF_DIR)' $(COSIGN)
BUILDAH_IMAGE := quay.io/buildah/stable
BUILDAH_TAG := v1.43.5-immutable
BUILDAH_DIGEST := sha256:7c2b605262748ace2c5c57c5550942d0adad57aec82ede3070927722306c0ffb
BUILDAH_REFERENCE := $(BUILDAH_IMAGE)@$(BUILDAH_DIGEST)
BUILDAH_VERSION := $(patsubst v%-immutable,%,$(BUILDAH_TAG))
BUILDAH_VOLUME := linux-compliance-runner-buildah
BUILDAH_SCRIPT := /opt/image-build/buildah.sh
BUILDAH_SECCOMP := tools/image/seccomp-buildah.json
BUILDAH_CAPABILITIES := CHOWN DAC_OVERRIDE FOWNER SETUID SETGID SYS_CHROOT
BUILDAH_RUN = $(CONTAINER_ENGINE) run --rm --cap-drop ALL $(foreach cap,$(BUILDAH_CAPABILITIES),--cap-add $(cap)) \
	--security-opt 'seccomp=$(CURDIR)/$(IMAGE_BUILD_DIR)/seccomp-buildah.json' --security-opt apparmor=unconfined \
	--volume '$(BUILDAH_VOLUME):/var/lib/image-build' \
	--volume '$(CURDIR)/$(IMAGE_BUILD_DIR)/buildah.sh:$(BUILDAH_SCRIPT):ro' \
	--env EXPECTED_BUILDAH_VERSION='$(BUILDAH_VERSION)' --env EXPECTED_COMMIT="$$(git rev-parse HEAD)"
RELEASE_REGISTRY := ghcr.io
RELEASE_REPOSITORY := $(RELEASE_REGISTRY)/freesecdev/linux-compliance-runner
RELEASE_SOURCE_REPOSITORY := FreeSecDev/linux-compliance-runner
RELEASE_WORKFLOW := $(RELEASE_SOURCE_REPOSITORY)/.github/workflows/image-build.yml
RELEASE_SIGNER_IDENTITY := https://github.com/$(RELEASE_WORKFLOW)@refs/heads/main
IMAGE_BUILD_DIR := build/image-build
IMAGE_BUILD_RECORD := $(IMAGE_BUILD_DIR)/build.json
IMAGE_ARCHIVE := $(IMAGE_BUILD_DIR)/image.tar
IMAGE_PUSH_DIR := build/image-push
IMAGE_PUSH_RECORD := $(IMAGE_PUSH_DIR)/push.json
IMAGE_BUILD_SOURCES := Containerfile Containerfile.dockerignore toolbox
LOCAL_BUILD_TAG := localhost/linux-compliance-runner:build
DOCKER_MANIFEST := application/vnd.docker.distribution.manifest.v2+json
SHA256_PATTERN := sha256:[0-9a-f]{64}
RELEASE_TAG_PATTERN := [0-9a-f]{40}-[0-9]+-[0-9]+
MISSING_MANIFEST_PATTERN := ^Error: .*(MANIFEST_UNKNOWN|NAME_UNKNOWN)
MISSING_PACKAGE_PATTERN := ^Error: GET https://ghcr\.io/token\?.*: DENIED:
CONFIG_MEMBER_PATTERN := [0-9a-f]{64}\.json
ifeq ($(origin ALLOW_MISSING_PACKAGE),command line)
MISSING_PACKAGE_ALLOWED := $(ALLOW_MISSING_PACKAGE)
else
MISSING_PACKAGE_ALLOWED :=
endif
EXPECTED_ARCHIVE_SHA256 ?=
EXPECTED_CONFIG_DIGEST ?=
export EXPECTED_ARCHIVE_SHA256 EXPECTED_CONFIG_DIGEST
REQUIRE_ARCHIVE_HASH = @if ! printf '%s\n' "$${EXPECTED_ARCHIVE_SHA256}" | grep -Eqx '[0-9a-f]{64}' || \
		! printf '%s\n' "$${EXPECTED_CONFIG_DIGEST}" | grep -Eqx '$(SHA256_PATTERN)'; then \
		printf 'error: EXPECTED_ARCHIVE_SHA256 (64 hex) and EXPECTED_CONFIG_DIGEST (sha256:<64 hex>) are required\n' >&2; \
		exit 2; \
	fi; \
	if ! printf '%s  %s\n' "$${EXPECTED_ARCHIVE_SHA256}" '$(IMAGE_ARCHIVE)' | sha256sum --check --strict --status -; then \
		printf 'error: %s is missing or does not match EXPECTED_ARCHIVE_SHA256\n' '$(IMAGE_ARCHIVE)' >&2; exit 1; \
	fi
REQUIRE_ARCHIVE = $(REQUIRE_ARCHIVE_HASH); \
	member="$${EXPECTED_CONFIG_DIGEST\#sha256:}.json"; \
	if ! tar -xOf '$(IMAGE_ARCHIVE)' -- manifest.json | \
		jq -e --arg member "$$member" 'length == 1 and .[0].Config == $$member' >/dev/null; then \
		printf 'error: manifest.json must name exactly one image whose config is %s\n' "$$member" >&2; exit 1; \
	fi; \
	if [ "sha256:$$(tar -xOf '$(IMAGE_ARCHIVE)' -- "$$member" | sha256sum | cut -d ' ' -f 1)" != "$${EXPECTED_CONFIG_DIGEST}" ]; then \
		printf 'error: the archived image config is not %s\n' "$${EXPECTED_CONFIG_DIGEST}" >&2; exit 1; \
	fi; \
	if [ "$$(tar -xOf '$(IMAGE_ARCHIVE)' -- "$$member" | jq -r '.config.Labels["org.opencontainers.image.revision"] // ""')" != \
		"$$(git rev-parse HEAD)" ]; then \
		printf 'error: the archived image revision label is not the checked-out commit\n' >&2; exit 1; \
	fi
IMAGE_RELEASE_DIR := build/image-release
SBOM_DIR := build/sbom
SPDX_PREDICATE := https://spdx.dev/Document/v2.3
SLSA_PREDICATE := https://slsa.dev/provenance/v1
SPDX_DESCRIBES_DIGEST := [.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and \
	.relationshipType == "DESCRIBES") | .relatedSpdxElement] as $$roots | ($$roots | length == 1) and \
	([.packages[] | select(.SPDXID == $$roots[0]) | [.versionInfo, (.checksums[]? | select(.algorithm == \
	"SHA256") | "sha256:" + .checksumValue)]] == [[$$digest, $$digest]])
DIGEST_REFERENCE_PATTERN := [a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}
IMAGE_REF ?=
RELEASE_TAG ?=
EXPECTED_COMMIT ?=
export IMAGE_REF RELEASE_TAG EXPECTED_COMMIT
VERIFY_COMMIT = $${EXPECTED_COMMIT:-$$(git rev-parse HEAD)}
REQUIRE_IMAGE_REF = @printf '%s\n' "$${IMAGE_REF}" | grep -Eqx '$(1)' || { \
	printf 'error: IMAGE_REF must be %s (a digest reference, never a tag)\n' '$(2)' >&2; exit 2; }
REQUIRE_EXPECTED_COMMIT = @head="$$(git rev-parse HEAD)"; \
	if [ -n "$${EXPECTED_COMMIT}" ] && [ "$${EXPECTED_COMMIT}" != "$$head" ]; then \
		printf 'error: the checkout is at %s, but EXPECTED_COMMIT is %s\n' "$$head" "$${EXPECTED_COMMIT}" >&2; exit 2; \
	fi
RELEASE_REFERENCE_PATTERN := $(subst .,\.,$(RELEASE_REPOSITORY))@sha256:[0-9a-f]{64}
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
SCAN_TARGET = $${IMAGE_REF:-$(SCAN_IMAGE)}
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
  lint-renovate         Lockfile pin check, npm ci --ignore-scripts of tools/renovate, then renovate-config-validator
  lint-container        hadolint on every Containerfile and a check that toolbox/uv.lock matches its pyproject
  lint-iac              [pending FREES-30] OpenTofu validation and Checkov

Security and types
  security              Bandit, gitleaks history scan and zizmor
  typecheck             mypy strict and Pyright strict

Tests
  test                  Alias for test-unit
  test-unit             Unit tests
  test-coverage         Unit tests with branch coverage thresholds

Image
  image-build           Build the archived HEAD commit with rootless Buildah in the pinned builder image and export
                        build/image-build/image.tar (no credentials)
  image-archive-check   Check build/image-build/image.tar against EXPECTED_ARCHIVE_SHA256, EXPECTED_CONFIG_DIGEST and HEAD
  image-push            Push the checked archive to GHCR as candidate-<commit>-<run>-<attempt> (workflow only)
  image-smoke-archive   Load the verified archive and run the smoke tests against it
  release-tag-absent    Fail unless RELEASE_TAG is proven absent from GHCR (any other registry error fails)
  image-pull            Pull IMAGE_REF (a name@sha256 digest) and check its digest and revision label
  image-smoke-pulled    Run the smoke tests against the pulled IMAGE_REF
  image-scan            Scan the local test image, or the registry digest IMAGE_REF, and apply the exception gate
  grype-expected-config Rewrite security/grype-expected-config.json from the last scan (after a Grype bump)
  sbom                  SPDX and CycloneDX SBOMs of the registry digest IMAGE_REF with the pinned Syft
  sbom-check            Check that build/sbom describes exactly the digest IMAGE_REF
  sign                  Sign the GHCR digest IMAGE_REF with cosign keyless (GitHub Actions OIDC only)
  verify-release        Verify the cosign signature and the provenance and SBOM attestations of IMAGE_REF
  image-release         Tag the verified GHCR digest IMAGE_REF as RELEASE_TAG (<commit>-<run>-<attempt>), never
                        moving or reusing a tag
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
	image-build image-push image-scan sbom sign image-smoke toolbox-lock-check docs release-check clean ci \
	require-uv require-container-engine require-image-workflow grype-db grype-expected-config lint-shell image-pull \
	image-smoke-pulled image-release verify-release print-release-repository image-smoke-archive \
	release-tag-absent sbom-check image-archive-check

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

lint: lint-repo lint-skills lint-python lint-yaml lint-actions lint-shell lint-container lint-renovate

lint-renovate: require-uv
	@node_major="$$(node --version 2>/dev/null | sed -e 's/^v//' -e 's/\..*//')"; \
	if [ -z "$$node_major" ] || [ "$$node_major" -lt $(NODE_MINIMUM_MAJOR) ]; then \
		printf 'error: lint-renovate needs Node.js %s or newer on PATH (found: %s); the pinned Renovate does not run on older versions\n' \
			'$(NODE_MINIMUM_MAJOR)' "$${node_major:-none}" >&2; \
		exit 1; \
	fi; \
	npm_version="$$(npm --version 2>/dev/null || true)"; \
	if [ -z "$$npm_version" ] || ! printf '%s\n' '$(NPM_MINIMUM_VERSION)' "$$npm_version" | sort --version-sort --check=quiet; then \
		printf 'error: lint-renovate needs npm %s or newer on PATH (found: %s) for the npm ci source restrictions\n' \
			'$(NPM_MINIMUM_VERSION)' "$${npm_version:-none}" >&2; \
		exit 1; \
	fi
	$(NPM_LOCK_CHECK)
	rm -rf $(RENOVATE_DIR)
	mkdir -p $(RENOVATE_DIR)
	cp $(RENOVATE_PROJECT)/package.json $(RENOVATE_PROJECT)/package-lock.json $(RENOVATE_PROJECT)/.npmrc $(RENOVATE_DIR)/
	cd $(RENOVATE_DIR) && $(NPM_CI)
	$(NPM_LOCK_CHECK) --installed $(RENOVATE_DIR)/node_modules/.package-lock.json
	RENOVATE_X_IGNORE_RE2=true $(RENOVATE_VALIDATOR) --strict --no-global .renovaterc.json

lint-python: require-uv
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) pylint tools tests

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-shell: require-uv
	$(TRACKED) -- '*.sh' | xargs -0 -r $(RUN) shellcheck

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

image-build: require-container-engine
	$(REQUIRE_EXPECTED_COMMIT)
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the release image is built for linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(IMAGE_BUILD_DIR)
	mkdir -p $(IMAGE_BUILD_DIR)/source
	git archive --format=tar HEAD -- $(IMAGE_BUILD_SOURCES) | tar -x -C $(IMAGE_BUILD_DIR)/source
	git show HEAD:tools/image/buildah.sh > $(IMAGE_BUILD_DIR)/buildah.sh
	git show HEAD:$(BUILDAH_SECCOMP) > $(IMAGE_BUILD_DIR)/seccomp-buildah.json
	$(CONTAINER_ENGINE) pull --quiet '$(BUILDAH_REFERENCE)'
	$(CONTAINER_ENGINE) volume rm --force '$(BUILDAH_VOLUME)' >/dev/null
	$(CONTAINER_ENGINE) volume create '$(BUILDAH_VOLUME)' >/dev/null
	$(BUILDAH_RUN) --env BUILD_DATE='$(BUILD_DATE)' --volume '$(CURDIR)/$(IMAGE_BUILD_DIR)/source:/source:ro' \
		'$(BUILDAH_REFERENCE)' bash '$(BUILDAH_SCRIPT)' build
	$(BUILDAH_RUN) '$(BUILDAH_REFERENCE)' bash '$(BUILDAH_SCRIPT)' export > $(IMAGE_ARCHIVE)
	$(CONTAINER_ENGINE) volume rm --force '$(BUILDAH_VOLUME)' >/dev/null
	@commit="$$(git rev-parse HEAD)"; \
	config="$$(tar -xOf '$(IMAGE_ARCHIVE)' -- manifest.json | jq -er 'if length == 1 then .[0].Config else error("not one image") end')"; \
	if ! printf '%s\n' "$$config" | grep -Eqx '$(CONFIG_MEMBER_PATTERN)'; then \
		printf 'error: the exported archive names an unexpected config member\n' >&2; exit 1; \
	fi; \
	digest="sha256:$$(tar -xOf '$(IMAGE_ARCHIVE)' -- "$$config" | sha256sum | cut -d ' ' -f 1)"; \
	if [ "$$digest.json" != "sha256:$$config" ]; then \
		printf 'error: the exported config member is not named after its digest\n' >&2; exit 1; \
	fi; \
	built="$$(tar -xOf '$(IMAGE_ARCHIVE)' -- "$$config" | jq -r '.config.Labels["org.opencontainers.image.revision"] // ""')"; \
	if [ "$$built" != "$$commit" ]; then \
		printf 'error: the archived image carries revision %s, expected %s\n' "$$built" "$$commit" >&2; exit 1; \
	fi; \
	archive="$$(sha256sum '$(IMAGE_ARCHIVE)' | cut -d ' ' -f 1)"; \
	jq -n --arg commit "$$commit" --arg built_commit "$$built" --arg config_digest "$$digest" \
		--arg archive_sha256 "$$archive" --arg builder_image '$(BUILDAH_REFERENCE)' \
		--arg buildah_version '$(BUILDAH_VERSION)' --arg build_date '$(BUILD_DATE)' \
		'$$ARGS.named' > $(IMAGE_BUILD_RECORD); \
	printf 'built %s: config %s, archive sha256 %s\n' "$$commit" "$$digest" "$$archive"

release-tag-absent: $(CRANE)
	@printf '%s\n' "$${RELEASE_TAG}" | grep -Eqx '$(RELEASE_TAG_PATTERN)' || { \
		printf 'error: RELEASE_TAG must be <commit>-<run number>-<run attempt>\n' >&2; exit 2; }
	@mkdir -p build
	@if $(CRANE_RUN) digest "$(RELEASE_REPOSITORY):$${RELEASE_TAG}" > build/release-tag-check.txt 2>&1; then \
		printf 'error: %s already exists; a release tag is never moved or reused\n' "$(RELEASE_REPOSITORY):$${RELEASE_TAG}" >&2; \
		exit 1; \
	elif grep -Eq '$(MISSING_MANIFEST_PATTERN)' build/release-tag-check.txt; then \
		printf '%s does not exist yet\n' "$(RELEASE_REPOSITORY):$${RELEASE_TAG}"; \
	elif [ "$(MISSING_PACKAGE_ALLOWED)" = 1 ] && grep -Eq '$(MISSING_PACKAGE_PATTERN)' build/release-tag-check.txt; then \
		printf '%s: no access before the first push; the package does not exist yet or the push fails next\n' \
			"$(RELEASE_REPOSITORY)"; \
	else \
		cat build/release-tag-check.txt >&2; \
		printf 'error: could not prove that %s is absent; refusing to continue\n' "$(RELEASE_REPOSITORY):$${RELEASE_TAG}" >&2; \
		exit 1; \
	fi

image-archive-check:
	$(REQUIRE_EXPECTED_COMMIT)
	$(REQUIRE_ARCHIVE)
	@printf 'archive %s holds the config %s of %s\n' '$(IMAGE_ARCHIVE)' "$${EXPECTED_CONFIG_DIGEST}" "$$(git rev-parse HEAD)"

image-push: require-image-workflow $(CRANE)
	$(REQUIRE_EXPECTED_COMMIT)
	$(REQUIRE_ARCHIVE_HASH)
	@for name in GITHUB_RUN_NUMBER GITHUB_RUN_ATTEMPT; do \
		printf '%s\n' "$${!name-}" | grep -Eqx '[0-9]+' || { printf 'error: %s is missing\n' "$$name" >&2; exit 2; }; \
	done
	@release="$$(git rev-parse HEAD)-$${GITHUB_RUN_NUMBER}-$${GITHUB_RUN_ATTEMPT}"; \
	$(MAKE) --no-print-directory release-tag-absent RELEASE_TAG="$$release" ALLOW_MISSING_PACKAGE=1
	@commit="$$(git rev-parse HEAD)"; \
	release="$$commit-$${GITHUB_RUN_NUMBER}-$${GITHUB_RUN_ATTEMPT}"; \
	candidate='$(RELEASE_REPOSITORY)'":candidate-$$release"; \
	$(CRANE_RUN) push '$(IMAGE_ARCHIVE)' "$$candidate" >/dev/null; \
	digest="$$($(CRANE_RUN) digest "$$candidate")"; \
	if ! printf '%s\n' "$$digest" | grep -Eqx '$(SHA256_PATTERN)'; then \
		printf 'error: GHCR reported no digest for %s\n' "$$candidate" >&2; exit 1; \
	fi; \
	reference='$(RELEASE_REPOSITORY)'"@$$digest"; \
	served="sha256:$$($(CRANE_RUN) manifest "$$reference" | sha256sum | cut -d ' ' -f 1)"; \
	media="$$($(CRANE_RUN) manifest "$$reference" | jq -r '.mediaType')"; \
	config="$$($(CRANE_RUN) manifest "$$reference" | jq -r '.config.digest')"; \
	built="$$($(CRANE_RUN) config "$$reference" | jq -r '.config.Labels["org.opencontainers.image.revision"] // ""')"; \
	if [ "$$served" != "$$digest" ]; then \
		printf 'error: GHCR serves %s for %s\n' "$$served" "$$reference" >&2; exit 1; \
	fi; \
	if [ "$$media" != '$(DOCKER_MANIFEST)' ]; then \
		printf 'error: the pushed manifest is %s, not a single Docker v2 image manifest\n' "$$media" >&2; exit 1; \
	fi; \
	if [ "$$config" != "$${EXPECTED_CONFIG_DIGEST}" ]; then \
		printf 'error: the pushed image config is %s, the build recorded %s\n' "$$config" "$${EXPECTED_CONFIG_DIGEST}" >&2; \
		exit 1; \
	fi; \
	if [ "$$built" != "$$commit" ]; then \
		printf 'error: the pushed image carries revision %s, expected %s\n' "$$built" "$$commit" >&2; exit 1; \
	fi; \
	mkdir -p $(IMAGE_PUSH_DIR); \
	jq -n --arg commit "$$commit" --arg built_commit "$$built" --arg digest "$$digest" --arg reference "$$reference" \
		--arg name '$(RELEASE_REPOSITORY)' --arg candidate "$$candidate" --arg release_tag "$$release" \
		--arg config_digest "$$config" \
		'$$ARGS.named' > $(IMAGE_PUSH_RECORD); \
	printf 'pushed %s as %s (config %s, revision %s)\n' "$$candidate" "$$reference" "$$config" "$$built"

image-smoke-archive: require-uv require-container-engine
	$(REQUIRE_EXPECTED_COMMIT)
	$(REQUIRE_ARCHIVE)
	$(CONTAINER_ENGINE) image rm --force '$(LOCAL_BUILD_TAG)' >/dev/null 2>&1 || true
	$(CONTAINER_ENGINE) load --quiet --input '$(IMAGE_ARCHIVE)'
	@revision="$$($(CONTAINER_ENGINE) image inspect \
		--format '{{index .Config.Labels "org.opencontainers.image.revision"}}' '$(LOCAL_BUILD_TAG)')"; \
	if [ "$$revision" != "$$(git rev-parse HEAD)" ]; then \
		printf 'error: the loaded image revision label %s is not the checked-out commit\n' "$$revision" >&2; exit 1; \
	fi
	SMOKE_IMAGE='$(LOCAL_BUILD_TAG)' SMOKE_ENGINE=$(notdir $(CONTAINER_ENGINE)) $(RUN) pytest tests/smoke \
		-k 'not test_build_rejects_a_build_date_that_is_not_rfc_3339'

print-release-repository:
	@printf '%s\n' '$(RELEASE_REPOSITORY)'

image-pull: require-container-engine
	$(call REQUIRE_IMAGE_REF,$(DIGEST_REFERENCE_PATTERN),name@sha256:<digest>)
	$(REQUIRE_EXPECTED_COMMIT)
	$(CONTAINER_ENGINE) pull --quiet "$${IMAGE_REF}"
	$(CONTAINER_ENGINE) image inspect --format '{{json .RepoDigests}}' "$${IMAGE_REF}" | \
		jq -e --arg reference "$${IMAGE_REF}" 'index($$reference) != null' >/dev/null
	@revision="$$($(CONTAINER_ENGINE) image inspect \
		--format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$${IMAGE_REF}")"; \
	if [ "$$revision" != "$$(git rev-parse HEAD)" ]; then \
		printf 'error: the image revision label %s is not the checked-out commit\n' "$$revision" >&2; \
		exit 1; \
	fi; \
	printf 'pulled %s, revision %s\n' "$${IMAGE_REF}" "$$revision"

image-smoke-pulled: require-uv require-container-engine
	$(call REQUIRE_IMAGE_REF,$(DIGEST_REFERENCE_PATTERN),name@sha256:<digest>)
	SMOKE_IMAGE="$${IMAGE_REF}" SMOKE_ENGINE=$(notdir $(CONTAINER_ENGINE)) $(RUN) pytest tests/smoke \
		-k 'not test_build_rejects_a_build_date_that_is_not_rfc_3339'

require-image-workflow:
	@if [ "$${GITHUB_ACTIONS-}" != true ] || [ "$${GITHUB_REF-}" != refs/heads/main ] || \
		[ "$${GITHUB_WORKFLOW_REF-}" != '$(RELEASE_WORKFLOW)@refs/heads/main' ]; then \
		printf 'error: %s runs only in the image-build workflow on main\n' '$(MAKECMDGOALS)' >&2; exit 2; \
	fi

require-container-engine:
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		printf 'error: docker or podman is required for the image targets\n' >&2; \
		exit 1; \
	fi

$(COSIGN):
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the pinned cosign download is linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(COSIGN_DIR).download
	mkdir -p $(COSIGN_DIR).download
	$(CURL) --max-time 120 --output $(COSIGN_DIR).download/cosign_checksums.txt $(COSIGN_RELEASE_URL)/cosign_checksums.txt
	$(CURL) --max-time 600 --output $(COSIGN_DIR).download/cosign-linux-amd64 $(COSIGN_RELEASE_URL)/cosign-linux-amd64
	@if ! grep -Fqx '$(COSIGN_SHA256_LINUX_AMD64)  cosign-linux-amd64' $(COSIGN_DIR).download/cosign_checksums.txt; then \
		printf 'error: the pinned cosign checksum is not in the release checksums file\n' >&2; \
		exit 1; \
	fi
	cd $(COSIGN_DIR).download && \
		printf '%s  %s\n' '$(COSIGN_SHA256_LINUX_AMD64)' cosign-linux-amd64 | sha256sum --check --strict -
	chmod 0755 $(COSIGN_DIR).download/cosign-linux-amd64
	test "$$($(COSIGN_DIR).download/cosign-linux-amd64 version --json | jq -r .gitVersion)" = 'v$(COSIGN_VERSION)'
	install -D -m 0755 $(COSIGN_DIR).download/cosign-linux-amd64 $(COSIGN)
	rm -rf $(COSIGN_DIR).download

$(GRYPE): | $(COSIGN)
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the pinned Grype download is linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(GRYPE_DIR).download
	mkdir -p $(GRYPE_DIR).download $(SIGSTORE_TUF_DIR)
	$(CURL) --max-time 120 --output $(GRYPE_DIR).download/checksums.txt $(GRYPE_RELEASE_URL)/$(GRYPE_CHECKSUMS)
	$(CURL) --max-time 120 --output $(GRYPE_DIR).download/checksums.txt.sigstore.json \
		$(GRYPE_RELEASE_URL)/$(GRYPE_CHECKSUMS).sigstore.json
	$(COSIGN_RUN) verify-blob \
		--bundle $(GRYPE_DIR).download/checksums.txt.sigstore.json \
		--certificate-identity-regexp '$(GRYPE_SIGNER_IDENTITY)' \
		--certificate-oidc-issuer '$(SIGSTORE_OIDC_ISSUER)' \
		--certificate-github-workflow-repository '$(GRYPE_SIGNER_REPOSITORY)' \
		--certificate-github-workflow-trigger '$(GRYPE_SIGNER_TRIGGER)' \
		--certificate-github-workflow-ref '$(GRYPE_SIGNER_REF)' \
		$(GRYPE_DIR).download/checksums.txt
	@if ! grep -Fqx '$(GRYPE_SHA256_LINUX_AMD64)  $(GRYPE_ARCHIVE)' $(GRYPE_DIR).download/checksums.txt; then \
		printf 'error: the pinned Grype checksum is not in the signed release checksums file\n' >&2; \
		exit 1; \
	fi
	$(CURL) --max-time 600 --output $(GRYPE_DIR).download/$(GRYPE_ARCHIVE) $(GRYPE_RELEASE_URL)/$(GRYPE_ARCHIVE)
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
	@if [ -n "$${IMAGE_REF}" ] && ! printf '%s\n' "$${IMAGE_REF}" | grep -Eqx '$(DIGEST_REFERENCE_PATTERN)'; then \
		printf 'error: IMAGE_REF must be a name@sha256:<digest> reference, never a tag\n' >&2; \
		exit 2; \
	fi
	@if ! $(CONTAINER_ENGINE) image inspect "$(SCAN_TARGET)" >/dev/null 2>&1; then \
		printf 'error: image %s not found; run make image-smoke (or make image-pull IMAGE_REF=...) first\n' \
			"$(SCAN_TARGET)" >&2; \
		exit 1; \
	fi
	rm -rf $(SCAN_DIR)
	$(MAKE) --no-print-directory grype-db
	if [ -n "$${IMAGE_REF}" ]; then printf '%s\n' "$${IMAGE_REF##*@}"; \
	else $(CONTAINER_ENGINE) image inspect --format '{{.Id}}' '$(SCAN_IMAGE)'; fi > $(SCAN_DIR)/image-id.txt
	$(CONTAINER_ENGINE) run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges --network=none \
		--user 10001 --entrypoint /bin/cat "$(SCAN_TARGET)" /etc/alpine-release > $(SCAN_DIR)/alpine-release.txt
	@if ! grep -Eqx '$(subst .,\.,$(ALPINE_MINOR))\.[0-9]+' $(SCAN_DIR)/alpine-release.txt; then \
		printf 'error: the image Alpine release does not match the pinned base image alpine:%s\n' '$(ALPINE_MINOR)' >&2; \
		exit 1; \
	fi
	if [ -n "$${IMAGE_REF}" ]; then source="registry:$${IMAGE_REF}"; \
	else source='$(notdir $(CONTAINER_ENGINE)):$(SCAN_IMAGE)'; fi; \
	$(GRYPE_RUN) "$$source" --output json --file $(SCAN_DIR)/grype.json
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
		--distro-version "$$(cat $(SCAN_DIR)/alpine-release.txt)" \
		$${IMAGE_REF:+--image-reference "$${IMAGE_REF}"}

grype-expected-config:
	@if [ ! -f $(SCAN_DIR)/grype.json ]; then \
		printf 'error: run make image-scan first; %s is missing\n' '$(SCAN_DIR)/grype.json' >&2; \
		exit 1; \
	fi
	jq '.descriptor.configuration | .file = "" | .db["cache-dir"] = ""' $(SCAN_DIR)/grype.json > $(GRYPE_EXPECTED_CONFIG).tmp
	mv $(GRYPE_EXPECTED_CONFIG).tmp $(GRYPE_EXPECTED_CONFIG)
	@printf 'review the diff of %s before committing it\n' '$(GRYPE_EXPECTED_CONFIG)'

$(SYFT): | $(COSIGN)
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the pinned Syft download is linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(SYFT_DIR).download
	mkdir -p $(SYFT_DIR).download $(SIGSTORE_TUF_DIR)
	$(CURL) --max-time 120 --output $(SYFT_DIR).download/checksums.txt $(SYFT_RELEASE_URL)/$(SYFT_CHECKSUMS)
	$(CURL) --max-time 120 --output $(SYFT_DIR).download/checksums.txt.sigstore.json \
		$(SYFT_RELEASE_URL)/$(SYFT_CHECKSUMS).sigstore.json
	$(COSIGN_RUN) verify-blob \
		--bundle $(SYFT_DIR).download/checksums.txt.sigstore.json \
		--certificate-identity-regexp '$(SYFT_SIGNER_IDENTITY)' \
		--certificate-oidc-issuer '$(SIGSTORE_OIDC_ISSUER)' \
		--certificate-github-workflow-repository '$(SYFT_SIGNER_REPOSITORY)' \
		--certificate-github-workflow-trigger '$(GRYPE_SIGNER_TRIGGER)' \
		--certificate-github-workflow-ref '$(GRYPE_SIGNER_REF)' \
		$(SYFT_DIR).download/checksums.txt
	@if ! grep -Fqx '$(SYFT_SHA256_LINUX_AMD64)  $(SYFT_ARCHIVE)' $(SYFT_DIR).download/checksums.txt; then \
		printf 'error: the pinned Syft checksum is not in the signed release checksums file\n' >&2; \
		exit 1; \
	fi
	$(CURL) --max-time 600 --output $(SYFT_DIR).download/$(SYFT_ARCHIVE) $(SYFT_RELEASE_URL)/$(SYFT_ARCHIVE)
	cd $(SYFT_DIR).download && \
		printf '%s  %s\n' '$(SYFT_SHA256_LINUX_AMD64)' '$(SYFT_ARCHIVE)' | sha256sum --check --strict - && \
		tar -xzf $(SYFT_ARCHIVE) syft
	test "$$($(SYFT_DIR).download/syft version -o json | jq -r .version)" = '$(SYFT_VERSION)'
	install -D -m 0755 $(SYFT_DIR).download/syft $(SYFT)
	rm -rf $(SYFT_DIR).download

$(CRANE):
	@if [ "$$(uname -s)/$$(uname -m)" != Linux/x86_64 ]; then \
		printf 'error: the pinned crane download is linux/amd64 only\n' >&2; \
		exit 1; \
	fi
	rm -rf $(CRANE_DIR).download
	mkdir -p $(CRANE_DIR).download
	$(CURL) --max-time 120 --output $(CRANE_DIR).download/checksums.txt $(CRANE_RELEASE_URL)/checksums.txt
	@if ! grep -Fqx '$(CRANE_SHA256_LINUX_AMD64)  $(CRANE_ARCHIVE)' $(CRANE_DIR).download/checksums.txt; then \
		printf 'error: the pinned crane checksum is not in the release checksums file\n' >&2; \
		exit 1; \
	fi
	$(CURL) --max-time 600 --output $(CRANE_DIR).download/$(CRANE_ARCHIVE) $(CRANE_RELEASE_URL)/$(CRANE_ARCHIVE)
	cd $(CRANE_DIR).download && \
		printf '%s  %s\n' '$(CRANE_SHA256_LINUX_AMD64)' '$(CRANE_ARCHIVE)' | sha256sum --check --strict - && \
		tar -xzf $(CRANE_ARCHIVE) crane
	test "$$($(CRANE_DIR).download/crane version)" = '$(CRANE_VERSION)'
	install -D -m 0755 $(CRANE_DIR).download/crane $(CRANE)
	rm -rf $(CRANE_DIR).download

sbom: $(SYFT)
	$(call REQUIRE_IMAGE_REF,$(DIGEST_REFERENCE_PATTERN),name@sha256:<digest>)
	rm -rf $(SBOM_DIR)
	mkdir -p $(SBOM_DIR)
	$(SYFT_RUN) scan "registry:$${IMAGE_REF}" --quiet \
		--output spdx-json=$(SBOM_DIR)/sbom.spdx.json --output cyclonedx-json=$(SBOM_DIR)/sbom.cdx.json
	$(MAKE) --no-print-directory sbom-check

sbom-check:
	$(call REQUIRE_IMAGE_REF,$(DIGEST_REFERENCE_PATTERN),name@sha256:<digest>)
	jq -e --arg digest "$${IMAGE_REF##*@}" '$(SPDX_DESCRIBES_DIGEST)' $(SBOM_DIR)/sbom.spdx.json >/dev/null || { \
		printf 'error: the SPDX SBOM does not describe %s\n' "$${IMAGE_REF}" >&2; exit 1; }
	jq -e --arg digest "$${IMAGE_REF##*@}" '.metadata.component.version == $$digest' \
		$(SBOM_DIR)/sbom.cdx.json >/dev/null || { \
		printf 'error: the CycloneDX SBOM does not describe %s\n' "$${IMAGE_REF}" >&2; exit 1; }
	@printf 'SBOM of %s: %s packages\n' "$${IMAGE_REF}" "$$(jq '.packages | length' $(SBOM_DIR)/sbom.spdx.json)"

image-release: require-image-workflow $(CRANE)
	$(call REQUIRE_IMAGE_REF,$(RELEASE_REFERENCE_PATTERN),$(RELEASE_REPOSITORY)@sha256:<digest>)
	@printf '%s\n' "$${RELEASE_TAG}" | grep -Eqx "$$(git rev-parse HEAD)-[0-9]+-[0-9]+" || { \
		printf 'error: RELEASE_TAG must be <checked-out commit>-<run number>-<run attempt>\n' >&2; exit 2; }
	@if [ "$$(cat $(IMAGE_RELEASE_DIR)/verified.txt 2>/dev/null)" != "$${IMAGE_REF}" ]; then \
		printf 'error: run make verify-release for IMAGE_REF first\n' >&2; exit 1; \
	fi
	$(MAKE) --no-print-directory release-tag-absent
	$(CRANE_RUN) tag "$${IMAGE_REF}" "$${RELEASE_TAG}"
	@digest="$${IMAGE_REF##*@}"; \
	tagged="$$($(CRANE_RUN) digest "$(RELEASE_REPOSITORY):$${RELEASE_TAG}")"; \
	if [ "$$tagged" != "$$digest" ]; then \
		printf 'error: %s resolves to %s, expected %s\n' "$(RELEASE_REPOSITORY):$${RELEASE_TAG}" "$$tagged" "$$digest" >&2; \
		exit 1; \
	fi; \
	jq -n --arg release "$${IMAGE_REF}" --arg digest "$$digest" --arg tag "$(RELEASE_REPOSITORY):$${RELEASE_TAG}" \
		--arg commit "$$(git rev-parse HEAD)" '{commit: $$commit, digest: $$digest, release: $$release, tag: $$tag}' \
		> $(IMAGE_RELEASE_DIR)/image.json; \
	printf 'released %s as %s\n' "$${IMAGE_REF}" "$(RELEASE_REPOSITORY):$${RELEASE_TAG}"

sign: $(COSIGN)
	$(call REQUIRE_IMAGE_REF,$(RELEASE_REFERENCE_PATTERN),$(RELEASE_REPOSITORY)@sha256:<digest>)
	@if [ -z "$${ACTIONS_ID_TOKEN_REQUEST_URL-}" ]; then \
		printf 'error: sign runs only in the image-build workflow (GitHub Actions OIDC keyless signing)\n' >&2; \
		exit 2; \
	fi
	mkdir -p $(SIGSTORE_TUF_DIR)
	$(COSIGN_SIGN_RUN) sign --yes "$${IMAGE_REF}"

verify-release: $(COSIGN)
	$(call REQUIRE_IMAGE_REF,$(RELEASE_REFERENCE_PATTERN),$(RELEASE_REPOSITORY)@sha256:<digest>)
	mkdir -p $(IMAGE_RELEASE_DIR) $(SIGSTORE_TUF_DIR)
	rm -f $(IMAGE_RELEASE_DIR)/verified.txt
	gh --version | head -n 1 > $(IMAGE_RELEASE_DIR)/gh-version.txt
	env -i $(foreach name,$(COSIGN_ENV_PASSTHROUGH) DOCKER_CONFIG,$(name)="$${$(name)-}") \
		TUF_ROOT='$(CURDIR)/$(SIGSTORE_TUF_DIR)' $(COSIGN) verify \
		--certificate-identity '$(RELEASE_SIGNER_IDENTITY)' \
		--certificate-oidc-issuer '$(SIGSTORE_OIDC_ISSUER)' \
		--certificate-github-workflow-repository '$(RELEASE_SOURCE_REPOSITORY)' \
		--certificate-github-workflow-ref refs/heads/main \
		--certificate-github-workflow-sha "$(VERIFY_COMMIT)" \
		"$${IMAGE_REF}" > $(IMAGE_RELEASE_DIR)/cosign-verify.json
	gh attestation verify "oci://$${IMAGE_REF}" --repo '$(RELEASE_SOURCE_REPOSITORY)' \
		--signer-workflow '$(RELEASE_WORKFLOW)@refs/heads/main' --signer-digest "$(VERIFY_COMMIT)" \
		--predicate-type '$(SLSA_PREDICATE)' \
		--source-ref refs/heads/main --source-digest "$(VERIFY_COMMIT)" --deny-self-hosted-runners \
		--format json > $(IMAGE_RELEASE_DIR)/provenance-verify.json
	gh attestation verify "oci://$${IMAGE_REF}" --repo '$(RELEASE_SOURCE_REPOSITORY)' \
		--signer-workflow '$(RELEASE_WORKFLOW)@refs/heads/main' --signer-digest "$(VERIFY_COMMIT)" \
		--predicate-type '$(SPDX_PREDICATE)' \
		--source-ref refs/heads/main --source-digest "$(VERIFY_COMMIT)" --deny-self-hosted-runners \
		--format json > $(IMAGE_RELEASE_DIR)/sbom-verify.json
	printf '%s\n' "$${IMAGE_REF}" > $(IMAGE_RELEASE_DIR)/verified.txt
	@printf 'verified the signature, provenance and SBOM attestations of %s with %s\n' "$${IMAGE_REF}" \
		"$$(cat $(IMAGE_RELEASE_DIR)/gh-version.txt)"

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
