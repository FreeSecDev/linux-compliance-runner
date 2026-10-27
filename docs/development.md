# Development guide

The `Makefile` is the single entry point for developers and CI. `make ci` runs every implemented,
credential-free stage locally and is what the pull request workflow runs, split into jobs.

Jira: FREES-35 and FREES-38 (Containerfile and smoke tests), FREES-37 and FREES-135 (Grype gate), FREES-133 (Renovate validator lockfile), FREES-68 (Makefile), FREES-69 (pre-commit), FREES-70 (Python tooling),
FREES-71 (pull request workflow), FREES-22 (community files), FREES-81 (dependency configuration),
FREES-29 (branch protection). The same foundation exists in the collection repository, which is the reference.

## Bootstrap

Requirements: `git`, GNU `make` and [`uv`](https://docs.astral.sh/uv/). Python 3.12 is selected by
`.python-version` and installed by `uv` when missing.

```text
make bootstrap
make help
```

`make bootstrap` runs `uv sync --frozen` (exact versions from `uv.lock`), installs the `pre-commit` and
`pre-push` git hooks and prints tool versions. A missing `uv` produces an error with install instructions.
OpenTofu checks join `make bootstrap` with FREES-30. hadolint is installed by `uv sync` from the `hadolint-bin`
PyPI package, so no separate install is needed.

## Makefile targets

| Target | Status | What it does |
|---|---|---|
| `help` | implemented | Prints this target list |
| `bootstrap` | implemented | `install` plus tool version check |
| `install` | implemented | `uv sync --frozen`, installs both git hook types |
| `format` | implemented | `ruff check --fix` and `ruff format` |
| `lint` | implemented | `lint-repo`, `lint-skills`, `lint-python`, `lint-yaml`, `lint-actions`, `lint-shell`, `lint-container`, `lint-renovate` |
| `lint-shell` | implemented | ShellCheck on every tracked `*.sh` (the in-container build script `tools/image/buildah.sh`) |
| `lint-python` | implemented | Ruff lint, Ruff format check, Pylint |
| `lint-yaml` | implemented | `yamllint --strict` |
| `lint-actions` | implemented | actionlint |
| `lint-repo` | implemented | `tools/lint/check_repo_rules.py` on tracked and new YAML and Python files |
| `lint-skills` | implemented | `tools/skills/validate_skills.py` with the skills this repository carries as required and the collection-only skills passed as `--external` |
| `security` | implemented | Bandit, gitleaks history scan, zizmor (pedantic persona) |
| `typecheck` | implemented | mypy strict, Pyright strict |
| `test` | implemented | Alias for `test-unit` |
| `test-unit` | implemented | `pytest tests/unit` |
| `test-coverage` | implemented | Unit tests with branch coverage, 95% overall, 100% on `tools/` |
| `docs` | implemented | markdownlint-cli2 and the relative link checker |
| `clean` | implemented | Removes caches, coverage output and `build/` (the Renovate tree, the cosign, Grype, Syft and crane binaries, the Sigstore trust root cache, the database, scan reports, SBOMs and build records) |
| `ci` | implemented | `lint typecheck test-coverage security docs` |
| `lint-renovate` | implemented | Checks that `tools/renovate/package-lock.json` pins every package (`tools/security/npm_lock.py`), installs it into `build/tools/renovate/` with `npm ci --ignore-scripts`, checks the installed tree against the lockfile, then runs `renovate-config-validator --strict --no-global`; needs Node.js 24 and npm 11.19.1 or newer (CI installs Node.js 24.22.1 with `actions/setup-node`). See [`dependency-management.md`](dependency-management.md#renovate-validator-tree) |
| `lint-container` | implemented | `toolbox-lock-check` (`uv lock --check` for `toolbox/`) and hadolint on every `Containerfile` with `.hadolint.yaml` (no ignores) |
| `toolbox-lock-check` | implemented | Fails when `toolbox/uv.lock` does not match `toolbox/pyproject.toml` |
| `lint-iac` | pending FREES-30 | OpenTofu validation and Checkov |
| `image-build` | implemented | Builds a `git archive` of `HEAD` with rootless Buildah in the digest-pinned `quay.io/buildah/stable` image (capabilities cut to six, the checked-in seccomp profile `tools/image/seccomp-buildah.json`, native overlay; no credentials, works locally), exports `build/image-build/image.tar` and records its hash and config digest in `build/image-build/build.json`; refuses a checkout that is not `EXPECTED_COMMIT`. See [`image-build.md`](image-build.md) |
| `image-push` | implemented | In the `image-build` workflow on `main` only, after `image-archive-check`: re-checks the archive hash, proves the release tag absent, pushes it to GHCR as `candidate-<commit>-<run>-<attempt>`, checks the served digest, media type, config digest and revision label, and writes `build/image-push/push.json` |
| `image-archive-check` | implemented | Checks `build/image-build/image.tar` against `EXPECTED_ARCHIVE_SHA256`, `EXPECTED_CONFIG_DIGEST` and `HEAD`; the config member name is derived from `EXPECTED_CONFIG_DIGEST`, never read from the archive |
| `image-smoke-archive` | implemented | Runs the same archive check, loads the archive and runs the smoke tests against it |
| `release-tag-absent` | implemented | Fails unless `RELEASE_TAG` is proven absent from GHCR; only `MANIFEST_UNKNOWN` or `NAME_UNKNOWN` counts as absent, every other registry error fails |
| `image-pull`, `image-smoke-pulled` | implemented | Pull `IMAGE_REF` (a `name@sha256:` reference) and check its digest and revision label, run the smoke tests against it |
| `image-scan` | implemented | Scans the local test image (`SCAN_IMAGE`, default the smoke tag; run `make image-smoke` first) or, with `IMAGE_REF=name@sha256:<digest>`, exactly that registry digest, with the pinned, checksum-verified Grype and a freshly verified vulnerability database, then applies the fail-closed exception gate `tools/security/grype_gate.py`; reports land in `build/image-scan/`. See [`image.md`](image.md#vulnerability-gate) |
| `grype-expected-config` | implemented | Rewrites `security/grype-expected-config.json` from the last `make image-scan` report (variable fields blanked); used after a Grype bump, and the diff is reviewed |
| `sbom` | implemented | SPDX and CycloneDX SBOMs of the registry digest `IMAGE_REF` with the pinned, signature-verified Syft; fails unless the SBOM describes exactly that manifest digest; `sbom-check` repeats only that check on `build/sbom/` |
| `sign`, `verify-release` | implemented | cosign keyless signature of the GHCR digest (in the workflow only), then verification of the signature and of the provenance and SBOM attestations, bound to `main` and the commit |
| `image-release` | implemented | In the `image-build` workflow on `main` only: tags the verified digest as `RELEASE_TAG` (`<commit>-<run>-<attempt>`) with the pinned crane, after `release-tag-absent` |
| `image-smoke` | implemented | Builds `localhost/linux-compliance-runner:smoke` locally with docker or podman (never pushed) and runs `tests/smoke` against it read-only, as UID 10001, without capabilities or network; see [`image.md`](image.md) |
| `release-check` | pending FREES-84 | Release readiness |

The required and external skill lists are passed explicitly by `make lint-skills` and by the `skill-validator`
pre-commit hook; change both together.

Pending targets print `not implemented yet: <target> (tracked in FREES-<key>)` to standard error and exit
with status 2. They never succeed silently and are not part of `lint`, `test` or `ci`.

## Pre-commit stages

Configuration: `.pre-commit-config.yaml`. Install the hooks with `make install`.

| Stage | Hooks |
|---|---|
| `pre-commit` (fast) | trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, check-merge-conflict, check-added-large-files, detect-private-key, gitleaks (staged), ruff check, ruff format, yamllint, markdownlint-cli2, hadolint (only when a `Containerfile` changes), shellcheck, repository source rules, skill validator, markdown relative links |
| `pre-push` | mypy, pyright, pylint, bandit, pytest |
| `manual` (CI only) | gitleaks history scan, actionlint, zizmor |

Run a stage by hand:

```text
uv run pre-commit run --all-files
uv run pre-commit run --all-files --hook-stage pre-push
uv run pre-commit run --all-files --hook-stage manual
```

`pre-commit run` only sees files known to git; `git add` new files first.

Hooks for OpenTofu and Checkov (FREES-30, FREES-31) are pending the issues that introduce their sources. They are intentionally absent rather than faked.

Pin ownership rule: every Python tool hook (ruff, yamllint, mypy, pyright, pylint, bandit, pytest, shellcheck,
actionlint, zizmor, hadolint) is a `repo: local` hook that runs `uv run --frozen <tool>`, so its version lives only in
`pyproject.toml` and `uv.lock` and is updated by Dependabot. Only hook repositories that are not tools declared in
`pyproject.toml` (pre-commit-hooks, gitleaks, markdownlint-cli2) are remote hooks. hadolint is pinned as `hadolint-bin` in
`pyproject.toml` and its local hook is restricted to `Containerfile` by `files: (^|/)Containerfile$`; the upstream
hadolint hook is not used because it only runs a binary from `PATH` and would pin nothing. pre-commit-hooks is a Python
package, but its version is the hook revision, owned by Renovate rather than by the project environment. They are
pinned by full commit SHA with a `# vX.Y.Z` annotation and updated by Renovate. `additional_dependencies` is never used. The annotation on `rev:` is the second permitted
YAML comment form (ADR 0005, amendment 2026-10-25).

## Running each check manually

| Check | Command |
|---|---|
| Ruff lint and format | `uv run ruff check .` and `uv run ruff format --check .` |
| Pylint | `uv run pylint tools tests` |
| mypy | `uv run mypy` |
| Pyright | `uv run pyright` |
| Bandit | `uv run bandit -c pyproject.toml -r tools` |
| Tests with coverage | `uv run pytest tests/unit --cov --cov-report=term-missing` |
| yamllint | `uv run yamllint --strict .` |
| actionlint | `uv run actionlint` |
| zizmor | `uv run zizmor --persona pedantic .github/workflows` |
| Repository rules | `uv run python tools/lint/check_repo_rules.py <files>` |
| Skills | `uv run python tools/skills/validate_skills.py` |
| Markdown links | `uv run python tools/docs/check_links.py <files>` |

zizmor runs offline unless a `GH_TOKEN` is present. CI exports the workflow token for the `security` job
so that online audits (impostor commits, version annotation mismatch, known vulnerable actions) run too.
The pedantic persona is used because it is the strictest signal and the workflow count is small; the
current workflows produce no findings under it.

## Comment and annotation rules

No inline code comments are allowed in Python, YAML, Makefile, TOML or shell. Use names, docstrings,
module documentation and `docs/` instead. `tools/lint/check_repo_rules.py` enforces the rules below on
YAML and Python files (collection repository ADR 0005):

- Every YAML file starts with `---` followed by a newline.
- YAML files contain no `#` comments, except a trailing version annotation of exactly `# vX.Y.Z` on a pinned line:
  - `uses: owner/repo@<40-hex>` in workflows,
  - `rev: <40-hex>` in `.pre-commit-config.yaml`.
- `#` inside quoted scalars, block scalars and URLs is content, not a comment.
- Python files contain no comments, except a shebang on the first line. This includes `# noqa` and
  `# type: ignore`; suppressions are configured in `pyproject.toml` instead.
- YAML files contain no `shell`, `command`, `raw`, `script`, `win_shell` or `win_command` task keys,
  including the fully qualified and `action` / `local_action` spellings. The rule is shared with the collection
  repository and is unlikely to fire here.

Every lint ignore lives in `pyproject.toml` with its reason in `[tool.freesecdev.lint-justifications]` or
`[tool.freesecdev.pylint-justifications]`.

Configuration relaxations, each with its reason:

- `.markdownlint-cli2.yaml` disables MD013 (line length) because prose and tables in the skills and docs are written one paragraph per line, and MD060 (table column style) because it demands padded
  pipes that the existing tables, which are maintained by hand, do not use. All other default rules are on.
- `.yamllint.yaml` exempts `docs/planning/` from the line length rule only. The exemption is inherited from the
  collection repository and unused here until planning files exist.

## Pull request workflow

`.github/workflows/ci.yml` runs on `pull_request` to `main`, `push` to `main` and `merge_group`.

| Job | Make target |
|---|---|
| `lint` | `make lint` |
| `typecheck` | `make typecheck` |
| `test` | `make test-coverage` |
| `security` | `make security` |
| `container` | `make lint-container` and `make image-smoke`; a test build on a GitHub-hosted runner, not a release artifact |
| `ci-gate` | none; fails unless every needed job succeeded |

`ci-gate` runs with `if: always()` and is the only check that branch protection should require. Job names
are stable, so the required check name `ci-gate` does not change. Runs for pull requests cancel superseded
runs; runs on `main` and merge groups are never cancelled. `docs` is part of `make ci` locally and is
added as a job together with the documentation pipeline.

This repository builds the toolbox runner image, so its own jobs run on `ubuntu-24.04` with a pinned `uv`; the
collection repository consumes the published GHCR image by digest only (FREES-36, see [`image-build.md`](image-build.md)). The merge queue
and the `ci-gate` required check are enabled in the repository rules after this workflow is on `main`
(FREES-29).

## Dependency pins

- Python tools are pinned to exact versions in `pyproject.toml` and locked in `uv.lock`. Update with
  `uv lock --upgrade-package <name>` and commit both files.
- GitHub Actions are pinned to full commit SHAs with a `# vX.Y.Z` annotation.
- The `uv` version used in CI is pinned in `.github/workflows/ci.yml`.
