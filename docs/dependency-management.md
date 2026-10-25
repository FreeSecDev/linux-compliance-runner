# Dependency management

Scope: which bot updates which dependency, the update policy, and the vulnerability response targets.
Audience: contributors, reviewers and maintainers.

Two bots run side by side, each owning distinct ecosystems so that no dependency receives duplicate pull requests.
Pinning rules from [`AGENTS.md`](../AGENTS.md) are kept current, never relaxed.

## Status

The configuration files are committed, but the bots are not confirmed active:

- Dependabot is built into GitHub and reads `.github/dependabot.yml` from the default branch.
- Renovate needs the **Mend Renovate GitHub App** to be installed on the FreeSecDev organisation and granted this
  repository. That is a one-time setup step for the organisation owner, tracked on FREES-81. Until it is done,
  `.renovaterc.json` has no effect.

## Ownership

| Ecosystem | Owner | Why |
|---|---|---|
| Python (`uv`, `pyproject.toml`) versions and security updates, including hadolint (`hadolint-bin`) | Dependabot | Native GitHub security alerts and the `uv` ecosystem keep Python updates and advisories in one place |
| GitHub Actions, pinned to full commit SHAs | Renovate | Digest pinning with release annotations ([ADR 0005](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0005-renovate-version-annotations.md)) |
| Container image digests, including the Alpine base image digest in the `Containerfile` | Renovate | Images are consumed by digest only; the `dockerfile` manager matches `Containerfile` by default |
| Alpine `apk` package pins in the `Containerfile` | Manual (Renovate planned) | Renovate's `dockerfile` manager reads the pins but skips them at extraction (`unknown-registry`), so no bot updates them yet; a build that reports a missing version is fixed by a pull request that bumps the pin. See [`image.md`](image.md) |
| OpenTofu version and archive SHA-256 in the `Containerfile` | Renovate | `customManagers` regex with the `github-release-attachments` datasource updates version and checksum together |
| python-build-standalone release and CPython archive SHA-256 in the `Containerfile` | Renovate | `customManagers` regex with the `github-release-attachments` datasource; the toolbox's CPython minor version still changes only by a deliberate pull request |
| Grype version and linux/amd64 archive SHA-256 in the `Makefile` (`GRYPE_VERSION`, `GRYPE_SHA256_LINUX_AMD64`) | Renovate | `customManagers` regex with the `github-release-attachments` datasource, which reads the new digest from the release `checksums.txt`; grouped as `image scanner` |
| Grype vulnerability database | Not pinned (fetched per scan) | Rebuilt daily and unsigned; `make image-scan` verifies the archive SHA-256 against the listing and fails when the database is older than 120 hours. See [`image.md`](image.md#vulnerability-gate) |
| Python tools in the toolbox image (`toolbox/pyproject.toml`, `toolbox/uv.lock`) | Dependabot | A second `uv` entry for `/toolbox`; the Containerfile exports the lock during the build |
| pre-commit hooks | Renovate | Hooks are pinned by revision |
| Terraform and OpenTofu providers | Renovate | Provider lock handling and version constraints |
| `astral-sh/setup-uv` `version:` input (the uv tool version) | Renovate | Read by the `github-actions` manager; Dependabot does not manage it |
| Python runtime version (`.python-version`, `setup-python` inputs) | Manual pull request | A runtime change needs full testing; Renovate disables the `python-version` datasource and the `actions/python-versions` package that `setup-python` resolves through |
| Security updates for ecosystems in GitHub's dependency graph (Python `uv`, GitHub Actions) | Dependabot | GitHub security updates are enabled for the repository; Renovate's `vulnerabilityAlerts` is disabled |
| Security fixes for container digests, `apk` pins, pre-commit hooks and OpenTofu providers | Renovate (scheduled) | No advisory-driven pull requests exist for these; see residual risk below |

Renovate runs only an explicit allow-list of managers (`github-actions`, `dockerfile`, `pre-commit`, `terraform`, `terraform-version`, `custom.regex`), none of which is a Python manager. Two enabled managers could
still see Python data, so Renovate also disables the `pypi` datasource (Python packages in pre-commit
`additional_dependencies`), the `python-version` datasource and the `actions/python-versions` package that the
`setup-python` action's version input resolves through. Renovate's `pre-commit` manager is off by default, so it is
enabled explicitly; listing it in `enabledManagers` alone does not turn it on. Python tools used by pre-commit
run as local hooks through `uv`, so their versions live only in `pyproject.toml` and `uv.lock`, which Dependabot owns.

Dependabot version updates cover the `uv` ecosystem only. GitHub's Dependabot security updates are enabled for the whole
repository, so security pull requests for ecosystems in GitHub's dependency graph, Python (`uv`) and GitHub Actions,
come from Dependabot.
Renovate's `vulnerabilityAlerts` is disabled so the two bots never open competing security pull requests.

One overlap is accepted on purpose: a Dependabot security update to a GitHub Action can land between Renovate's
scheduled digest updates. Renovate then rebases or closes its own pull request. This keeps security fixes fast without
waiting for the Renovate schedule.

A new ecosystem must be assigned to exactly one bot in this table in the same pull request that adds it.

## Update policy

- Routine updates run weekly, on Monday morning (Europe/Amsterdam), and are grouped where related.
- Both bots wait 7 days after a release before proposing it, 14 days for majors, to reduce supply-chain risk:
  Renovate through `minimumReleaseAge` and Dependabot through `cooldown`.
  Dependabot security updates for Python and GitHub Actions are not delayed by that wait or by the schedule.
- Major updates wait 14 days, are labelled `breaking-change` and get their own pull request. Like every other update,
  they are reviewed by the `freesecdev-review` App and must pass the required checks. Nobody is asked to approve them
  on the dependency dashboard, which is informational only.
- Concurrency is limited (Dependabot 5 open pull requests, Renovate 5 concurrent and 2 per hour).
- Commits use the Conventional Commit type `build`, for example `build(deps): bump ...`.
- Labels: `dependencies` plus an ecosystem label such as `python` or `ci`.
- Automerge is disabled. Every update goes through the same review and required checks as any other change.
- Update pull requests are untrusted code: they receive no cloud role and no secrets. Reviewers check changelogs,
  provenance, new maintainers and licence changes, and confirm that an action or image digest matches its release.
- Hash-locked files are regenerated, never edited by hand.

### Grype version

`make image-scan` pins Grype 0.121.0, published 2026-10-19, before the 7-day release age had passed. It is treated as a
security release and is exempt from the wait, as OpenTofu 1.13.2, CPython 3.12.15 and Node.js 24.22.1 were. Its release notes
list five remediated vulnerabilities in Grype's own `golang.org/x/net`: GO-2026-6612 (critical) and GO-2026-6603,
GO-2026-6610, GO-2026-6611 and GO-2026-6617 (high), the same advisories accepted for OpenTofu. Grype uses that module for its network code, and the scanner runs on
every pull request. The archive SHA-256 `64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519` was checked against
`grype_0.121.0_checksums.txt` and a fresh download, and the binary reports database schema 6.
A Grype bump changes the effective scanner configuration that the gate compares, so a Renovate pull request for Grype also
needs `security/grype-expected-config.json` regenerated with `make grype-expected-config` and reviewed; until then the gate
fails, by design.

## Residual risk

GitHub's dependency graph does not cover container images, `apk` packages, pre-commit hooks or OpenTofu
providers, and Renovate's own vulnerability alerts are disabled to avoid competing security pull
requests. A security fix in one of these ecosystems therefore arrives with the next weekly Renovate run, after the
7-day (or 14-day for majors) release age. The Grype image gate (`make image-scan`, FREES-37, ADR 0006) narrows this gap for
the image: the CI `container` job fails on every unlisted critical or high finding in the toolbox image, including its `apk`
packages, the Python environment and the Go modules compiled into OpenTofu, with a vulnerability database at most 120 hours
old. The response targets below then require a manual update pull request or a documented exception. The gate does not cover
pre-commit hooks or OpenTofu providers; for those, fixes arrive only through the Renovate schedule unless a maintainer acts on
an advisory. Revisit this if Renovate's OSV-based alerts can be scoped to these ecosystems without overlapping
Dependabot. Tracked on FREES-81.

## Vulnerability response targets

| Severity | Fix or documented exception within |
|---|---|
| critical | 48 hours |
| high | 7 days |
| medium | 30 days |
| low | next scheduled update |

A fixable critical or high finding blocks a release. Ignore entries need a justification, owner, Jira issue and an expiry
no later than 90 days out. The authoritative tables are in
[the dependency-management skill reference](../.agents/skills/dependency-management/references/ownership-and-sla.md).

## Related

- [ADR 0005](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0005-renovate-version-annotations.md), [ADR 0006](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0006-toolchain-selection.md)
- [`SECURITY.md`](../SECURITY.md) for reporting vulnerabilities
- Jira: FREES-81 (dependency configuration), FREES-35 (Containerfile, toolbox lock and binary pin managers), FREES-37 (Grype gate)

## Vulnerability exceptions

Accepted findings are recorded in [`security/vulnerability-exceptions.yaml`](../security/vulnerability-exceptions.yaml)
(format 2) with the finding ID, the package name and version exactly as Grype reports them, a component description,
severity, justification, owner, Jira issue, creation date and an expiry at most 90 days after both the creation date and
today. One validator (`tools/security/vulnerability_exceptions.py`) serves the unit test and the Grype gate; the gate matches
findings on ID, package and version together and fails on unlisted critical or high findings, stale or expired entries, a
changed severity and any schema violation. Current entries (all created 2026-10-25, expiring 2027-01-23): the
`golang.org/x/net` and `grpc` findings compiled into OpenTofu 1.13.2 (FREES-37; no OpenTofu release includes the fixes yet)
and `ecdsa` 0.19.2 (FREES-82; no fixed release exists). Details are in [`image.md`](image.md#vulnerability-gate).
