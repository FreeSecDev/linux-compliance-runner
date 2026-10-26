# Ownership and triage reference

## Ownership

| Ecosystem | Owner |
|---|---|
| Container image digests (Alpine base image digest) | Renovate |
| Alpine apk package pins | Renovate (planned, FREES-35) |
| GitHub Actions SHAs | Renovate |
| OpenTofu providers | Renovate |
| pre-commit hooks (remote hook repositories) | Renovate |
| Python (pip, uv) versions and security updates, including hadolint (`hadolint-bin`) | Dependabot |
| `setup-uv` `version:` input | Renovate |
| Python runtime (`.python-version`, `setup-python`) | Manual pull request |
| Security updates for Python and GitHub Actions | Dependabot security updates |
| Security fixes for images, apk pins, hooks, providers | Renovate schedule (documented residual risk) |
| OpenTofu and python-build-standalone release versions and checksums in the `Containerfile` | Renovate (`customManagers` regex) |
| Python tools in the toolbox image (`toolbox/uv.lock`) | Dependabot |
| Grype version and checksum in the `Makefile` | Renovate (`customManagers` regex) |
| cosign version and checksum in the `Makefile` (verifies the Grype release signature) | Renovate (`customManagers` regex) |
| Renovate validator tree (`tools/renovate/package.json`, `package-lock.json`) | Renovate (`npm` manager, lock file maintenance) |
| Packer plugins, Ansible Galaxy requirements | Not used in this repository |

Renovate Python managers stay disabled, and Renovate also disables the `pypi` and `python-version` datasources and
the `actions/python-versions` package. Renovate's `vulnerabilityAlerts` is disabled. The `pre-commit` manager is
enabled explicitly because it is off by default.

## Severity SLA

| Severity | Fix or documented exception within |
|---|---|
| critical | 48 hours |
| high | 7 days |
| medium | 30 days |
| low | next scheduled update |

A fixable critical or high finding blocks release.

## Ignore entry format

Each entry records: finding ID, the package name and version as the scanner reports them, affected
component, severity, justification, owner, Jira issue, created date and an expiry date no later than
90 days after the created date and after today. CI fails on expired, stale or malformed entries.

## Pull request body template

```text
Summary of updates and release notes links.

Refs: FREES-<maintenance-issue>
```
