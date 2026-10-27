# AGENTS.md

Mandatory instructions for every human or AI agent working in this repository.
Task-specific guidance lives in [`.agents/skills/`](.agents/skills/). Skills for collection work
(`ansible-collection`, `ansible-modules`, `compliance-frameworks`, `molecule-testing`, `packer-images`,
`reporting-dashboard`) live in
[`FreeSecDev/ansible-linux-compliance`](https://github.com/FreeSecDev/ansible-linux-compliance/tree/main/.agents/skills).

## Project

This repository builds the minimal OCI toolbox image used by the `freesecdev.linux_compliance` CI.
It contains no collection code. The image is built on GitHub-hosted runners, published to GHCR, signed and attested, and consumed by digest.

## Traceability

- Every change maps to a Jira issue in project `FREES` on `vidlunnia.atlassian.net`.
- Branch names: `<type>/FREES-<number>-<short-slug>`.
- Commits follow Conventional Commits and end with a `Refs: FREES-<number>` footer.
- Every change lands through a pull request into `main`; squash merge only, rebased on the latest `main`.
- Architecture decisions are ADRs in [`docs/adr/`](docs/adr/); platform-wide ADRs live in the collection repository.

## Hard rules

1. The build file is a `Containerfile`; there is no `Dockerfile`.
2. The base image is pinned by digest; packages and Python dependencies are pinned and hash-locked.
3. The image runs as a non-root user, contains no SSH daemon or credentials, and works with a read-only root file system
   and all capabilities dropped.
4. Release images are built and published only by the `image-build` workflow on `main`, on GitHub-hosted runners
   (ADR 0002); never published from a local machine or a self-hosted runner.
5. A release is never published if any scan, SBOM, signature or smoke test step fails.
6. Pin GitHub Actions to full commit SHAs. The image workflow uses only the per-job `GITHUB_TOKEN`; no AWS access
   and no long-lived keys.
7. Every YAML file starts with `---` followed by a newline. No inline code comments.
8. Never print, commit or log credentials. Never report work as successful unless it actually ran.

## Developer interface

The `Makefile` is the single entry point for developers and CI. Run `make help` for targets.
