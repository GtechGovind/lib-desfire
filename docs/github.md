---
layout: default
title: GitHub features
---

# GitHub features

## Automation

| Feature | Configuration | Behavior |
| --- | --- | --- |
| Core CI | `.github/workflows/ci.yml` | Linux/macOS/Windows static and shared builds, installation and offline consumer checks |
| Dashboard CI | Same workflow | Windows native build, staged assets, help smoke check and temporary build artifact |
| Frontend CI | Same workflow | Pinned npm installation, TypeScript/Vite build, ESLint and Prettier |
| CodeQL | `.github/workflows/codeql.yml` | C++ including the Windows application, and JavaScript/TypeScript; pushes, PRs and weekly scans |
| Dependency review | `.github/workflows/dependency-review.yml` | Reject newly introduced high/critical vulnerabilities in supported dependency changes |
| Dependabot | `.github/dependabot.yml` | Weekly npm and SHA-pinned GitHub Actions update PRs |
| Documentation | `.github/workflows/pages.yml` | Build this documentation with Jekyll and deploy through GitHub Pages |
| Draft source releases | `.github/workflows/release.yml` | Version-tag check, core/consumer build, CPack ZIP, SHA-256 checksums and generated release notes |

Workflows default to read-only repository access. Security uploads, Pages
deployment and draft releases receive only the additional permissions they need.
Pull requests run without project secrets. Third-party Actions are pinned to
commit SHAs and maintained by Dependabot.

CMake FetchContent archive dependencies are versioned and SHA-256 checked;
review their updates manually. Dependabot configuration here covers npm and
GitHub Actions, not those CMake archives. CI is offline with respect to cards and
does not replace protocol, cryptographic or physical-hardware qualification.

## Community

The repository includes issue forms, a PR template, contribution and security
policies, a code of conduct, support links, CODEOWNERS and release note categories.
Use the default **Q&A** Discussions category for integration questions. Its form
is in `.github/DISCUSSION_TEMPLATE/q-a.yml`.

Codespaces uses `.devcontainer/devcontainer.json` to build the portable core on
Ubuntu. The dashboard and physical Windows PC/SC transport require Windows;
Codespaces does not attach your local reader. Codespaces usage follows the
account's GitHub quota and billing settings.

## Repository settings

Issues, Discussions, Pages, dependency alerts, security updates, private
vulnerability reporting and available secret protection are configured through
GitHub settings rather than repository files. Administrators should check these
settings after transferring or forking the repository.

CODEOWNERS requests reviews where supported; it does not enforce branch rules.
For a larger maintainer team, add a ruleset requiring successful CI and reviewed
pull requests. Choose review requirements that the actual team can satisfy.

## Sponsorship

`.github/FUNDING.yml` and README links point to
[GtechGovind on GitHub Sponsors](https://github.com/sponsors/GtechGovind).
The maintainer must finish GitHub Sponsors enrollment and payment setup before
accepting sponsorships. Committing a funding file does not enroll an account or
create payment tiers.

## Release procedure

Follow [release checks](release.md). Push a tag matching `CMakeLists.txt`, such as
`v0.2.0`, to produce a **draft** source release. Inspect its archive, checksums,
generated notes and hardware coverage before publishing it. The workflow does
not publish unqualified Windows binaries.
