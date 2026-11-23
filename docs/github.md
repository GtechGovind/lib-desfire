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
| Releases | `.github/workflows/release.yml` | Source ZIP/tar.gz, Windows dashboard ZIP, checksums, manual package tests and tag-triggered draft releases |

Workflows default to read-only repository access. Security uploads, Pages
deployment and draft releases receive only the additional permissions they need.
Pull requests run without project secrets. Third-party Actions are pinned to
commit SHAs and maintained by Dependabot.

CMake FetchContent archive dependencies are versioned and SHA-256 checked;
review their updates manually. Dependabot configuration here covers npm and
GitHub Actions, not those CMake archives. CI is offline with respect to cards and
does not replace protocol, cryptographic or physical-hardware qualification.

TypeScript remains pinned to 6.0.3 because `typescript-eslint` 8.73.0 requires
`>=4.8.4 <6.1.0`. Dependabot leaves TypeScript 6.1+ updates for a coordinated
compiler/parser update; do not bypass npm's peer-dependency checks to install one.

### Reviewed CodeQL finding

The initial C++ scan reported `cpp/non-https-url` in cpp-httplib 0.67.0's
`ClientImpl::proxy_target_prefix()` (`build/codeql/_deps/httplib-src/httplib.h`).
That function constructs the absolute-form target for a plain HTTP proxy in
upstream client code. This application creates only `httplib::Server`, binds it
to `127.0.0.1`, and never instantiates an HTTP client or configures an outbound
proxy. The finding is therefore a false positive for this application's behavior.
Only that individual alert is dismissed; the query and dependency analysis
remain enabled. Reassess this decision if outbound HTTP client usage is added.

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

Follow [release checks](release.md). Test packaging from **Actions → Release**
without creating a tag or release, or push a tag matching `CMakeLists.txt`, such
as `v0.2.0`, to produce a **draft** source and Windows dashboard release. The
tagged commit must belong to `main` and have successful CI and CodeQL checks.
Inspect the packages, checksums, generated notes and hardware coverage before
publishing. Release automation never runs persistent card operations.
