# Contributing

Keep changes focused and preserve the portable core's public contracts.

## Getting started

Fork the repository, create a focused branch and follow the
[build guide](docs/building.md). For a browser-based core environment, open the
repository in GitHub Codespaces; the development container installs OpenSSL and
builds the portable core. Windows is required for the PC/SC dashboard.

Discuss substantial API or protocol changes in an issue before implementation.
Use synthetic examples and describe the intended compatibility and card-state
behavior. Questions belong in [Discussions](https://github.com/GtechGovind/lib-desfire/discussions).

## Code conventions

- Use C++17, snake_case names, explicit ownership and the repository's
  `.clang-format` configuration.
- Document public bounds, lifetimes, state transitions and delivery outcomes.
- Split protocol, transport, application policy and HTTP concerns into focused
  modules. Application dependencies must not enter the core's public interface.
- Prefer explicit control flow, complete validation before I/O and RAII for
  resource ownership and secret erasure.
- Use strict TypeScript, focused React components/hooks, ESLint and Prettier.
  Validate data at the API boundary rather than casting untrusted JSON.
- Preserve one physical card/session relationship and never retry a card command
  automatically.

## Verification

Build the affected native targets with compiler warnings enabled. For frontend
changes, run the build, lint and formatting checks described in
[building](docs/building.md). Verify malformed input, delivery errors and session
transitions as well as successful operations.

Use only cards and readers you are authorized to operate. State whether a result
comes from an offline check or physical hardware. Do not run persistent writes,
formatting or key replacement as part of an ordinary build or startup check.
Keep verification credentials, captures and temporary probes outside the source
tree; never include actual key values or personal card data in a contribution.

## Changes for review

Explain the concrete problem, resulting behavior and verification performed.
Call out changes to compatibility, state management, dependencies or persistence.
Do not include personal machine paths, internal notes, card identifiers, private
configuration or protected traffic in code, screenshots, issues or pull requests.

Pull requests run the core build/install matrix, offline consumer check, frontend
checks, Windows dashboard build, CodeQL and dependency review. The
[offline consumer](examples/consumer) exercises installation and transport failure
handling without hardware. Describe any additional protocol or hardware testing
in the PR. See [GitHub features](docs/github.md) for workflow details.

By submitting a contribution, you agree to license it under the project's
[MIT license](LICENSE). Follow the [code of conduct](CODE_OF_CONDUCT.md).
