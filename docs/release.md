---
layout: default
title: release
---

# Release checks

## Automated source releases

Update the version in `CMakeLists.txt`, complete the checks below, then push a
matching version tag, for example `git tag v0.2.0` followed by
`git push origin v0.2.0`. The source-release workflow builds the core, verifies
the installed consumer and creates a **draft** GitHub Release with a CPack source
ZIP, SHA-256 checksums and generated notes. Review the draft before publishing.
No version tag or published release is created by an ordinary branch push.

## Source distribution

Include the library, application and frontend sources, command catalog, public
build configuration and documentation.

Exclude local presets, IDE metadata, caches, dependencies downloaded for a local
build, generated assets, logs, process identifiers, archives, credentials and
reader captures. `.gitignore` lists these local artifacts. The CMake source
package configuration applies the same exclusions.

Inspect the candidate source package for machine-specific paths, usernames,
private endpoints, card identifiers, key bytes, internal workflow notes and
obsolete product-specific references. This check applies to package contents,
not just files visible in the editor.

## Binary distribution

Build the React assets and native application in Release configuration. Package
the executable with `web`, required compiler/OpenSSL runtime files, applicable
provider modules and notices supplied by those dependencies. Do not include
credential stores, server logs or the local development tree.

Run the binary from a clean directory. Verify help/version output, application
startup, static asset delivery, request validation and clean shutdown. Reader
checks must distinguish observed card behavior from unsupported or unexecuted
combinations. Never imply that one card verifies every generation or key family.

Persistent write, transaction and key-change qualification requires an explicitly
designated disposable card and separate authorization. Document the coverage
without publishing its keys, identifiers or captured protected traffic.
