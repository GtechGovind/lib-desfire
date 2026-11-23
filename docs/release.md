---
layout: default
title: release
---

# Release checks

## Release workflow

The **Release** workflow produces three archives and `SHA256SUMS`:

- `lib-desfire-X.Y.Z-source.zip` and `lib-desfire-X.Y.Z-source.tar.gz`: tracked
  source with a top-level directory, including documentation and the frontend lockfile.
- `lib-desfire-X.Y.Z-windows-x64.zip`: the native dashboard, web assets, matching
  OpenSSL Crypto/legacy provider, dependency licenses, setup guide and a signed
  Microsoft Visual C++ x64 runtime installer. `BUILD-INFO.json` records the source
  commit, dependency version and hashes of bundled files.

The application binary is unsigned. Its automated checks do not imply hardware
certification or coverage of every card/reader combination.

### Test packaging without creating a release

Open **Actions → Release → Run workflow**, select a branch, leave `tag` blank
and leave `create_draft` unchecked. Alternatively:

```sh
gh workflow run release.yml --ref main -f create_draft=false
```

The workflow builds the source extracted from its archive, runs the installed
consumer check, builds the Windows dashboard, checks frontend lint/formatting,
verifies providers and starts the extracted ZIP to check its web assets.
It never connects to a card. Download **release-files** from the workflow's
artifacts; this contains all archives and checksums. No tag or release is created.

### Create a draft release

1. Update `CMakeLists.txt` to the intended stable `X.Y.Z` version and push the
   commit to `main`. Complete the checks below and wait for CI and CodeQL to pass.
2. Create and push the matching tag, for example:

   ```sh
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

3. The workflow checks tag/version equality, main-branch ancestry and successful
   CI/CodeQL on that exact commit, then packages the release and creates a **draft**
   with generated release notes. Inspect it before publishing.

To create or retry a draft manually, select an **existing** tag in the `tag`
input and check `create_draft`, or run:

```sh
gh workflow run release.yml --ref main -f tag=v0.2.0 -f create_draft=true
```

Existing draft assets can be refreshed on a retry. Published releases are never
modified by this workflow. Stable `vX.Y.Z` tags are required; prerelease tags are
not supported. Ordinary branch pushes do not create a release.

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
