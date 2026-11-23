# Windows dashboard release

This package contains the x64 DESFire card console, its web assets, OpenSSL
Crypto and legacy provider, third-party notices and a Microsoft-signed Visual
C++ runtime installer. It does not require Node.js, npm, CMake or a compiler.

## Start the console

1. Extract the entire ZIP to a writable folder. Keep its files and subdirectories together.
2. Install `prerequisites/vc_redist.x64.exe` if the current Microsoft Visual C++
   v14 x64 Redistributable is not already installed. The installer presents
   Microsoft's license terms. Installation may require administrator access.
3. Install your PC/SC reader driver if Windows does not already provide one.
4. Run `desfire_dashboard.exe` and open **http://127.0.0.1:8765**.
5. Stop the foreground application with Ctrl+C when finished.

Use `desfire_dashboard.exe --help` for port and asset-directory options.
The `ossl-modules` directory contains the matching OpenSSL legacy provider.
An existing `OPENSSL_MODULES` environment variable takes precedence over that
directory; remove an unrelated override when launching this package.

The native binary is not code-signed. Windows may show a publisher warning.
Verify the ZIP against the release's `SHA256SUMS`; `BUILD-INFO.json` records the
source commit, dependency version and hashes of bundled files. The bundled
Microsoft installer retains its own signature and license.

## Scope and security

This is a Windows 10+ x64 build. Automated release checks exercise help/version,
OpenSSL provider loading and serving web assets from an extracted ZIP. They do
not certify every card generation, key family or reader. Review the release
notes for physical hardware coverage.

Use the console only on a trusted local workstation, with authorized cards and
readers. Read `SECURITY.md`; never expose the loopback listener through a public
proxy or tunnel. Real card writes and key changes are not part of release tests.

`LICENSE` covers lib-desfire. Files under `dependencies` cover the bundled
OpenSSL, cpp-httplib, nlohmann/json, React, React DOM and scheduler components.
