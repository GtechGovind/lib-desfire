---
layout: default
title: building
---

# Building

## Requirements

- CMake 3.24 or newer and a C++17 compiler.
- OpenSSL 1.1.1 or newer development files and thread support.
- Windows and a PC/SC reader driver for the dashboard; the library is portable.
- Node.js 22.12 or newer and npm to build the React frontend.
- Internet access for initial dependency downloads, or installed CMake packages
  and a populated npm cache.

Use matching architectures and compiler runtimes for the compiler and OpenSSL.
OpenSSL 3 and newer require the default and legacy providers used by the selected
authentication family. Ensure the provider modules are available at runtime.

## Core library

```sh
cmake -S . -B build/core -DCMAKE_BUILD_TYPE=Release
cmake --build build/core --config Release --parallel
cmake --install build/core --config Release --prefix install
```

The dashboard is optional and disabled by default. Use
`-Dlib_desfire_build_shared=ON` for a shared core library. Pass
`-DOPENSSL_ROOT_DIR=/path/to/openssl` when OpenSSL is outside the compiler's
normal search paths. Cross compilation uses the target SDK's CMake toolchain.

An installed consumer uses:

```cmake
find_package(lib_desfire 0.2 CONFIG REQUIRED)
target_link_libraries(your_application PRIVATE lib_desfire::core)
```

## Dashboard

From a Windows developer terminal with CMake, a compiler, Node.js and npm on PATH:

```powershell
cmake -S . -B build/dashboard -Dlib_desfire_build_dashboard=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build/dashboard --parallel
build/dashboard/desfire_dashboard.exe
```

For multi-configuration generators, add `--config Release` to the build command
and run the executable from the `Release` directory. CMake builds the frontend
and copies its production files to `web` beside the executable. The resulting
dashboard runs from the native executable and staged web assets.

The PowerShell helper performs configuration, build and launch:

```powershell
./src/run_dashboard.ps1 -BuildDirectory build/dashboard
```

Use an existing compiler toolchain or CMake toolchain file. The helper does not
discover private IDE installations or modify execution policy. If scripts are
restricted, run the equivalent CMake commands directly.

The application listens at `http://127.0.0.1:8765`. Use `--port 8766` to choose
another port and `--assets /path/to/web` to select a production web directory.
`--help` lists available arguments. Stop the foreground process with Ctrl+C.

## Frontend development

```sh
cd src/dashboard/frontend
npm ci
npm run build
npm run lint
npm run format:check
```

The production frontend is served by the C++ application. Keep the browser and
API on the same origin; the server intentionally rejects cross-origin calls.
Changing `commands.json` requires reconfiguring the C++ target so its embedded
catalog matches the frontend schema delivered by the server.

## Distribution

Install the application, web assets and license notices together. Include the
matching native runtime libraries and OpenSSL provider modules for the intended
deployment. Do not package build caches, local presets, credentials, reader
captures, logs or IDE files. See [release checks](release.md).
