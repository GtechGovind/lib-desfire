---
layout: default
title: architecture
---

# Architecture

## Scope

lib-desfire provides a portable C++17 card protocol library and a local desktop
dashboard. The library implements native DESFire and standard ISO 7816 commands.
The dashboard adds a Windows PC/SC adapter, an HTTP API, and a React interface.

The core remains independent of the dashboard, HTTP, JSON, operating-system card
drivers, and frontend build tools. Dashboard dependencies are private to the
application target.

## Components

| Component | Responsibility |
| --- | --- |
| `lib/include` | Public command API, result types, bounds and transport contracts |
| `lib/impl` | Protocol encoding, cryptography, secure messaging and session state |
| `src/transport` | Exclusive WinSCard connection and deadline-aware frame exchange |
| `src/application` | Command validation, credentials, dispatch and application session metadata |
| `src/http` | Loopback request guards, API routes and static asset delivery |
| `src/dashboard` | Native application entry point and shared command catalog |
| `src/dashboard/frontend` | React components, typed API boundary and interaction state |

One C++ process owns the HTTP server, credential storage and card connection.
There is no subprocess command protocol or separate application runtime.
The server serves the compiled frontend from its `web` directory.

## Request lifecycle

1. The browser receives the command catalog, a session token and an in-memory
   state snapshot from `/api/bootstrap`. Bootstrap performs no reader I/O.
2. Reader enumeration occurs only when requested by the interface. Connecting
   requires an explicitly selected reader and resets its card before creating
   the library session.
3. A command request passes the HTTP origin, token, body and JSON guards.
4. The application validates the command and its complete argument set against
   the shared catalog, including key widths and cross-field constraints. Card
   commands must also match the session revision captured by the client.
5. One command owns the card session. Concurrent requests receive `busy` and are
   not queued. Persistent mutations and raw frames require reviewed submission.
6. The dispatcher invokes the public library operation and returns its result,
   exact available status fields, delivery outcome and updated session metadata.

The command catalog is embedded by CMake from `commands.json`. The browser and
server use this same resource; no second generated validation table is maintained.
Iterator, range and bounded-output overloads share their logical dashboard command.

## Card state

The transport owns one exclusive PC/SC handle. Both native and standard APDU
callbacks refer to that handle and share deadline admission and quarantine.
Application metadata mirrors verified selection and authentication transitions;
it never assumes a rejected command completed successfully.

The server advances a session revision when a card command is admitted or a
connection is changed. The browser submits its captured revision with commands
and retains the revision shown during mutation review. If another tab changes
the session first, the stale command is rejected before reader I/O. Commands
are never retargeted to a newer reader or application automatically.

An unknown delivery outcome requires explicit reconnection before further card
commands. Raw frames make typed session state unknown; additional raw frames
remain available after a definite reply, while typed operations require a fresh
connection. No frame, transaction, authentication or recovery action is retried
automatically.

Resetting host state does not reset the card or undo a transaction. Pending
transactions, immediate writes and key changes retain the card's documented
persistence rules. The interface exposes commit and abort explicitly.

## Credentials and diagnostics

Saved credentials are process-local and have no persistence format. Only names,
application identifiers, slots, algorithms and versions leave the credential
store. Owned key buffers erase their live bytes before release or replacement.
HTTP and browser processing can create transient copies, so the application does
not promise locked memory or protection against a privileged local process.

Activity records exclude request arguments, tokens and key material. Users may
still receive sensitive application data in command responses; exported response
data must be reviewed before sharing. The server does not log request bodies.

## Dependency boundaries

OpenSSL supplies cryptographic primitives. The application uses cpp-httplib for
HTTP and JSON for Modern C++ for JSON processing. React, TypeScript and Vite are
frontend build dependencies; the installed dashboard requires only its native
executable, web assets and applicable native runtime libraries.

Third-party versions and archive checksums are pinned in CMake. The core build
does not fetch application dependencies. Dependency licenses are retained in
release notices.
