---
layout: default
title: http-api
---

# HTTP API

The dashboard serves a same-origin JSON API on `http://127.0.0.1:8765` by default.
It accepts only the canonical loopback Host. Supplied Origin, Referer and fetch
metadata must describe the same local origin. There are no cross-origin grants.

## Routes

| Method | Route | Result | Authorization |
| --- | --- | --- | --- |
| GET | `/api/bootstrap` | Token, command catalog, session state, credential metadata | Local origin guards |
| GET | `/api/commands` | Command catalog | `X-Session-Token` |
| GET | `/api/state` | Session-state envelope | `X-Session-Token` |
| POST | `/api/command` | Command result and session state | Exact Origin and `X-Session-Token` |

Bootstrap and state snapshots do not contact the card. The frontend may explicitly
request reader enumeration after startup. Static serving is restricted to the
production index and approved asset filenames; source and configuration files
are not HTTP resources.

## Requests

POST bodies use `application/json` and are limited to 64 KiB. Duplicate JSON
properties, unknown command/argument names, non-finite numbers, invalid key
widths, incomplete hex bytes and out-of-range values are rejected before I/O.

```json
{
  "command": "get_version",
  "args": {},
  "expected_revision": "0",
  "confirm": false
}
```

The catalog describes command names, groups, fields, bounds, defaults, allowed
choices and whether reviewed confirmation is required. Hexadecimal fields use
hex text; numeric fields use decimal values. No request is implicitly selected,
authenticated or retried to make another command succeed.

`expected_revision` must equal the decimal-string `session_revision` returned in
the current state. The value above is illustrative; obtain the actual revision
from bootstrap or a state snapshot. All card commands require it. A review dialog
retains its original revision. A mismatch returns `stale_session` before I/O, so
another tab cannot silently change the target of a reviewed write. Connect and
disconnect validate a supplied revision and allow omission for explicit recovery.

## Responses

Command responses contain `ok`, `result`, `state` and, on failure, `error`.
Errors retain the available native status, ISO status, reader error and delivery
outcome. A rejected card command is a command failure even when the HTTP exchange
itself completed with status 200.

`state` includes connection status, reader name, known native application scope,
authentication metadata, ATR and whether explicit reconnection is required.
It also includes the current `session_revision`.
Unknown selection is represented by `null`. Credential responses contain only
names, identifiers, slots, algorithms and versions; key bytes are never returned.

HTTP errors use meaningful status codes, including malformed requests (400),
failed source/token guards (403), unknown routes (404), concurrent execution
(409), stale session revisions (409), oversized bodies (413) and unsupported
content types (415).

## Execution and delivery

One request owns the command service at a time. Busy requests are rejected, not
queued. The transport and library enforce a bounded operation deadline. A reader
driver call that outlives its deadline retains its resources and quarantines the
connection while it finishes; further frames are not admitted on that handle.

Delivery is separate from success:

| Delivery | Meaning |
| --- | --- |
| `not_sent` | No frame was transmitted |
| `rejected` | A definite card rejection was received |
| `succeeded` | Card execution succeeded but later host processing failed |
| `unknown` | Delivery or execution cannot be established |

Never infer rollback from an error or resend a persistent mutation merely because
its response was lost. Raw traffic requires a fresh connection before typed
commands, and uncertain delivery requires explicit recovery before more card I/O.

## Data handling

Tokens, request arguments and key material must not be added to application logs.
Responses may contain sensitive file data; diagnostics are not automatically
safe to publish. Saved credentials disappear when removed or when the process
ends. This API is intended for a trusted local workstation, not remote access.
