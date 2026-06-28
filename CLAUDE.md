# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go build ./...       # verify the package compiles
go vet ./...         # run static analysis
go test ./...        # run the unit tests
go generate ./...    # regenerate stringer files (*_string.go)
```

Tests cover validation helpers (including the SSRF guard in `validate.go`) and a
few enum/permission helpers; coverage is partial, so most types have none yet.

## Architecture

This is a pure Go library (`github.com/deploys-app/api`) — no `main` package, no server. It defines the shared API contract for deploys.app and has two layers:

**Root package** — interfaces, request/response types, validation, errors, and constants. Every resource (Deployment, Billing, Domain, Disk, etc.) has its own file that contains:
- The resource interface (e.g. `Deployment`, `Billing`)
- All request/response structs for that resource
- `Valid() error` methods on request types for client-side validation

**`client/` package** — HTTP client that implements all root-package interfaces by calling `https://api.deploys.app/`. Each resource has a corresponding `client/<resource>.go` file containing a private `<resource>Client` struct. All calls go through `Client.invoke()` which POSTs JSON and expects `{"ok": bool, "result": ..., "error": ...}`.

The top-level `Interface` in `api.go` aggregates all resource interfaces. `client.Client` implements `api.Interface`.

## Key conventions

**Enum types** (e.g. `DeploymentType`, `DomainType`) are defined as `int` with iota constants. They always implement `String()`, custom JSON and YAML marshal/unmarshal, `Valid() bool`, and a `Parse<Type>String()` constructor. The `*_string.go` files are generated via `go generate` using `stringer`.

**Validation** uses `github.com/moonrhythm/validator`. Request types implement `Valid() error` returning a `*ValidateError` (via `WrapValidate`). The client calls `Valid()` before making any HTTP request.

**Errors** are package-level `var` sentinels created with `newError()`, which registers them in `AllErrors`. The client matches error messages from the API response against `AllErrors` to return typed errors.

**`Empty`** is the request/response type for operations with no parameters (GET-style). It implements `UnmarshalRequest` to reject non-GET HTTP methods and `Table()` for CLI output.

**Constants** in `constraint.go` define validation limits (`MinNameLength`, `MaxNameLength`, replica bounds, disk size). `price.go` defines per-unit pricing constants. Both are shared between client validation and server logic.

**`Deployer` and `Collector` interfaces** are internal/privileged: `Deployer` is used by the cluster agent to receive commands and report results; `Collector` is used to report resource usage for billing.
