---
name: update-and-audit-deps
description: >-
  Runs scripts/update-go-version.sh to update the Go toolchain and module
  dependencies, then audits all upstream dependency changes for security
  vulnerabilities, regressions, or API contract hazards that are exploitable
  in tlsproxy or tlsclient. Use when the user asks to update Go dependencies,
  run update-go-version.sh, or audit updated upstream Go libraries.
---

# Update and Audit Go Dependencies

## Overview

This skill updates the Go version and upstream module dependencies using [`scripts/update-go-version.sh`](../../../scripts/update-go-version.sh), extracts the exact source code diffs between the old and new module versions from `GOMODCACHE`, and audits every change for malicious/suspicious code, security vulnerabilities, or subtle behavioral changes before any build or test command is executed.

> [!CAUTION]
> **CRITICAL: Never run `go build`, `go test`, `go run`, or `go generate` BEFORE completing the full source diff audit in Step 3, and NEVER run them if suspicious or malicious code is detected in any dependency.**
> Compiling or testing untrusted dependency updates can execute attacker-controlled code on the host (via `init()` functions, test binaries, CGo, or compiler directives). If suspicious code is found during Step 3, stop immediately, do not build or run tests, and report the finding to the user.

## Workflow

### 1. Check Working Tree & Run `scripts/update-go-version.sh`

1. Check `git status -s` in the repository root:
   - Confirm what baseline git ref (`BASE_REF`, typically `HEAD`) holds the pre-update `go.mod`.
   - If `go.mod` has not yet been updated in the working tree, run:
     ```bash
     ./scripts/update-go-version.sh
     ```
2. Inspect `git diff go.mod CHANGELOG.md Dockerfile .goversion` to see which Go version and modules were updated.
   - Note: `scripts/update-go-version.sh` prepends a new `## next` block to `CHANGELOG.md`. If `CHANGELOG.md` already had a `## next` section, merge the duplicate `## next` heading cleanly.

### 2. Generate Upstream Module Source Diffs

Run the helper script [`scripts/diff-go-deps.sh`](./scripts/diff-go-deps.sh) against the pre-update git ref (`HEAD` if `go.mod` is uncommitted, or `HEAD~1` if the update was already committed):

```bash
./.agents/skills/update-and-audit-deps/scripts/diff-go-deps.sh HEAD /tmp/tlsproxy-dep-audit
```

- The script downloads both the previous and updated versions of each changed module into `GOMODCACHE`, locates every `.go` file in `tlsproxy` and `tlsclient` that imports the module, and writes:
  - `/tmp/tlsproxy-dep-audit/summary.md`: Overview of all changed modules, their `GOMODCACHE` paths, importing files in this repo, and diff line counts.
  - `/tmp/tlsproxy-dep-audit/<module>.diff`: Unified diff of non-test source files between the old and new versions.
- Read `/tmp/tlsproxy-dep-audit/summary.md` first.

### 3. Audit Upstream Changes and `tlsproxy` / `tlsclient` Call Sites

For each upgraded module (delegate to parallel `research` subagents if multiple large diffs exist):

1. **Read the upstream diff** (`/tmp/tlsproxy-dep-audit/<module>.diff`) and the surrounding upstream package code in `GOMODCACHE`.
2. **Read every call site** in `tlsproxy` (`proxy/`, `certmanager/`, `jwks/`) and `tlsclient/` that interacts with the upgraded module.
3. **Evaluate against supply-chain threats and the `tlsproxy` / `tlsclient` threat model**:
   - **Supply-Chain & Suspicious Code Inspection (Must Pass Before Any Build/Test)**:
     - Check for newly added or modified `init()` functions, `os/exec` commands, `syscall` / `unsafe` / `reflect` abuse, `//go:linkname` or `//go:cgo_*` directives, CGo/assembly files, obfuscated strings or encoded payloads (base64/hex blobs), unexpected outbound network calls (`net`, `net/http`), environment variable access (`os.Getenv`, `os.Environ`), or unexpected filesystem reads/writes.
     - **If any suspicious, backdoored, or unexplained code is detected: STOP IMMEDIATELY. Do NOT proceed to Step 4 (`go test` / `go build`).** Alert the user with the exact file path and line numbers in `GOMODCACHE`.
   - **Parsing & Input Validation**:
     - Can malformed network input (TLS `ClientHello` / ECH extensions, QUIC frames/streams, HTTP/1.1, HTTP/2, HTTP/3 pseudo-headers `:path` / `:authority` / `:scheme`, WebSocket control/data frames, PROXY protocol v1/v2 headers, SSH certificates, OCSP responses, JWT/OIDC/SAML tokens, CBOR/WebAuthn passkeys, DNS/DoH responses) trigger panics (slice bounds, nil-pointer dereference, type assertion, divide-by-zero, `close of closed channel`, concurrent map read/write)?
     - Does any parser change introduce request-target / host / path normalization discrepancies that could bypass `Backend.checkRequestHost`, `be.SSO.Rules`, `PathOverrides`, `localHandlers`, or `SanitizePath`?
   - **Cryptographic & Authentication Verification**:
     - Are signatures, certificate chains, key usages (`ExtKeyUsageOCSPSigning`, etc.), validity windows (`NotBefore`/`NotAfter`, `ThisUpdate`/`NextUpdate`, `iat`/`exp`), and issuer/subject bindings still strictly enforced?
   - **Resource Exhaustion & DoS**:
     - Can an unauthenticated or authenticated peer cause unbounded memory allocation (e.g., pre-allocating frame buffers from untrusted length headers or `io.ReadAll` without `io.LimitedReader` / `http.MaxBytesReader`)?
     - Are connection, stream, file-descriptor, or goroutine lifecycles changed in a way that leaks resources on early close, half-close, context cancellation, or error paths?
     - Do rate limiters (`golang.org/x/time/rate`), connection counters (`MaxOpen`, `MaxOpenPerIP`), or locks (`sync.Mutex`) remain bounded under deadline expiration or cancellation?
     - Are idle HTTP connections/transports or background goroutines leaked?

### 4. Build, Test, and Report Findings

> [!IMPORTANT]
> **Only run the build and test commands below if Step 3 confirmed that no suspicious or malicious code was introduced in any dependency diff.** If suspicious code was detected, skip Step 4.1 entirely and report the suspicious code immediately.

1. Run the test suite and build checks (only after all diffs pass inspection):
   ```bash
   go test -count=1 ./...
   GOOS=js GOARCH=wasm go build -o /dev/null ./proxy/internal/pki/clientwasm
   go build -tags noquic -o /dev/null ./...
   ```
2. Present a concise, triaged report of the audit:
   - **Summary Table of Upgraded Modules**: Module name, old -> new version, and audit status.
   - **Triaged Findings (Critical / High / Medium / Low)**:
     - Exact upstream file and line numbers in `GOMODCACHE`
     - Exact `tlsproxy` / `tlsclient` call-site file and line numbers
     - Exploitability preconditions and impact
     - Recommended fix location (`tlsproxy`/`tlsclient`, sibling `github.com/c2FmZQ/*` repository, or upstream third-party library)
