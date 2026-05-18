# FakeRADIUS — Workspace Scan & Audit (debug0001)

## Project Overview

- **Name**: FakeRADIUS
- **Language**: Go 1.21
- **Module**: `github.com/fakeradius/fakeradius`
- **Dependency**: `github.com/spf13/pflag v1.0.10`
- **Purpose**: Lightweight RADIUS server + CLI for testing authentication clients. Accepts all auth requests except usernames with `no_` prefix.

---

## Directory Tree

```
.
├── .claude/                 # Claude config/skills
├── .git/
├── .gitignore
├── .planning/               # GSD planning artifacts
├── AGENTS.md                # Agent instructions
├── CLAUDE.md                # Claude-specific config
├── README.md
├── cmd/
│   ├── cli/
│   │   ├── main.go          # CLI entry point — flag parsing, auth mode dispatch
│   │   └── radius-cli.go    # RADIUS client impl (575 lines) — PAP/CHAP/MS-CHAP wire protocol
│   └── server/
│       ├── main.go          # Server entry point — UDP listener, packet dispatch (308 lines)
│       ├── handler.go       # Packet building, MA validation, auth logic (633 lines)
│       └── handler_test.go  # Tests — hasNoPrefix, ServeRadius, buildAttribute, hasMessageAuthenticator
├── dist/                    # Pre-built platform binaries
├── go.mod
├── go.sum
├── review/                  # Standalone/reference copies
│   ├── debug.md             # Extensive debugging history (350 lines)
│   ├── handler.go
│   ├── handler_test.go
│   └── main.go
├── server.exe               # Pre-built binary
└── session_20260514_112206.json
```

---

## Auth Logic (intended)

| Username    | Response      |
|-------------|---------------|
| alice, bob, admin, any | Access-Accept |
| no_* prefix | Access-Reject  |

Works for all three modes — PAP, CHAP, MS-CHAP.

---

## Key Source Files

### `cmd/cli/main.go`
- `pflag`-based CLI flags: `--server`, `--secret`, `--username`, `--password`, `--chap`, `--mschap`
- Dispatches to PAP (default), CHAP (`--chap`), or MS-CHAP (`--mschap`)
- Validates required flags: `--secret`, `--username`, `--password`

### `cmd/cli/radius-cli.go`
- **PAP** (`SendAccessRequest`): Encrypts password via XOR with `MD5(secret + authenticator)` per RFC 2865
- **CHAP** (`SendCHAPAccessRequest`): Generates 16-byte challenge, computes `MD5(chapID + password + challenge)`, builds CHAP-Response attribute (Type 61)
- **MS-CHAP** (`SendMSCHAPAccessRequest`): Builds Vendor-Specific attribute (Type 26, Microsoft vendor ID 311) with random 24-byte NT-Response
- **Message-Authenticator**: HMAC-MD5 per RFC 2869
- **Packet structure**: 1 byte Code + 1 ID + 2 Length + 16 Authenticator + attributes, sent over UDP

### `cmd/server/main.go`
- Flags: `--secret` (required), `--addr` (default `:1812`), `--log` (file path)
- **Dual Logger**: Timestamped output to console + optional log file
- **UDP Listener**: 1-second read deadline for signal checking (SIGINT/SIGTERM)
- **Auth detection**: Attribute-based — CHAP (Type 60/61), MS-CHAP (Type 26, vendor 311), else PAP
- **Packet safety**: `packet[:length]` slicing to discard UDP padding; bounds check on declared length

### `cmd/server/handler.go`
- **`Handler.ServeRadius`**: Accepts all except `no_*` prefix — works correctly
- **`hasMessageAuthenticator`**: Scans packet attributes for Type 80
- **`validateMessageAuthenticator`**: Zeroes MA, computes `HMAC-MD5(code + id + len + reqAuth + attrs-with-zeroed-MA, secret)`, compares
- **`buildResponsePacket`**:
  - Step 1: Build Reply-Message attribute
  - Step 2 (if request had MA): Temporary response authenticator → real MA via HMAC-MD5 → append
  - Step 3: Final Response Authenticator = `MD5(code + id + len + reqAuth + attrs + secret)`
- **CHAP validation**: `validateCHAPResponse` recomputes `MD5(chapID + password + challenge)`
- **MS-CHAP parsing**: Vendor-Specific attribute → `MSCHAPData` (PeerChallenge, Response, Flags, Name)
- **`validateMSCHAPResponse`**: Checks Name matches username, response ≥ 24 bytes

---

## ~~🔴 Bug 1 — `no_` prefix rejection bypassed in CHAP mode~~ ✅ FIXED

**File**: `cmd/server/handler.go:478-492`

**Fix**: Moved the `hasNoPrefix` check to the top of `ServeRadiusWithCHAP`, before the nil guard. Removed the dead `password` parameter. The prefix check now always runs, regardless of whether CHAP data is present.

Before:
```go
if chapResponse == nil || challenge == nil {
    if username != "" && hasNoPrefix(username) {
        return AccessReject, "User not allowed"
    }
    return AccessAccept, "Authentication accepted"
}
testPassword := []byte(username)
```

After:
```go
if username != "" && hasNoPrefix(username) {
    return AccessReject, "User not allowed"
}
if chapResponse == nil || challenge == nil {
    return AccessAccept, "Authentication accepted"
}
```

---

## ~~🔴 Bug 2 — `no_` prefix rejection bypassed in MS-CHAP mode~~ ✅ FIXED

**File**: `cmd/server/handler.go:621-632`

**Fix**: Moved `hasNoPrefix` to the top of `ServeRadiusWithMSCHAP`, before the `mschap == nil` guard.

Before:
```go
if mschap == nil {
    if username != "" && hasNoPrefix(username) {
        return AccessReject, "User not allowed"
    }
    return AccessAccept, "Authentication accepted"
}
```

After:
```go
if username != "" && hasNoPrefix(username) {
    return AccessReject, "User not allowed"
}
if mschap == nil {
    return AccessAccept, "Authentication accepted"
}
```

---

## ~~🔴 Bug 3 — `encryptPassword` truncates to unpadded length~~ ✅ FIXED

**File**: `cmd/cli/radius-cli.go:335-360`

**Fix**: Changed `return result[:len(password)]` to `return result`, returning the full padded encrypted value per RFC 2865 Section 5.2.

Before: `return result[:len(password)]`
After: `return result`

---

## ~~🟡 Issue 4 — Unused `password` parameter in `ServeRadiusWithCHAP`~~ ✅ FIXED

**File**: `cmd/server/handler.go:479`, `cmd/server/main.go:218`

**Fix**: Removed the `password []byte` parameter from `ServeRadiusWithCHAP` and updated the caller in `main.go` to pass only 3 args.

`handler.go`: `func (h *Handler) ServeRadiusWithCHAP(username string, chapResponse, challenge []byte)`
`main.go`: `handler.ServeRadiusWithCHAP(username, chapResponse, chapChallenge)`

---

## ~~🟡 Issue 5 — Silent error swallowing~~ ✅ FIXED

**File**: `cmd/server/main.go:209-216`

**Fix**: Both MS-CHAP and CHAP extraction/parsing errors are now logged via `logger.Print()`:

```go
mschapData, err := extractMSCHAPAttribute(packet)
if err != nil {
    logger.Print("[%s] MS-CHAP extraction error: %v", clientAddr, err)
}
var parsedMSCHAP *MSCHAPData
if err == nil {
    parsedMSCHAP, err = parseMSCHAPData(mschapData)
    if err != nil {
        logger.Print("[%s] MS-CHAP parse error: %v", clientAddr, err)
    }
}
```

---

## ~~🟡 Issue 6 — Missing bounds checks in attribute iteration~~ ✅ FIXED

**Files**: `cmd/server/handler.go:217`, `cmd/server/handler.go:456`, `cmd/server/handler.go:600`

**Fix**: Added `pos+attrLen > len(packet)` check alongside the existing `attrLen < 2` check in all three functions:

Before: `if attrLen < 2 { break }`
After: `if attrLen < 2 || pos+attrLen > len(packet) { break }`

Affected functions:
- `hasMessageAuthenticator` (handler.go)
- `hasCHAPAttributes` (handler.go)
- `hasMSCHAPAttributes` (handler.go)

---

## Summary of current state

All bugs found in this audit have been fixed. See git diff for the full patch.

| Component | Status |
|-----------|--------|
| PAP auth logic | ✅ Correct |
| CHAP auth no_ bypass | ✅ Fixed |
| MS-CHAP auth no_ bypass | ✅ Fixed |
| encryptPassword padding | ✅ Fixed — full padded return |
| Attribute parsing bounds | ✅ Fixed — consistent checks |
| Error handling | ✅ Fixed — logged instead of silent |
| Code duplication | 🟡 review/ dir duplicates cmd/server/ logic |
