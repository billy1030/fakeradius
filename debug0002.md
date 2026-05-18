# FakeRADIUS — Protocol Audit & Robustness (debug0002)

## Audit Overview

Following persistent `Message-Authenticator validation failed` reports from a firewall client, a deep audit of the RADIUS wire protocol implementation was conducted. This session focused on RFC 2865 (RADIUS) and RFC 2869 (RADIUS Extensions) compliance, specifically regarding authenticator calculations in response packets.

---

## Key Findings

### 1. Message-Authenticator Validation (Incoming)
- **Status**: ✅ **RFC 2869 Compliant**
- **Verification**: Manual re-calculation of HMAC-MD5 for captured failing packets (using `testing123`) matched the server's expected hash exactly.
- **Root Cause**: The mismatch in the logs was confirmed to be a **Shared Secret mismatch** on the client device (NAS), as PAP password decryption also failed with the same secret.

### 2. Response Authenticator Circular Dependency (Outgoing)
- **Status**: 🔴 **BUG FOUND & FIXED**
- **Issue**: The server was recalculating the Response Authenticator *after* inserting the Message-Authenticator.
- **RFC Conflict**: RFC 2869 requires the MA to be calculated over the packet with a zeroed MA field *and* the Response Authenticator in the header. Recalculating the header after the MA is set invalidates the MA.
- **Fix**: The Response Authenticator is now calculated once with zeroed MA and reused for both the header and the HMAC calculation.

### 3. Attribute Ordering for Firewalls
- **Status**: 🟡 **IMPROVED**
- **Issue**: Some strict firewalls (Palo Alto, Fortinet) require the `Message-Authenticator` (Type 80) to be the **first** attribute in the packet (RFC 5080).
- **Fix**: Refactored `buildResponsePacket` to always prepend the MA attribute to the start of the response attributes list.

---

## Bug Fixes & Improvements

### 🔴 Bug 1 — Response Authenticator Circular Dependency ✅ FIXED

**File**: `cmd/server/handler.go`

**Issue**: The calculation of the MD5 Response Authenticator was being performed twice—once for the MA calculation and once for the final packet. The second calculation included the non-zero MA, which changed the header and invalidated the MA signature.

**Fix**:
```go
// 1. Calculate Response Authenticator with zeroed MA
respAuth = md5.Sum(authData)

if needsMA {
    // 2. Calculate MA using the above respAuth
    realMA := calculateMessageAuthenticator(..., respAuth[:], ...)
    // 3. Insert real MA into attributes
    copy(attributes[2:18], realMA)
}

// 4. Use the original respAuth in the final header
copy(packet[4:20], respAuth[:])
```

---

### 🔴 Bug 2 — Message-Authenticator Attribute Position ✅ FIXED

**File**: `cmd/server/handler.go`

**Issue**: The server was appending the MA attribute to the end of the list. RFC 5080 and many hardware vendors expect it to be the first attribute.

**Fix**: Updated `buildResponsePacket` to initialize the attributes slice with the Message-Authenticator placeholder if the request requires it.

---

### 🟡 Improvement 3 — Robust Attribute Preservation ✅ FIXED

**File**: `cmd/server/handler.go`

**Issue**: `replaceOrAddMA` was discarding trailing "junk" bytes or UDP padding during the attribute scanning loop. If a client calculated its MA over a padded packet, the server would fail to match it.

**Fix**: Added logic to `replaceOrAddMA` to explicitly preserve all remaining bytes in the buffer when a مالformed attribute or end-of-buffer is encountered.

---

## Final Status Table

| Protocol Feature | Status | RFC Reference |
|------------------|--------|---------------|
| Request MA Validation | ✅ Verified | RFC 2869 |
| Response MA Calculation | ✅ Fixed | RFC 2869 |
| Response Auth Calculation | ✅ Fixed | RFC 2865 |
| Attribute Ordering | ✅ Prepend MA | RFC 5080 |
| UDP Padding Handling | ✅ Preserved | Robustness |
| Binary Distribution | ✅ Rebuilt | Cross-platform |

---

## Action Items for User
1. **Deploy New Binary**: Use the updated binary from `dist/multi/linux-amd64/` to ensure the Response Authenticator fix is active.
2. **Verify Secret**: If `Message-Authenticator validation failed` persists on the *server* log for Access-Request, double-check for trailing spaces or case-sensitivity in the NAS secret configuration.
