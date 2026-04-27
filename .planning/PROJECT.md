# Fake RADIUS Server

## What This Is

A lightweight, self-contained RADIUS server for testing RADIUS client devices (Switches, WiFi controllers). The server accepts all authentication requests except usernames prefixed with `no_`, which are rejected.

**Core value:** Zero-config RADIUS server that "just works" for testing.

## What This Is NOT

- A production AAA server
- A full-featured RADIUS implementation with accounting
- A user management system

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go language | Cross-platform, mature RADIUS libraries, single binary | — Pending |
| UDP-only initially | Simplicity — most legacy devices use UDP 1812 | RADSEC/TLS deferrable |
| Simple accept/reject | Testing clients only — no MFA/OTP complexity | — Pending |
| Embedded query tool | One-shot testing without external tools | — Pending |

## Requirements

### Active

- [ ] **RADIUS-01**: Server listens on UDP port 1812 (standard RADIUS)
- [ ] **RADIUS-02**: Server accepts Access-Request packets
- [ ] **RADIUS-03**: Server returns Access-Accept for any username NOT starting with `no_`
- [ ] **RADIUS-04**: Server returns Access-Reject for usernames starting with `no_`
- [ ] **RADIUS-05**: Server validates Message-Authenticator attribute (if present)
- [ ] **RADIUS-06**: Server responds with minimal Reply-Message attribute confirming auth result
- [ ] **AUTH-01**: Query tool can send Access-Request to the server
- [ ] **AUTH-02**: Query tool displays full response packet details
- [ ] **AUTH-03**: Query tool supports username, password, and shared secret arguments

### Out of Scope

- [Access-Challenge / MFA] — Not needed for basic client testing
- [Accounting (RADIUS port 1813)] — Not needed for auth testing
- [RADSEC / TLS] — Can be added if real client requires it
- [User database] — All users accepted except `no_` prefix

## Success Criteria

1. A real WiFi controller or Switch can authenticate against this server using any username except `no_*`
2. `no_*` usernames are consistently rejected
3. Query tool can send test packets and display raw RADIUS response
4. Server starts with zero config file — just run the binary

---
*Last updated: 2026-04-27 after initialization*

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state
