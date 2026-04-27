# Requirements — Fake RADIUS Server

## v1 Requirements

### RADIUS Server

- [ ] **RADIUS-01**: Server listens on UDP port 1812 (standard RADIUS authentication port)
- [ ] **RADIUS-02**: Server accepts Access-Request packets from any client
- [ ] **RADIUS-03**: Server returns Access-Accept for any username NOT starting with `no_`
- [ ] **RADIUS-04**: Server returns Access-Reject for usernames starting with `no_`
- [ ] **RADIUS-05**: Server validates Message-Authenticator attribute if present (standard RADIUS security)
- [ ] **RADIUS-06**: Server responds with Reply-Message attribute confirming auth result

### Query Tool

- [ ] **AUTH-01**: Query tool can send Access-Request to the server via command line
- [ ] **AUTH-02**: Query tool displays full response packet details (code, attributes, raw bytes)
- [ ] **AUTH-03**: Query tool accepts username, password, and shared secret as arguments

## v2 Requirements (Deferred)

- [ ] **RADSEC-01**: Support TLS/RADSEC for environments requiring encrypted RADIUS
- [ ] **ACCT-01**: Basic RADIUS Accounting support on port 1813

## Out of Scope

| Exclusion | Reason |
|-----------|--------|
| Access-Challenge / MFA | Not needed for basic client testing |
| User database | All users accepted except `no_` prefix |
| Configuration file | Zero-config is the goal — shared secret passed via CLI |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| RADIUS-01 | Phase 1 | — |
| RADIUS-02 | Phase 1 | — |
| RADIUS-03 | Phase 1 | — |
| RADIUS-04 | Phase 1 | — |
| RADIUS-05 | Phase 1 | — |
| RADIUS-06 | Phase 1 | — |
| AUTH-01 | Phase 1 | — |
| AUTH-02 | Phase 1 | — |
| AUTH-03 | Phase 1 | — |
