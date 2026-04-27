# Roadmap — Fake RADIUS Server

## Phases

- [ ] **Phase 1: Core Implementation** — RADIUS server with query tool

## Phase Details

### Phase 1: Core Implementation

**Goal**: Users can run a zero-config RADIUS server and test it with a CLI query tool

**Depends on**: Nothing

**Requirements**: RADIUS-01, RADIUS-02, RADIUS-03, RADIUS-04, RADIUS-05, RADIUS-06, AUTH-01, AUTH-02, AUTH-03

**Success Criteria** (what must be TRUE):

1. Server starts on UDP port 1812 when given a shared secret via CLI flag
2. Server returns Access-Accept for usernames NOT starting with `no_`
3. Server returns Access-Reject for usernames starting with `no_`
4. Server validates Message-Authenticator attribute when present in request
5. Server includes Reply-Message attribute in response
6. Query tool sends Access-Request packets from command line
7. Query tool displays full response packet details (code, attributes, raw bytes)

**Plans**: TBD

**UI hint**: no

---

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Core Implementation | 0/1 | Not started | - |
