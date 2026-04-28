# FakeRADIUS

A lightweight, self-contained RADIUS server for testing authentication clients. Supports **PAP**, **CHAP**, and **MS-CHAP** authentication modes.

## Overview

FakeRADIUS accepts all authentication requests except usernames prefixed with `no_`. Designed for testing RADIUS client devices such as switches, WiFi controllers, and enterprise authentication systems.

## Supported Authentication Modes

| Mode | CLI Flag | Security | Use Case |
|------|---------|----------|----------|
| PAP | (default) | Basic | Legacy compatibility |
| CHAP | `--chap` | High | Enterprise WiFi (RFC 1994) |
| MS-CHAP v2 | `--mschap` | High | Windows AD, enterprise (RFC 2759) |

## Binaries

Pre-built binaries for all platforms are in `dist/multi/`:

| Platform | Architecture | Location |
|----------|--------------|----------|
| Windows | amd64, arm64 | `dist/multi/windows-{amd64,arm64}/` |
| Linux | amd64, arm64 | `dist/multi/linux-{amd64,arm64}/` |
| macOS | amd64, arm64 | `dist/multi/darwin-{amd64,arm64}/` |

### Quick Start Scripts

Test scripts for each authentication mode:

| Script | Auth Mode | Expected Result |
|--------|-----------|-----------------|
| `test-pap-user` | PAP | Access-Accept |
| `test-pap-no-user` | PAP | Access-Reject |
| `test-chap-user` | CHAP | Access-Accept |
| `test-chap-no-user` | CHAP | Access-Reject |
| `test-mschap-user` | MS-CHAP | Access-Accept |
| `test-mschap-no-user` | MS-CHAP | Access-Reject |

Usage:
```bash
# Start server
./start-server.sh testing123

# In another terminal, run tests
./test-pap-user.sh alice
./test-chap-user.sh alice
./test-mschap-user.sh alice
```

## Quick Start

### Start the Server

```bash
# Linux/macOS
./dist/multi/linux-amd64/fakeradius-server --secret testing123 --log server.log

# Windows
dist\multi\windows-amd64\fakeradius-server.exe --secret testing123 --log server.log
```

Listen on specific IP and port:
```bash
fakeradius-server --secret testing123 --addr 192.168.1.100:1812 --log server.log
```

### Test with CLI

**PAP (default):**
```bash
radius-cli --username alice --password test --secret testing123
```

**CHAP:**
```bash
radius-cli --username alice --password StrongPass123! --secret testing123 --chap
```

**MS-CHAP:**
```bash
radius-cli --username alice --password StrongPass123! --secret testing123 --mschap
```

**Test rejected user (no_ prefix):**
```bash
radius-cli --username no_admin --password test --secret testing123
```

**Test remote server:**
```bash
radius-cli --username alice --password test --secret testing123 --server 192.168.1.100:1812
```

## Behavior

| Username | Response |
|----------|----------|
| `alice`, `bob`, `admin`, any name | Access-Accept |
| `no_*` prefix (e.g., `no_admin`, `no_peter`) | Access-Reject |

## Server Options

| Flag | Description | Default |
|------|-------------|---------|
| `--secret` | Shared secret (required) | - |
| `--addr` | Listen address (IP:Port) | `:1812` |
| `--log` | Log file path | console only |

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--username` | Username for authentication (required) | - |
| `--password` | Password for authentication (required) | - |
| `--secret` | Shared secret with the server (required) | - |
| `--server` | RADIUS server IP:Port | `127.0.0.1:1812` |
| `--chap` | Use CHAP authentication | false |
| `--mschap` | Use MS-CHAP authentication | false |

## Features

- RADIUS authentication on UDP port 1812
- **PAP** (Password Authentication Protocol)
- **CHAP** (Challenge-Handshake) with MD5 validation
- **MS-CHAP v1/v2** (Microsoft CHAP) for Windows AD integration
- Message-Authenticator validation
- Reply-Message in responses
- Timestamped logging to file
- Cross-platform CLI tool for testing (Windows, Linux, macOS)
