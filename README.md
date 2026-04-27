# FakeRADIUS

A lightweight RADIUS server for testing authentication clients.

## Overview

FakeRADIUS accepts all authentication requests except usernames prefixed with `no_`. Designed for testing RADIUS client devices such as switches and WiFi controllers.

## Binaries

| File | Platform |
|------|----------|
| `fakeradius-server.exe` | Windows x86-64 |
| `radius-cli.exe` | Windows x86-64 |
| `fakeradius-server-linux` | Linux x86-64 |
| `radius-cli-linux` | Linux x86-64 |
| `fakeradius-server-linux-arm64` | Linux ARM64 |
| `radius-cli-linux-arm64` | Linux ARM64 |

## Quick Start

### Start the Server

Listen on all interfaces:
```cmd
fakeradius-server.exe --secret testing123 --log server.log
```

Listen on specific IP and port:
```cmd
fakeradius-server.exe --secret testing123 --addr 192.168.1.100:1812 --log server.log
```

### Test with CLI

Test local server (default: 127.0.0.1:1812):
```cmd
radius-cli.exe --username alice --password test --secret testing123
radius-cli.exe --username no_admin --password test --secret testing123
```

Test remote server with IP and port:
```cmd
radius-cli.exe --username alice --password test --secret testing123 --server 192.168.1.100:1812
```

## Behavior

| Username | Response |
|----------|----------|
| `alice`, `bob`, any name | Access-Accept |
| `no_*` prefix (e.g., `no_admin`) | Access-Reject |

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

## Features

- RADIUS authentication on UDP port 1812
- Message-Authenticator validation
- Reply-Message in responses
- Timestamped logging to file
- CLI tool for testing
