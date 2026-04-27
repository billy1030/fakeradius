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

```cmd
fakeradius-server.exe --secret testing123 --log server.log
```

### Test with CLI

```cmd
radius-cli.exe --username alice --password test --secret testing123
radius-cli.exe --username no_admin --password test --secret testing123
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
| `--addr` | Listen address | `:1812` |
| `--log` | Log file path | console only |

## Features

- RADIUS authentication on UDP port 1812
- Message-Authenticator validation
- Reply-Message in responses
- Timestamped logging to file
- CLI tool for testing
