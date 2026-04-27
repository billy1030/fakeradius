# FakeRADIUS

A lightweight RADIUS server for testing authentication clients.

## Overview

FakeRADIUS accepts all authentication requests except usernames prefixed with `no_`. Designed for testing RADIUS client devices such as switches and WiFi controllers.

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

## Features

- RADIUS authentication on UDP port 1812
- Message-Authenticator validation
- Reply-Message in responses
- Timestamped logging to file
- CLI tool for testing

## Files

| File | Description |
|------|-------------|
| `fakeradius-server` | RADIUS server binary |
| `radius-cli` | CLI testing tool |
| `start-server` | Script to start server |
| `test-normal-user` | Test script for normal users |
| `test-no-user` | Test script for rejected users |
