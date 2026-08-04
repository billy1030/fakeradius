# FakeRADIUS & FakeTACACS+

**v0.3** - Dual RADIUS + TACACS+ mock AAA server. Verified working with **Palo Alto Networks** firewalls (CHAP auth + authorization AV-pairs).

A lightweight, self-contained mock AAA server for testing RADIUS and TACACS+ authentication clients. Accepts all users except those prefixed with `no_`. No external dependencies - single binary, cross-platform.

## Supported Protocols & Auth Modes

| Protocol | Transport | Auth Types | Standard |
|----------|-----------|------------|----------|
| **RADIUS** | UDP :1812 | PAP, CHAP, MS-CHAP v1/v2, EAP-TTLS | RFC 2865 / 2869 |
| **TACACS+** | TCP :49 / :4949 | ASCII, PAP, CHAP, MS-CHAP | RFC 8907 |

### TACACS+ Authentication Methods

TACACS+ delegates PAP/CHAP negotiation to the NAS device (firewall/switch). The server receives the method type and decides PASS or FAIL:

| authen_type | Value | NAS sends | Server action |
|-------------|-------|-----------|---------------|
| ASCII | `0x01` | Username (may prompt for password) | PASS |
| **PAP** | `0x02` | Username + cleartext password | PASS |
| **CHAP** | `0x03` | Username + CHAP response (ID + MD5) | PASS |
| **MS-CHAP** | `0x04` | Username + MS-CHAP response | PASS |

> As a **fake/testing server**, hash/password verification is intentionally skipped. Any user (except `no_` prefix) is accepted regardless of credential content.

### RADIUS Message Authentication

| Component | Logic | Description |
|-----------|-------|-------------|
| **Shared Secret** | `string` | Common password between client and server |
| **Request Authenticator** | `random(16)` | Random 16-byte value per request |
| **Response Authenticator** | `MD5(Code+ID+Len+ReqAuth+Attrs+Secret)` | Proves response origin |
| **Message-Authenticator** | `HMAC-MD5(Packet, Secret)` | Packet integrity (Attribute 80) |
| **PAP Password** | `Password XOR MD5(Secret + ReqAuth)` | Never sent in cleartext |

## Quick Start

### 1. Start the Server

```bash
# Linux/macOS - auto-detects platform binary
./dist/start-server.sh

# Linux - with explicit flags
./dist/start-server.sh --secret testing123 -a :1812 -t :4949

# Linux - bind to real IP (required for network devices)
sudo ./dist/start-server.sh --secret testing123 -a 192.168.1.100:1812 -t 172.22.30.47:49

# Windows - convenience script
dist\start-server.bat

# Windows - direct binary
dist\multi\windows-amd64\fakeradius-server.exe --secret testing123
```

> **Linux Port 49**: TCP port 49 requires `sudo`. Use `-t :4949` for non-root testing.
> Open firewall ports permanently:
> ```bash
> sudo firewall-cmd --permanent --add-port=1812/udp
> sudo firewall-cmd --permanent --add-port=49/tcp
> sudo firewall-cmd --permanent --add-port=4949/tcp
> sudo firewall-cmd --reload
> ```

### 2. Test with Built-in Scripts

| Script | Auth Mode | Expected Result |
|--------|-----------|-----------------|
| `test-pap-user.sh` | RADIUS PAP | Access-Accept |
| `test-pap-no-user.sh` | RADIUS PAP | Access-Reject |
| `test-chap-user.sh` | RADIUS CHAP | Access-Accept |
| `test-chap-no-user.sh` | RADIUS CHAP | Access-Reject |
| `test-mschap-user.sh` | RADIUS MS-CHAP | Access-Accept |
| `test-mschap-no-user.sh` | RADIUS MS-CHAP | Access-Reject |
| `test-ttls-no-ca.sh` | EAP-TTLS | UNTRUSTED |
| `test-ttls-with-ca.sh` | EAP-TTLS | TRUSTED |
| `test-tacacs-user.sh` | TACACS+ | PASS |
| `test-tacacs-no-user.sh` | TACACS+ | FAIL |

```bash
# Run from the dist/ directory
./test-pap-user.sh alice
./test-tacacs-user.sh peter
./test-tacacs-no-user.sh no_admin
```

### 3. Test with CLI (`radius-cli`)

**RADIUS PAP (default):**
```bash
radius-cli --username alice --password test --secret testing123
```

**RADIUS CHAP:**
```bash
radius-cli --username alice --password StrongPass123! --secret testing123 --chap
```

**RADIUS MS-CHAP:**
```bash
radius-cli --username alice --password StrongPass123! --secret testing123 --mschap
```

**EAP-TTLS:**
```bash
radius-cli --username alice --password test --secret testing123 --ttls --ca ca.pem
```

**TACACS+:**
```bash
radius-cli --server 127.0.0.1:4949 --secret testing123 --username alice --password test --tacacs
```

**Test reject (no_ prefix):**
```bash
radius-cli --username no_admin --password test --secret testing123
radius-cli --server 127.0.0.1:4949 --secret testing123 --username no_admin --password test --tacacs
```

**Test remote server:**
```bash
radius-cli --username alice --password test --secret testing123 --server 172.22.30.47:1812
```

## Auth Behavior

| Username | RADIUS | TACACS+ |
|----------|--------|---------|
| `alice`, `bob`, `peter`, any name | Access-Accept | PASS + PASS_ADD |
| `no_admin`, `no_user`, `no_*` | Access-Reject | FAIL |

## Server Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--secret` | `-s` | Shared secret for RADIUS and TACACS+ | (required) |
| `--addr` | `-a` | RADIUS listen address (UDP) | `:1812` |
| `--tacacs-addr` | `-t` | TACACS+ listen address (TCP) | `:49` |
| `--log` | `-l` | Log file path | console only |
| `--cert` | | TLS certificate path | `cert/server.pem` |
| `--key` | | TLS private key path | `cert/server.key` |

## CLI Options (`radius-cli`)

| Flag | Description | Default |
|------|-------------|---------|
| `--username` | Username for authentication | (required) |
| `--password` | Password for authentication | (required) |
| `--secret` | Shared secret with the server | (required) |
| `--server` | AAA server IP:Port | `127.0.0.1:1812` |
| `--pap` | Use RADIUS PAP | (default) |
| `--chap` | Use RADIUS CHAP | false |
| `--mschap` | Use RADIUS MS-CHAP | false |
| `--ttls` | Use RADIUS EAP-TTLS | false |
| `--tacacs` | Use TACACS+ (TCP) | false |
| `--ca` | CA certificate for EAP-TTLS | - |

## Firewall Compatibility

### Palo Alto Networks - Verified (v0.3)

Full TACACS+ auth + authz verified end-to-end:

```
Authentication to TACACS+ server at 172.22.30.47 for user peter
Attempting CHAP authentication ...
Authorization request sent: service=PaloAlto, protocol=firewall
Authorization succeeded
Authentication succeeded!
```

Configure in PA: **Device > Server Profiles > TACACS+**
- **Server IP**: your server IP
- **Port**: `4949` (or `49` with sudo)
- **Secret**: `testing123`
- **Protocol**: CHAP or PAP

### Cisco IOS

```
aaa new-model
tacacs server FAKE
 address ipv4 172.22.30.47
 port 4949
 key testing123
aaa authentication login default group tacacs+ local
```

### Firewall Rules (Linux firewalld)

```bash
sudo firewall-cmd --permanent --add-port=1812/udp
sudo firewall-cmd --permanent --add-port=49/tcp
sudo firewall-cmd --permanent --add-port=4949/tcp
sudo firewall-cmd --reload
```

### UDP Checksum Offloading (VMware / virtualized)

If you see timeout or invalid authenticator errors in a VM:
```bash
sudo ethtool -K ens33 tx off
```

## Pre-built Binaries

| Platform | Architecture | Path |
|----------|--------------|------|
| Linux | amd64 | `dist/multi/linux-amd64/fakeradius-server` |
| Linux | arm64 | `dist/multi/linux-arm64/fakeradius-server` |
| Windows | amd64 | `dist/multi/windows-amd64/fakeradius-server.exe` |
| Windows | arm64 | `dist/multi/windows-arm64/fakeradius-server.exe` |
| macOS | amd64 | `dist/multi/darwin-amd64/fakeradius-server` |
| macOS | arm64 | `dist/multi/darwin-arm64/fakeradius-server` |

## Build from Source

```bash
git clone https://github.com/billy1030/fakeradius.git
cd fakeradius

# Build for current platform
go build -o fakeradius-server ./cmd/server
go build -o radius-cli ./cmd/cli

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o fakeradius-server-linux ./cmd/server

# Run tests
go test ./pkg/...
```

## Changelog

### v0.3 (2026-08-04)
- Fixed: TACACS+ Authorization request decoder - corrected RFC 8907 field offsets (user_len@[4], arg_cnt@[7])
- Verified: Full auth + authz working with Palo Alto Networks firewall (CHAP + AV-pair mirroring)
- Improved: Authorization log now shows all AV-pairs (service=, protocol=, cmd=)

### v0.2 (2026-08-04)
- Added: TACACS+ protocol support (RFC 8907) on TCP port 49/4949
- Added: TACACS+ Authentication (ASCII, PAP, CHAP, MS-CHAP)
- Added: TACACS+ Authorization with AV-pair mirroring
- Added: Convenience scripts: start-server.sh, start-server.bat, test-tacacs-*.sh
- Fixed: Linux binary path resolution in shell scripts

### v0.1
- Initial RADIUS server with PAP, CHAP, MS-CHAP v1/v2, EAP-TTLS
- Cross-platform CLI test client
- Pre-built binaries for Windows, Linux, macOS

## Disclaimer

This is a **testing tool only**. It is intentionally permissive - use at your own risk in isolated test environments.
