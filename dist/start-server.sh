#!/bin/bash
# Start the Fake RADIUS Server
# Usage: ./start-server.sh [secret] [logfile]
# Default secret is "testing123", logfile is "server.log"

SECRET="${1:-testing123}"
LOGFILE="${2:-server.log}"

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin*) OS="darwin" ;;
  linux*)  OS="linux" ;;
  *)       echo "Unsupported OS: $OS"; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BIN_DIR="$(dirname "$0")/multi/${OS}-${ARCH}"

echo "Starting Fake RADIUS & TACACS+ Server..."
echo "Secret: $SECRET"
echo "Log file: $LOGFILE"
echo "Platform: ${OS}-${ARCH}"
echo "RADIUS Listening:  UDP :1812"
echo "TACACS+ Listening: TCP :49 (use --tacacs-addr :4949 if non-root)"
echo "Auth Modes: PAP, CHAP, MS-CHAP v1/v2, EAP-TTLS, TACACS+"
echo ""

"${BIN_DIR}/fakeradius-server" --secret "$SECRET" --log "$LOGFILE" --tacacs-addr :4949
