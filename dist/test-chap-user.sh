#!/bin/bash
# Test CHAP authentication with a normal user (should get Access-Accept)
# Usage: ./test-chap-user.sh [username] [secret] [server]
# Default: username="alice", secret="testing123", server="127.0.0.1:1812"

USERNAME="${1:-alice}"
SECRET="${2:-testing123}"
SERVER="${3:-127.0.0.1:1812}"

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

echo "Testing RADIUS CHAP authentication with normal user..."
echo "Username: $USERNAME"
echo "Server: $SERVER"
echo "Platform: ${OS}-${ARCH}"
echo "Auth Mode: CHAP (high security)"
echo ""

"${BIN_DIR}/radius-cli" --username "$USERNAME" --password "StrongPass123!" --secret "$SECRET" --server "$SERVER" --chap
