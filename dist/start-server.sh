#!/bin/bash
# Start the Fake RADIUS & TACACS+ Server
# Usage: ./start-server.sh [options...]
# Example: sudo ./start-server.sh --secret testing123 --tacacs-addr :49

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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "${SCRIPT_DIR}/multi/${OS}-${ARCH}/fakeradius-server" ]; then
  BIN="${SCRIPT_DIR}/multi/${OS}-${ARCH}/fakeradius-server"
elif [ -f "${SCRIPT_DIR}/fakeradius-server" ]; then
  BIN="${SCRIPT_DIR}/fakeradius-server"
elif [ -f "${SCRIPT_DIR}/../dist/multi/${OS}-${ARCH}/fakeradius-server" ]; then
  BIN="${SCRIPT_DIR}/../dist/multi/${OS}-${ARCH}/fakeradius-server"
else
  echo "Error: fakeradius-server binary not found for ${OS}-${ARCH}"
  exit 1
fi

# If no arguments provided, use defaults
if [ $# -eq 0 ]; then
  set -- --secret testing123 --log server.log --tacacs-addr :4949
fi

echo "Starting Fake RADIUS & TACACS+ Server..."
echo "Platform: ${OS}-${ARCH}"
echo "Binary:   ${BIN}"
echo ""

exec "${BIN}" "$@"
