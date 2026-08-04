#!/bin/sh
# Test TACACS+ authentication with a normal user (should get PASS)
# Usage: ./test-tacacs-user.sh [username] [secret] [server]

USERNAME="${1:-peter}"
SECRET="${2:-testing123}"
SERVER="${3:-127.0.0.1:4949}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Testing TACACS+ authentication with normal user..."
echo "Username: $USERNAME"
echo "Server: $SERVER"
echo "Protocol: TACACS+ (TCP)"
echo

"$SCRIPT_DIR/multi/linux-amd64/radius-cli" --username "$USERNAME" --password testpass123 --secret "$SECRET" --server "$SERVER" --tacacs
