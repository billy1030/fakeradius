#!/bin/sh
# Test TACACS+ authentication with a rejected user (no_ prefix, should get FAIL)
# Usage: ./test-tacacs-no-user.sh [username] [secret] [server]

USERNAME="${1:-no_admin}"
SECRET="${2:-testing123}"
SERVER="${3:-127.0.0.1:4949}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Testing TACACS+ authentication with rejected user (no_ prefix)..."
echo "Username: $USERNAME"
echo "Server: $SERVER"
echo "Protocol: TACACS+ (TCP)"
echo

"$SCRIPT_DIR/multi/linux-amd64/radius-cli" --username "$USERNAME" --password testpass123 --secret "$SECRET" --server "$SERVER" --tacacs
