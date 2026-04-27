#!/bin/bash
# Test with a "no_" prefixed user (should get Access-Reject)
# Usage: ./test-no-user.sh [username] [secret]
# Default: username="no_admin", secret="testing123"

USERNAME="${1:-no_admin}"
SECRET="${2:-testing123}"
SERVER="${3:-127.0.0.1:1812}"

echo "Testing RADIUS authentication with no_ prefix user..."
echo "Username: $USERNAME (should be REJECTED)"
echo "Server: $SERVER"
echo ""

./radius-cli-linux --username "$USERNAME" --password "testpass123" --secret "$SECRET" --server "$SERVER"
