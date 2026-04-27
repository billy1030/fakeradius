#!/bin/bash
# Test with a normal user (should get Access-Accept)
# Usage: ./test-normal-user.sh [username] [secret]
# Default: username="alice", secret="testing123"

USERNAME="${1:-alice}"
SECRET="${2:-testing123}"
SERVER="${3:-127.0.0.1:1812}"

echo "Testing RADIUS authentication with normal user..."
echo "Username: $USERNAME"
echo "Server: $SERVER"
echo ""

./radius-cli-linux --username "$USERNAME" --password "testpass123" --secret "$SECRET" --server "$SERVER"
