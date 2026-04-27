#!/bin/bash
# Start the Fake RADIUS Server
# Usage: ./start-server.sh [secret]
# Default secret is "testing123" if not provided

SECRET="${1:-testing123}"

echo "Starting Fake RADIUS Server..."
echo "Secret: $SECRET"
echo "Listening on: UDP :1812"
echo ""

./fakeradius-server-linux --secret "$SECRET"
