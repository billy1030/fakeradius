#!/bin/bash
# Start the Fake RADIUS Server
# Usage: ./start-server.sh [secret] [logfile]
# Default secret is "testing123", logfile is "server.log"

SECRET="${1:-testing123}"
LOGFILE="${2:-server.log}"

echo "Starting Fake RADIUS Server..."
echo "Secret: $SECRET"
echo "Log file: $LOGFILE"
echo "Listening on: UDP :1812"
echo ""

./fakeradius-server-linux --secret "$SECRET" --log "$LOGFILE"
