#!/bin/bash
# Test EAP-TTLS authentication WITH CA (Expect TRUSTED)

SECRET=${1:-testing123}
USERNAME=${2:-test}
PASSWORD=${3:-test}

echo "Testing EAP-TTLS WITH CA (ca.pem)..."
echo ""

./multi/linux-amd64/radius-cli --secret "$SECRET" --username "$USERNAME" --password "$PASSWORD" --ttls --ca ca.pem
