#!/bin/bash
# Test EAP-TTLS authentication WITHOUT CA (Expect UNTRUSTED)

SECRET=${1:-testing123}
USERNAME=${2:-test}
PASSWORD=${3:-test}

echo "Testing EAP-TTLS without CA..."
echo ""

./multi/linux-amd64/radius-cli --secret "$SECRET" --username "$USERNAME" --password "$PASSWORD" --ttls
