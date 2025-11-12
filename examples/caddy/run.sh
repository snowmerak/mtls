#!/bin/bash

# Run Caddy with mTLS configuration

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting Caddy with mTLS configuration...${NC}"
echo ""

# Check if certificates exist
if [ ! -f "../../certs/servers/localhost/server-cert.pem" ]; then
    echo "Error: Server certificate not found!"
    echo "Please generate certificates first:"
    echo ""
    echo "  cd ../.."
    echo "  ./mtls ca create --batch --cn \"Example CA\" --key-type rsa4096"
    echo "  ./mtls cert create --batch --ca ./certs/ca --cn \"localhost\" --dns \"localhost,127.0.0.1\" --ip \"127.0.0.1\" --key-type rsa2048"
    echo ""
    exit 1
fi

# Check if Caddy is installed
if ! command -v caddy &> /dev/null; then
    echo "Error: Caddy is not installed!"
    echo "Please install Caddy: https://caddyserver.com/docs/install"
    exit 1
fi

echo -e "${GREEN}✓ Certificates found${NC}"
echo -e "${GREEN}✓ Caddy installed${NC}"
echo ""
echo "Server will start on: https://localhost:8443"
echo ""
echo "Test with:"
echo "  curl --cert ../../certs/servers/localhost/server-cert.pem \\"
echo "       --key ../../certs/servers/localhost/server-key.pem \\"
echo "       --cacert ../../certs/ca/ca-cert.pem \\"
echo "       https://localhost:8443"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run Caddy
caddy run --config Caddyfile
