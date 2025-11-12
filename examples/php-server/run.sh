#!/bin/bash

# Certificate paths
CERT_DIR="$(dirname "$0")/../../certs"
SERVER_CERT="$CERT_DIR/servers/localhost/server-cert.pem"
SERVER_KEY="$CERT_DIR/servers/localhost/server-key.pem"
CA_CERT="$CERT_DIR/ca/ca-cert.pem"

PORT=8443

echo "🔒 mTLS PHP Server"
echo "=================="
echo "Server running on https://localhost:$PORT"
echo ""
echo "Endpoints:"
echo "  GET  /          - Main endpoint with client info"
echo "  GET  /health    - Health check"
echo "  GET  /api/data  - Sample data endpoint"
echo "  POST /api/echo  - Echo endpoint"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run PHP built-in server with SSL
php -S localhost:$PORT \
    -t "$(dirname "$0")" \
    server.php
