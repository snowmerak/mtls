#!/bin/bash

# Test script for mTLS examples

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  mTLS Examples Test Suite${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check if certificates exist
echo -e "${YELLOW}Checking certificates...${NC}"
if [ ! -f "certs/ca/ca-cert.pem" ]; then
    echo -e "${RED}✗ CA certificate not found${NC}"
    echo "Generating certificates..."
    
    ./mtls ca create --batch --cn "Test CA" --key-type rsa4096
    echo -e "${GREEN}✓ CA created${NC}"
fi

if [ ! -f "certs/servers/localhost/server-cert.pem" ]; then
    echo -e "${RED}✗ Server certificate not found${NC}"
    echo "Generating server certificate..."
    
    ./mtls cert create --batch \
        --ca ./certs/ca \
        --cn "localhost" \
        --dns "localhost,127.0.0.1" \
        --ip "127.0.0.1" \
        --key-type rsa2048
    
    echo -e "${GREEN}✓ Server certificate created${NC}"
else
    echo -e "${GREEN}✓ Certificates found${NC}"
fi

echo ""
echo -e "${YELLOW}Building examples...${NC}"

# Build Go server
cd examples/go-server
go build -o server main.go
echo -e "${GREEN}✓ Go server built${NC}"
cd ../..

# Build Go client
cd examples/go-client
go build -o client main.go
echo -e "${GREEN}✓ Go client built${NC}"
cd ../..

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Test 1: Go Server + Go Client${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Start Go server in background
cd examples/go-server
./server > server.log 2>&1 &
SERVER_PID=$!
cd ../..

echo -e "${YELLOW}Server started (PID: $SERVER_PID)${NC}"
echo "Waiting for server to start..."
sleep 2

# Run Go client
echo -e "${YELLOW}Running client tests...${NC}"
cd examples/go-client
./client
CLIENT_EXIT=$?
cd ../..

# Stop server
echo ""
echo -e "${YELLOW}Stopping server...${NC}"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

if [ $CLIENT_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Test passed${NC}"
else
    echo -e "${RED}✗ Test failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Test 2: cURL Test${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Start Go server again
cd examples/go-server
./server > server.log 2>&1 &
SERVER_PID=$!
cd ../..

echo "Waiting for server to start..."
sleep 2

# Test with curl
echo -e "${YELLOW}Testing with curl...${NC}"
CURL_OUTPUT=$(curl --silent \
    --cert certs/servers/localhost/server-cert.pem \
    --key certs/servers/localhost/server-key.pem \
    --cacert certs/ca/ca-cert.pem \
    https://localhost:8443)

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ cURL test passed${NC}"
    echo "Response:"
    echo "$CURL_OUTPUT" | head -3
else
    echo -e "${RED}✗ cURL test failed${NC}"
fi

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  All tests completed!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "You can now:"
echo "  1. Run the Go server: cd examples/go-server && ./server"
echo "  2. Run the Go client: cd examples/go-client && ./client"
echo "  3. Run Caddy: cd examples/caddy && ./run.sh"
echo ""
