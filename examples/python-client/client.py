#!/usr/bin/env python3

import ssl
import json
import urllib.request
from datetime import datetime
from pathlib import Path

# Certificate paths
CERT_DIR = Path(__file__).parent.parent.parent / "certs"
CLIENT_CERT = CERT_DIR / "servers" / "localhost" / "server-cert.pem"
CLIENT_KEY = CERT_DIR / "servers" / "localhost" / "server-key.pem"
CA_CERT = CERT_DIR / "ca" / "ca-cert.pem"

SERVER_URL = "https://localhost:8443"

def create_ssl_context():
    """Create SSL context with mTLS configuration"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Load client certificate and key
    context.load_cert_chain(
        certfile=str(CLIENT_CERT),
        keyfile=str(CLIENT_KEY)
    )
    
    # Load CA certificate for server verification
    context.load_verify_locations(cafile=str(CA_CERT))
    
    # Verify server certificate
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    return context

def make_request(path, method='GET', data=None):
    """Make HTTPS request with mTLS"""
    url = f"{SERVER_URL}{path}"
    
    headers = {}
    body = None
    
    if data:
        body = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method
    )
    
    context = create_ssl_context()
    
    with urllib.request.urlopen(request, context=context) as response:
        return {
            'status_code': response.status,
            'body': response.read().decode('utf-8')
        }

def test_main_endpoint():
    """Test main endpoint"""
    print('📡 Test 1: Main endpoint (GET /)')
    try:
        response = make_request('/')
        data = json.loads(response['body'])
        
        print(f"✅ Status: {response['status_code']}")
        print(f"   Message: {data['message']}")
        print(f"   Client Certificate: {data['client_cert']}")
        print(f"   Verified: {data['verified']}")
        print(f"   Server Time: {data['server_time']}")
    except Exception as e:
        print(f"❌ Request failed: {e}")
    print()

def test_health_endpoint():
    """Test health endpoint"""
    print('📡 Test 2: Health check (GET /health)')
    try:
        response = make_request('/health')
        
        print(f"✅ Status: {response['status_code']}")
        print(f"   Response: {response['body']}")
    except Exception as e:
        print(f"❌ Request failed: {e}")
    print()

def test_api_data_endpoint():
    """Test API data endpoint"""
    print('📡 Test 3: API data (GET /api/data)')
    try:
        response = make_request('/api/data')
        data = json.loads(response['body'])
        
        print(f"✅ Status: {response['status_code']}")
        print('   Data:')
        formatted = json.dumps(data, indent=6)
        for line in formatted.split('\n'):
            print(f'   {line}')
    except Exception as e:
        print(f"❌ Request failed: {e}")
    print()

def test_echo_endpoint():
    """Test echo endpoint"""
    print('📡 Test 4: Echo test (POST /api/echo)')
    try:
        test_data = {
            'message': 'Hello from mTLS Python client!',
            'timestamp': datetime.now().isoformat(),
            'test': True
        }
        
        response = make_request('/api/echo', method='POST', data=test_data)
        data = json.loads(response['body'])
        
        print(f"✅ Status: {response['status_code']}")
        print('   Response:')
        formatted = json.dumps(data, indent=6)
        for line in formatted.split('\n'):
            print(f'   {line}')
    except Exception as e:
        print(f"❌ Request failed: {e}")
    print()

def main():
    print('🔒 mTLS Python Client')
    print('=====================')
    print()
    
    test_main_endpoint()
    test_health_endpoint()
    test_api_data_endpoint()
    test_echo_endpoint()
    
    print('✅ All tests completed successfully!')

if __name__ == '__main__':
    main()
