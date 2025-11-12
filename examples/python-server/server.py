#!/usr/bin/env python3

import ssl
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Certificate paths
CERT_DIR = Path(__file__).parent.parent.parent / "certs"
SERVER_CERT = CERT_DIR / "servers" / "localhost" / "server-cert.pem"
SERVER_KEY = CERT_DIR / "servers" / "localhost" / "server-key.pem"
CA_CERT = CERT_DIR / "ca" / "ca-cert.pem"

class MTLSRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to add custom logging"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

    def get_client_cert_info(self):
        """Extract client certificate information"""
        try:
            cert = self.connection.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                return {
                    'cn': subject.get('commonName', 'Unknown'),
                    'organization': subject.get('organizationName', 'N/A'),
                    'verified': True
                }
        except Exception as e:
            print(f"Error getting client cert: {e}")
        
        return {
            'cn': 'Unknown',
            'organization': 'N/A',
            'verified': False
        }

    def send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def send_text_response(self, status_code, text):
        """Send plain text response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(text.encode())

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            self.handle_root()
        elif self.path == '/health':
            self.handle_health()
        elif self.path == '/api/data':
            self.handle_data()
        else:
            self.send_json_response(404, {'error': 'Not found'})

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/api/echo':
            self.handle_echo()
        else:
            self.send_json_response(404, {'error': 'Not found'})

    def handle_root(self):
        """Main endpoint with client info"""
        client_info = self.get_client_cert_info()
        response = {
            'status': 'success',
            'message': 'mTLS Python Server',
            'client_cert': client_info['cn'],
            'server_time': datetime.now().isoformat(),
            'verified': client_info['verified']
        }
        self.send_json_response(200, response)

    def handle_health(self):
        """Health check endpoint"""
        self.send_text_response(200, 'OK')

    def handle_data(self):
        """API data endpoint"""
        import platform
        import sys
        
        client_info = self.get_client_cert_info()
        data = {
            'timestamp': datetime.now().isoformat(),
            'client': client_info,
            'server': {
                'name': 'python-mtls-server',
                'version': '1.0.0',
                'platform': platform.system(),
                'python_version': sys.version.split()[0]
            },
            'data': {
                'users': 42,
                'requests': 1337,
                'status': 'healthy'
            }
        }
        self.send_json_response(200, data)

    def handle_echo(self):
        """Echo endpoint"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            received_data = json.loads(body.decode())
            
            client_info = self.get_client_cert_info()
            response = {
                'echo': received_data,
                'metadata': {
                    'received_at': datetime.now().isoformat(),
                    'client_cn': client_info['cn'],
                    'content_length': content_length
                }
            }
            self.send_json_response(200, response)
        except json.JSONDecodeError:
            self.send_json_response(400, {'error': 'Invalid JSON'})
        except Exception as e:
            self.send_json_response(500, {'error': str(e)})

def create_ssl_context():
    """Create SSL context with mTLS configuration"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Load server certificate and key
    context.load_cert_chain(
        certfile=str(SERVER_CERT),
        keyfile=str(SERVER_KEY)
    )
    
    # Load CA certificate for client verification
    context.load_verify_locations(cafile=str(CA_CERT))
    
    # Require and verify client certificate
    context.verify_mode = ssl.CERT_REQUIRED
    
    return context

def main():
    host = 'localhost'
    port = 8443
    
    # Create HTTP server
    server = HTTPServer((host, port), MTLSRequestHandler)
    
    # Wrap with SSL
    server.socket = create_ssl_context().wrap_socket(
        server.socket,
        server_side=True
    )
    
    print('🔒 mTLS Python Server')
    print('=====================')
    print(f'Server running on https://{host}:{port}')
    print('\nEndpoints:')
    print('  GET  /          - Main endpoint with client info')
    print('  GET  /health    - Health check')
    print('  GET  /api/data  - Sample data endpoint')
    print('  POST /api/echo  - Echo endpoint')
    print('\nPress Ctrl+C to stop')
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n\nShutting down gracefully...')
        server.shutdown()
        print('Server closed')

if __name__ == '__main__':
    main()
