const https = require('https');
const fs = require('fs');
const path = require('path');

// Load certificates
const options = {
  key: fs.readFileSync(path.join(__dirname, '../../certs/servers/localhost/server-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../../certs/servers/localhost/server-cert.pem')),
  ca: fs.readFileSync(path.join(__dirname, '../../certs/ca/ca-cert.pem')),
  requestCert: true,
  rejectUnauthorized: true
};

const server = https.createServer(options, (req, res) => {
  const clientCert = req.socket.getPeerCertificate();
  
  // Route handling
  if (req.url === '/' && req.method === 'GET') {
    handleRoot(req, res, clientCert);
  } else if (req.url === '/health' && req.method === 'GET') {
    handleHealth(req, res);
  } else if (req.url === '/api/data' && req.method === 'GET') {
    handleData(req, res, clientCert);
  } else if (req.url === '/api/echo' && req.method === 'POST') {
    handleEcho(req, res, clientCert);
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

function handleRoot(req, res, clientCert) {
  const response = {
    status: 'success',
    message: 'mTLS Node.js Server',
    client_cert: clientCert.subject.CN || 'Unknown',
    server_time: new Date().toISOString(),
    verified: clientCert.authorized
  };
  
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(response, null, 2));
}

function handleHealth(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
}

function handleData(req, res, clientCert) {
  const data = {
    timestamp: new Date().toISOString(),
    client: {
      cn: clientCert.subject.CN || 'Unknown',
      organization: clientCert.subject.O || 'N/A',
      verified: clientCert.authorized
    },
    server: {
      name: 'node-mtls-server',
      version: '1.0.0',
      platform: process.platform,
      nodeVersion: process.version
    },
    data: {
      users: 42,
      requests: 1337,
      uptime: process.uptime()
    }
  };
  
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data, null, 2));
}

function handleEcho(req, res, clientCert) {
  let body = '';
  
  req.on('data', chunk => {
    body += chunk.toString();
  });
  
  req.on('end', () => {
    let receivedData;
    try {
      receivedData = JSON.parse(body);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    
    const response = {
      echo: receivedData,
      metadata: {
        received_at: new Date().toISOString(),
        client_cn: clientCert.subject.CN || 'Unknown',
        content_length: body.length
      }
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response, null, 2));
  });
}

const PORT = process.env.PORT || 8443;

server.listen(PORT, () => {
  console.log('🔒 mTLS Node.js Server');
  console.log('======================');
  console.log(`Server running on https://localhost:${PORT}`);
  console.log('\nEndpoints:');
  console.log('  GET  /          - Main endpoint with client info');
  console.log('  GET  /health    - Health check');
  console.log('  GET  /api/data  - Sample data endpoint');
  console.log('  POST /api/echo  - Echo endpoint');
  console.log('\nPress Ctrl+C to stop');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\nShutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
