const https = require('https');
const fs = require('fs');
const path = require('path');

// Load certificates
const options = {
  key: fs.readFileSync(path.join(__dirname, '../../certs/servers/localhost/server-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../../certs/servers/localhost/server-cert.pem')),
  ca: fs.readFileSync(path.join(__dirname, '../../certs/ca/ca-cert.pem')),
  rejectUnauthorized: true
};

const SERVER_URL = 'localhost';
const SERVER_PORT = 8443;

function makeRequest(path, method = 'GET', data = null) {
  return new Promise((resolve, reject) => {
    const requestOptions = {
      hostname: SERVER_URL,
      port: SERVER_PORT,
      path: path,
      method: method,
      ...options
    };

    if (data) {
      const jsonData = JSON.stringify(data);
      requestOptions.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(jsonData)
      };
    }

    const req = https.request(requestOptions, (res) => {
      let body = '';

      res.on('data', (chunk) => {
        body += chunk;
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        });
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function testMainEndpoint() {
  console.log('📡 Test 1: Main endpoint (GET /)');
  try {
    const response = await makeRequest('/');
    const data = JSON.parse(response.body);
    
    console.log(`✅ Status: ${response.statusCode}`);
    console.log(`   Message: ${data.message}`);
    console.log(`   Client Certificate: ${data.client_cert}`);
    console.log(`   Verified: ${data.verified}`);
    console.log(`   Server Time: ${data.server_time}`);
  } catch (error) {
    console.log(`❌ Request failed: ${error.message}`);
  }
  console.log();
}

async function testHealthEndpoint() {
  console.log('📡 Test 2: Health check (GET /health)');
  try {
    const response = await makeRequest('/health');
    
    console.log(`✅ Status: ${response.statusCode}`);
    console.log(`   Response: ${response.body}`);
  } catch (error) {
    console.log(`❌ Request failed: ${error.message}`);
  }
  console.log();
}

async function testAPIDataEndpoint() {
  console.log('📡 Test 3: API data (GET /api/data)');
  try {
    const response = await makeRequest('/api/data');
    const data = JSON.parse(response.body);
    
    console.log(`✅ Status: ${response.statusCode}`);
    console.log('   Data:');
    console.log(JSON.stringify(data, null, 6).split('\n').map(line => '   ' + line).join('\n'));
  } catch (error) {
    console.log(`❌ Request failed: ${error.message}`);
  }
  console.log();
}

async function testEchoEndpoint() {
  console.log('📡 Test 4: Echo test (POST /api/echo)');
  try {
    const testData = {
      message: 'Hello from mTLS Node.js client!',
      timestamp: new Date().toISOString(),
      test: true
    };
    
    const response = await makeRequest('/api/echo', 'POST', testData);
    const data = JSON.parse(response.body);
    
    console.log(`✅ Status: ${response.statusCode}`);
    console.log('   Response:');
    console.log(JSON.stringify(data, null, 6).split('\n').map(line => '   ' + line).join('\n'));
  } catch (error) {
    console.log(`❌ Request failed: ${error.message}`);
  }
  console.log();
}

async function main() {
  console.log('🔒 mTLS Node.js Client');
  console.log('======================');
  console.log();

  await testMainEndpoint();
  await testHealthEndpoint();
  await testAPIDataEndpoint();
  await testEchoEndpoint();

  console.log('✅ All tests completed successfully!');
}

main().catch(console.error);
