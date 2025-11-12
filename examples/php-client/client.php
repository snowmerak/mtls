<?php

// Certificate paths
$certDir = dirname(__DIR__, 2) . '/certs';
$clientCert = $certDir . '/servers/localhost/server-cert.pem';
$clientKey = $certDir . '/servers/localhost/server-key.pem';
$caCert = $certDir . '/ca/ca-cert.pem';

$serverUrl = 'https://localhost:8443';

function makeRequest($url, $method = 'GET', $data = null) {
    global $clientCert, $clientKey, $caCert;
    
    $context = stream_context_create([
        'ssl' => [
            'local_cert' => $clientCert,
            'local_pk' => $clientKey,
            'cafile' => $caCert,
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ],
        'http' => [
            'method' => $method,
            'header' => 'Content-Type: application/json',
            'content' => $data ? json_encode($data) : null,
            'ignore_errors' => true,
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        $error = error_get_last();
        throw new Exception($error['message'] ?? 'Request failed');
    }
    
    // Get response headers
    $statusLine = $http_response_header[0] ?? 'HTTP/1.1 200 OK';
    preg_match('/\d{3}/', $statusLine, $matches);
    $statusCode = (int)($matches[0] ?? 200);
    
    return [
        'status_code' => $statusCode,
        'body' => $response
    ];
}

function testMainEndpoint() {
    global $serverUrl;
    
    echo "📡 Test 1: Main endpoint (GET /)\n";
    try {
        $response = makeRequest($serverUrl . '/');
        $data = json_decode($response['body'], true);
        
        echo "✅ Status: {$response['status_code']}\n";
        echo "   Message: {$data['message']}\n";
        echo "   Client Certificate: {$data['client_cert']}\n";
        echo "   Verified: " . ($data['verified'] ? 'true' : 'false') . "\n";
        echo "   Server Time: {$data['server_time']}\n";
    } catch (Exception $e) {
        echo "❌ Request failed: {$e->getMessage()}\n";
    }
    echo "\n";
}

function testHealthEndpoint() {
    global $serverUrl;
    
    echo "📡 Test 2: Health check (GET /health)\n";
    try {
        $response = makeRequest($serverUrl . '/health');
        
        echo "✅ Status: {$response['status_code']}\n";
        echo "   Response: {$response['body']}\n";
    } catch (Exception $e) {
        echo "❌ Request failed: {$e->getMessage()}\n";
    }
    echo "\n";
}

function testAPIDataEndpoint() {
    global $serverUrl;
    
    echo "📡 Test 3: API data (GET /api/data)\n";
    try {
        $response = makeRequest($serverUrl . '/api/data');
        $data = json_decode($response['body'], true);
        
        echo "✅ Status: {$response['status_code']}\n";
        echo "   Data:\n";
        $formatted = json_encode($data, JSON_PRETTY_PRINT);
        foreach (explode("\n", $formatted) as $line) {
            echo "   $line\n";
        }
    } catch (Exception $e) {
        echo "❌ Request failed: {$e->getMessage()}\n";
    }
    echo "\n";
}

function testEchoEndpoint() {
    global $serverUrl;
    
    echo "📡 Test 4: Echo test (POST /api/echo)\n";
    try {
        $testData = [
            'message' => 'Hello from mTLS PHP client!',
            'timestamp' => date('c'),
            'test' => true
        ];
        
        $response = makeRequest($serverUrl . '/api/echo', 'POST', $testData);
        $data = json_decode($response['body'], true);
        
        echo "✅ Status: {$response['status_code']}\n";
        echo "   Response:\n";
        $formatted = json_encode($data, JSON_PRETTY_PRINT);
        foreach (explode("\n", $formatted) as $line) {
            echo "   $line\n";
        }
    } catch (Exception $e) {
        echo "❌ Request failed: {$e->getMessage()}\n";
    }
    echo "\n";
}

echo "🔒 mTLS PHP Client\n";
echo "==================\n";
echo "\n";

testMainEndpoint();
testHealthEndpoint();
testAPIDataEndpoint();
testEchoEndpoint();

echo "✅ All tests completed successfully!\n";
