<?php

// Certificate paths
$certDir = dirname(__DIR__, 2) . '/certs';
$serverCert = $certDir . '/servers/localhost/server-cert.pem';
$serverKey = $certDir . '/servers/localhost/server-key.pem';
$caCert = $certDir . '/ca/ca-cert.pem';

// Create SSL context
$context = stream_context_create([
    'ssl' => [
        'local_cert' => $serverCert,
        'local_pk' => $serverKey,
        'cafile' => $caCert,
        'verify_peer' => true,
        'verify_peer_name' => true,
        'allow_self_signed' => false,
        'verify_depth' => 3,
    ]
]);

// Get request info
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Get client certificate info
$clientCert = $_SERVER['SSL_CLIENT_S_DN_CN'] ?? 'Unknown';
$clientVerified = isset($_SERVER['SSL_CLIENT_VERIFY']) && $_SERVER['SSL_CLIENT_VERIFY'] === 'SUCCESS';

// Route handling
header('Content-Type: application/json');

switch ($path) {
    case '/':
        if ($method === 'GET') {
            handleRoot($clientCert, $clientVerified);
        } else {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
        }
        break;

    case '/health':
        if ($method === 'GET') {
            handleHealth();
        } else {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
        }
        break;

    case '/api/data':
        if ($method === 'GET') {
            handleData($clientCert, $clientVerified);
        } else {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
        }
        break;

    case '/api/echo':
        if ($method === 'POST') {
            handleEcho($clientCert);
        } else {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
        }
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
        break;
}

function handleRoot($clientCert, $clientVerified) {
    $response = [
        'status' => 'success',
        'message' => 'mTLS PHP Server',
        'client_cert' => $clientCert,
        'server_time' => date('c'),
        'verified' => $clientVerified
    ];
    
    echo json_encode($response, JSON_PRETTY_PRINT);
}

function handleHealth() {
    header('Content-Type: text/plain');
    echo 'OK';
}

function handleData($clientCert, $clientVerified) {
    $data = [
        'timestamp' => date('c'),
        'client' => [
            'cn' => $clientCert,
            'organization' => $_SERVER['SSL_CLIENT_S_DN_O'] ?? 'N/A',
            'verified' => $clientVerified
        ],
        'server' => [
            'name' => 'php-mtls-server',
            'version' => '1.0.0',
            'platform' => PHP_OS,
            'php_version' => PHP_VERSION
        ],
        'data' => [
            'users' => 42,
            'requests' => 1337,
            'status' => 'healthy'
        ]
    ];
    
    echo json_encode($data, JSON_PRETTY_PRINT);
}

function handleEcho($clientCert) {
    $input = file_get_contents('php://input');
    $receivedData = json_decode($input, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON']);
        return;
    }
    
    $response = [
        'echo' => $receivedData,
        'metadata' => [
            'received_at' => date('c'),
            'client_cn' => $clientCert,
            'content_length' => strlen($input)
        ]
    ];
    
    echo json_encode($response, JSON_PRETTY_PRINT);
}
