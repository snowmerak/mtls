use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

const SERVER_URL: &str = "https://localhost:8443";

#[derive(Deserialize, Debug)]
struct ServerResponse {
    status: String,
    message: String,
    client_cert: String,
    server_time: String,
    verified: bool,
}

#[derive(Deserialize, Debug)]
struct DataResponse {
    timestamp: String,
    client: serde_json::Value,
    server: serde_json::Value,
    data: serde_json::Value,
}

async fn create_client() -> reqwest::Result<reqwest::Client> {
    let cert_dir = PathBuf::from("../../certs");
    
    // Load client certificate and key
    let cert_pem = fs::read(cert_dir.join("servers/localhost/server-cert.pem"))
        .expect("Failed to read client certificate");
    let key_pem = fs::read(cert_dir.join("servers/localhost/server-key.pem"))
        .expect("Failed to read client key");
    
    // Combine cert and key for Identity
    let mut pem = cert_pem.clone();
    pem.extend_from_slice(&key_pem);
    
    let identity = Identity::from_pem(&pem)
        .expect("Failed to create identity");
    
    // Load CA certificate
    let ca_cert = fs::read(cert_dir.join("ca/ca-cert.pem"))
        .expect("Failed to read CA certificate");
    let ca = Certificate::from_pem(&ca_cert)
        .expect("Failed to parse CA certificate");
    
    // Build client with mTLS
    reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca)
        .build()
}

async fn test_main_endpoint(client: &reqwest::Client) {
    println!("📡 Test 1: Main endpoint (GET /)");
    
    match client.get(format!("{}/", SERVER_URL)).send().await {
        Ok(response) => {
            let status = response.status();
            match response.json::<ServerResponse>().await {
                Ok(data) => {
                    println!("✅ Status: {}", status);
                    println!("   Message: {}", data.message);
                    println!("   Client Certificate: {}", data.client_cert);
                    println!("   Verified: {}", data.verified);
                    println!("   Server Time: {}", data.server_time);
                }
                Err(e) => println!("❌ Failed to parse response: {}", e),
            }
        }
        Err(e) => println!("❌ Request failed: {}", e),
    }
    println!();
}

async fn test_health_endpoint(client: &reqwest::Client) {
    println!("📡 Test 2: Health check (GET /health)");
    
    match client.get(format!("{}/health", SERVER_URL)).send().await {
        Ok(response) => {
            let status = response.status();
            match response.text().await {
                Ok(text) => {
                    println!("✅ Status: {}", status);
                    println!("   Response: {}", text);
                }
                Err(e) => println!("❌ Failed to read response: {}", e),
            }
        }
        Err(e) => println!("❌ Request failed: {}", e),
    }
    println!();
}

async fn test_api_data_endpoint(client: &reqwest::Client) {
    println!("📡 Test 3: API data (GET /api/data)");
    
    match client.get(format!("{}/api/data", SERVER_URL)).send().await {
        Ok(response) => {
            let status = response.status();
            match response.json::<DataResponse>().await {
                Ok(data) => {
                    println!("✅ Status: {}", status);
                    println!("   Data:");
                    let json_str = serde_json::to_string_pretty(&data).unwrap();
                    for line in json_str.lines() {
                        println!("   {}", line);
                    }
                }
                Err(e) => println!("❌ Failed to parse response: {}", e),
            }
        }
        Err(e) => println!("❌ Request failed: {}", e),
    }
    println!();
}

async fn test_echo_endpoint(client: &reqwest::Client) {
    println!("📡 Test 4: Echo test (POST /api/echo)");
    
    let test_data = json!({
        "message": "Hello from mTLS Rust client!",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "test": true
    });
    
    match client
        .post(format!("{}/api/echo", SERVER_URL))
        .json(&test_data)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            match response.json::<serde_json::Value>().await {
                Ok(data) => {
                    println!("✅ Status: {}", status);
                    println!("   Response:");
                    let json_str = serde_json::to_string_pretty(&data).unwrap();
                    for line in json_str.lines() {
                        println!("   {}", line);
                    }
                }
                Err(e) => println!("❌ Failed to parse response: {}", e),
            }
        }
        Err(e) => println!("❌ Request failed: {}", e),
    }
    println!();
}

#[tokio::main]
async fn main() {
    println!("🔒 mTLS Rust Client");
    println!("===================");
    println!();
    
    let client = create_client().await.expect("Failed to create client");
    
    test_main_endpoint(&client).await;
    test_health_endpoint(&client).await;
    test_api_data_endpoint(&client).await;
    test_echo_endpoint(&client).await;
    
    println!("✅ All tests completed successfully!");
}
