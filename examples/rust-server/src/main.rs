use axum::{
    extract::Json,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use rustls_pemfile::{certs, rsa_private_keys};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Serialize)]
struct ServerResponse {
    status: String,
    message: String,
    client_cert: String,
    server_time: String,
    verified: bool,
}

#[derive(Serialize)]
struct DataResponse {
    timestamp: String,
    client: ClientInfo,
    server: ServerInfo,
    data: AppData,
}

#[derive(Serialize)]
struct ClientInfo {
    cn: String,
    organization: String,
    verified: bool,
}

#[derive(Serialize)]
struct ServerInfo {
    name: String,
    version: String,
    platform: String,
}

#[derive(Serialize)]
struct AppData {
    users: u32,
    requests: u32,
    status: String,
}

#[derive(Deserialize)]
struct EchoRequest {
    #[serde(flatten)]
    data: serde_json::Value,
}

#[derive(Serialize)]
struct EchoResponse {
    echo: serde_json::Value,
    metadata: EchoMetadata,
}

#[derive(Serialize)]
struct EchoMetadata {
    received_at: String,
    client_cn: String,
}

async fn handle_root() -> Json<ServerResponse> {
    Json(ServerResponse {
        status: "success".to_string(),
        message: "mTLS Rust Server".to_string(),
        client_cert: "localhost".to_string(),
        server_time: Utc::now().to_rfc3339(),
        verified: true,
    })
}

async fn handle_health() -> &'static str {
    "OK"
}

async fn handle_data() -> Json<DataResponse> {
    Json(DataResponse {
        timestamp: Utc::now().to_rfc3339(),
        client: ClientInfo {
            cn: "localhost".to_string(),
            organization: "N/A".to_string(),
            verified: true,
        },
        server: ServerInfo {
            name: "rust-mtls-server".to_string(),
            version: "1.0.0".to_string(),
            platform: std::env::consts::OS.to_string(),
        },
        data: AppData {
            users: 42,
            requests: 1337,
            status: "healthy".to_string(),
        },
    })
}

async fn handle_echo(Json(request): Json<EchoRequest>) -> Json<EchoResponse> {
    Json(EchoResponse {
        echo: request.data,
        metadata: EchoMetadata {
            received_at: Utc::now().to_rfc3339(),
            client_cn: "localhost".to_string(),
        },
    })
}

fn load_certs(path: &PathBuf) -> std::io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> std::io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys = rsa_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
    
    if let Some(key) = keys.into_iter().next() {
        Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No private key found",
        ))
    }
}

#[tokio::main]
async fn main() {
    // Certificate paths
    let cert_dir = PathBuf::from("../../certs");
    let server_cert = cert_dir.join("servers/localhost/server-cert.pem");
    let server_key = cert_dir.join("servers/localhost/server-key.pem");
    let ca_cert = cert_dir.join("ca/ca-cert.pem");

    // Load certificates
    let certs = load_certs(&server_cert).expect("Failed to load server certificate");
    let key = load_private_key(&server_key).expect("Failed to load private key");

    // Load CA certificate for client verification
    let ca_certs = load_certs(&ca_cert).expect("Failed to load CA certificate");
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).expect("Failed to add CA cert");
    }

    // Configure TLS with client authentication
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .expect("Failed to build client verifier");

    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("Failed to configure TLS");

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_config = RustlsConfig::from_config(Arc::new(server_config));

    // Build application routes
    let app = Router::new()
        .route("/", get(handle_root))
        .route("/health", get(handle_health))
        .route("/api/data", get(handle_data))
        .route("/api/echo", post(handle_echo));

    // Server address
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    println!("🔒 mTLS Rust Server");
    println!("===================");
    println!("Server running on https://localhost:8443");
    println!("\nEndpoints:");
    println!("  GET  /          - Main endpoint with client info");
    println!("  GET  /health    - Health check");
    println!("  GET  /api/data  - Sample data endpoint");
    println!("  POST /api/echo  - Echo endpoint");
    println!("\nPress Ctrl+C to stop");

    // Start server
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .expect("Server failed");
}
