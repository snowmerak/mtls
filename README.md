# mTLS Certificate Management Tool

A powerful, user-friendly CLI tool for creating and managing mTLS (mutual TLS) certificates, including self-signed Root CAs and server certificates.

## Features

- 🔐 **Create Self-Signed Root CA** - Generate your own Certificate Authority
- ⛓️ **Create Intermediate CA** - Generate Intermediate CAs for multi-level trust chains
- 📜 **Generate Server Certificates** - Create server certificates signed by your CA
- 👤 **Generate Client Certificates** - Create client certificates for mTLS authentication
- ✍️ **Sign CSRs** - Sign Certificate Signing Requests from external sources
- 🚫 **Revoke Certificates** - Revoke certificates and generate CRLs
- 🔍 **Inspect & Verify** - Inspect certificate details and verify chains
- 🌳 **Visualize Hierarchy** - View certificate chain hierarchy and status tree
- 🔑 **Multiple Key Types** - Support for RSA (2048/4096), ECDSA (P-256/P-384/P-521), and Ed25519
- 🎨 **Interactive CLI** - User-friendly prompts with sensible defaults
- 📊 **Certificate Registry** - Track all your certificates in one place with SQLite backend
- 🎯 **Flexible Subject Configuration** - Customize all certificate fields (Simplified DN support)
- 🌐 **SAN Support** - Add DNS names and IP addresses to both server and client certificates
- 📦 **Full Chain Support** - Automatically generates full chain certificates by default

## Installation

```bash
# Clone the repository
git clone https://github.com/snowmerak/mtls.git
cd mtls

# Build the binary
go build

# Optional: Install globally
go install
```

## Examples

See the [examples](./examples) directory for practical implementations in multiple languages:

- **Go**: [Server](./examples/go-server/) | [Client](./examples/go-client/) - Standard library, zero dependencies
- **Node.js**: [Server](./examples/node-server/) | [Client](./examples/node-client/) - Built-in HTTPS module
- **Python**: [Server](./examples/python-server/) | [Client](./examples/python-client/) - Standard library ssl module
- **PHP**: [Server](./examples/php-server/) | [Client](./examples/php-client/) - Stream contexts with OpenSSL
- **Rust**: [Server](./examples/rust-server/) | [Client](./examples/rust-client/) - Axum + Rustls for performance
- **Caddy**: [Config](./examples/caddy/) - Production-ready reverse proxy with mTLS

Quick test:
```bash
cd examples
./test.sh
```

## Quick Start

### 1. Create a Root CA (Interactive Mode)

```bash
./mtls ca create
```

You'll be prompted for:
- CA Type (Root CA or Intermediate CA)
- Common Name (e.g., "My Company Root CA")
- Organization (Optional)
- Country Code (Optional)
- Validity Period (years)
- Key Type (RSA 2048/4096, ECDSA P-256/P-384/P-521, Ed25519)
- Output directory

> **Note**: Organization and Country are optional. If omitted, the DN will only contain the Common Name.
> **Note**: The generated `ca-cert.pem` will contain the full chain if it's an intermediate CA. A separate `ca-cert-leaf.pem` is also created.

### 2. Create an Intermediate CA (Interactive Mode)

```bash
./mtls ca create
```

Select "Intermediate CA" when prompted for CA Type. You'll then be asked to select a parent CA from your registry.

### 3. Create a Server Certificate (Interactive Mode)

```bash
./mtls cert create
```

You'll be prompted for:
- Select existing CA or browse for one
- Common Name (e.g., "api.example.com")
- DNS names (comma-separated)
- IP addresses (comma-separated)
- Organization (Optional)
- Validity Period
- Key Type

> **Note**: The generated `server-cert.pem` contains the full certificate chain. The leaf certificate is available as `server-cert-leaf.pem`.

### 4. Create a Client Certificate (Interactive Mode)

```bash
./mtls cert create-client
```

You'll be prompted for:
- Select existing CA
- Common Name (e.g., "client-1")
- DNS names (comma-separated, optional)
- IP addresses (comma-separated, optional)
- Organization (Optional)
- Validity Period
- Key Type

> **Note**: The generated `client-cert.pem` contains the full certificate chain. The leaf certificate is available as `client-cert-leaf.pem`.

### 5. View Certificate Tree

Visualize your certificate hierarchy and status:

```bash
./mtls tree
```

This will display a tree view of all your certificates, showing their validity status, expiration dates, and relationships.

```text
Certificate Registry Tree
=========================
Legend: ✓ Valid  ! Expired  ✗ Revoked

├── ✓ My Root CA (root_ca) [Expires: 2035-12-22 (3650 days left)]
│   ├── ✓ Intermediate CA (intermediate_ca) [Expires: 2030-12-22 (1825 days left)]
│   │   ├── ✓ api.server.com (server) [Expires: 2026-12-22 (365 days left)]
│   │   └── ! expired-client (client) [Expired: 2024-01-01 (-356 days left)]
```
- Validity Period
- Key Type

### 5. Other Operations

```bash
# List all CAs (Root and Intermediate)
./mtls ca list

# List all server certificates
./mtls cert list

# List all client certificates
./mtls cert list-client

# Sign a CSR
./mtls ca sign

# Revoke a certificate
./mtls ca revoke

# Generate CRL
./mtls ca crl

# Inspect a certificate
./mtls cert inspect --cert ./path/to/cert.pem

# Verify a certificate chain
./mtls cert verify --cert ./path/to/cert.pem --root ./path/to/root.pem --intermediate ./path/to/inter.pem
```

## Batch Mode (Non-Interactive)

### Create Root CA

```bash
./mtls ca create --batch \
  --type root \
  --cn "My Company Root CA" \
  --org "My Organization" \
  --country "US" \
  --years 10 \
  --key-type rsa4096 \
  --output ./certs/ca
```

### Create Intermediate CA

```bash
./mtls ca create --batch \
  --type intermediate \
  --parent "My Company Root CA" \
  --cn "My Company Intermediate CA" \
  --org "My Organization" \
  --country "US" \
  --years 5 \
  --key-type rsa4096 \
  --output ./certs/intermediate

```bash
./mtls ca create --batch \
  --cn "My Company Root CA" \
  --org "My Organization" \
  --country "US" \
  --years 10 \
  --key-type rsa4096 \
  --output ./certs/ca
```

### Create Server Certificate

```bash
./mtls cert create --batch \
  --ca ./certs/ca \
  --cn "api.example.com" \
  --org "My API Server" \
  --dns "api.example.com,*.api.example.com,localhost" \
  --ip "127.0.0.1,192.168.1.100" \
  --years 5 \
  --key-type rsa2048 \
  --output ./certs/servers/api.example.com
```

## Key Types

| Key Type | Security | Speed | Use Case |
|----------|----------|-------|----------|
| `rsa2048` | Good | Fast | General server certificates |
| `rsa4096` | Better | Slower | Root CAs, high-security environments |
| `ecp256` | Good | Very Fast | Modern systems, IoT |
| `ecp384` | Better | Fast | High-security modern systems |
| `ecp521` | Best | Medium | Maximum security requirements |

## Directory Structure

After generating certificates, you'll have:

```
certs/
├── .registry.json                    # Certificate registry
├── ca/
│   ├── ca-cert.pem                  # CA certificate
│   ├── ca-key.pem                   # CA private key (0600)
│   └── .metadata.json               # CA metadata
└── servers/
    └── api.example.com/
        ├── server-cert.pem          # Server certificate
        ├── server-key.pem           # Server private key (0600)
        ├── ca-cert.pem              # CA certificate (copy)
        └── .metadata.json           # Certificate metadata
```

## Usage in Go Code

### Server Side (mTLS Server)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "net/http"
    "os"
)

func main() {
    // Load server certificate
    cert, err := tls.LoadX509KeyPair(
        "certs/servers/api.example.com/server-cert.pem",
        "certs/servers/api.example.com/server-key.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // Load CA certificate for client verification
    caCert, err := os.ReadFile("certs/ca/ca-cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Configure TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientCAs:    caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    log.Println("Server starting on https://localhost:8443")
    log.Fatal(server.ListenAndServeTLS("", ""))
}
```

### Client Side (mTLS Client)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "io"
    "log"
    "net/http"
    "os"
)

func main() {
    // Load client certificate
    cert, err := tls.LoadX509KeyPair(
        "certs/servers/client.example.com/server-cert.pem",
        "certs/servers/client.example.com/server-key.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // Load CA certificate
    caCert, err := os.ReadFile("certs/ca/ca-cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Configure TLS client
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    }

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    resp, err := client.Get("https://api.example.com:8443")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    log.Println(string(body))
}
```

## IP-Only Certificates

You can create certificates with only IP addresses (no DNS names):

```bash
./mtls cert create --batch \
  --ca ./certs/ca \
  --cn "192.168.1.100" \
  --ip "192.168.1.100,10.0.0.5" \
  --key-type ecp256
```

This is useful for:
- Internal network services
- Kubernetes pods with IP-based communication
- IoT devices with static IPs

## Commands Reference

```bash
# Root CA Management
mtls ca create              # Create new Root CA (interactive)
mtls ca create --batch      # Create new Root CA (non-interactive)
mtls ca list                # List all Root CAs

# Server Certificate Management
mtls cert create            # Create server certificate (interactive)
mtls cert create --batch    # Create server certificate (non-interactive)
mtls cert list              # List all server certificates

# Utility
mtls version                # Show version
mtls help                   # Show help
mtls [command] --help       # Show command-specific help
```

## Advanced Options

### Custom Subject Fields

When using batch mode, you can customize more fields:

```bash
./mtls ca create --batch \
  --cn "My Root CA" \
  --org "My Organization" \
  --country "US" \
  --key-type rsa4096
```

### Mixed Key Types

You can use different key types for CA and server certificates:

```bash
# ECDSA CA (fast)
./mtls ca create --batch --cn "Fast CA" --key-type ecp256

# RSA server certificate signed by ECDSA CA
./mtls cert create --batch --ca ./certs/ca --cn "server.com" --key-type rsa2048
```

## Security Best Practices

1. **Private Key Protection**: Private keys are automatically set to 0600 permissions
2. **Key Types**: Use RSA 4096 or ECDSA P-384+ for CAs
3. **Validity Periods**: 
   - CAs: 10-20 years
   - Server certificates: 1-5 years
4. **Certificate Rotation**: Regularly rotate server certificates
5. **Storage**: Keep CA private keys in secure, encrypted storage

## Development

### Run Tests

```bash
go test -v
go test -cover
go test -bench=.
```

### Build

```bash
go build
```

## License

This project is open source. See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
