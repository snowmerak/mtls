package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	serverURL = "https://localhost:8443"
)

type ServerResponse struct {
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	ClientCert string    `json:"client_cert"`
	ServerTime time.Time `json:"server_time"`
	Verified   bool      `json:"verified"`
}

func main() {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(
		"../../certs/servers/localhost/server-cert.pem",
		"../../certs/servers/localhost/server-key.pem",
	)
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}

	// Load CA certificate to verify server
	caCert, err := os.ReadFile("../../certs/ca/ca-cert.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// Create certificate pool and add CA cert
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to append CA certificate")
	}

	// Configure TLS for client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},  // Client certificate
		RootCAs:      caCertPool,               // Trusted CAs for server verification
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP client with mTLS
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	fmt.Println("🔒 mTLS Go Client")
	fmt.Println("================")
	fmt.Println()

	// Test 1: Main endpoint
	fmt.Println("📡 Test 1: Main endpoint (GET /)")
	testMainEndpoint(client)
	fmt.Println()

	// Test 2: Health check
	fmt.Println("📡 Test 2: Health check (GET /health)")
	testHealthEndpoint(client)
	fmt.Println()

	// Test 3: API data endpoint
	fmt.Println("📡 Test 3: API data (GET /api/data)")
	testAPIDataEndpoint(client)
	fmt.Println()

	// Test 4: Echo endpoint
	fmt.Println("📡 Test 4: Echo test (POST /api/echo)")
	testEchoEndpoint(client)
	fmt.Println()

	fmt.Println("✅ All tests completed successfully!")
}

func testMainEndpoint(client *http.Client) {
	resp, err := client.Get(serverURL + "/")
	if err != nil {
		log.Printf("❌ Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read response: %v", err)
		return
	}

	var response ServerResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("❌ Failed to parse JSON: %v", err)
		return
	}

	fmt.Printf("✅ Status: %d\n", resp.StatusCode)
	fmt.Printf("   Message: %s\n", response.Message)
	fmt.Printf("   Client Certificate: %s\n", response.ClientCert)
	fmt.Printf("   Verified: %v\n", response.Verified)
	fmt.Printf("   Server Time: %s\n", response.ServerTime.Format(time.RFC3339))
}

func testHealthEndpoint(client *http.Client) {
	resp, err := client.Get(serverURL + "/health")
	if err != nil {
		log.Printf("❌ Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read response: %v", err)
		return
	}

	fmt.Printf("✅ Status: %d\n", resp.StatusCode)
	fmt.Printf("   Response: %s", string(body))
}

func testAPIDataEndpoint(client *http.Client) {
	resp, err := client.Get(serverURL + "/api/data")
	if err != nil {
		log.Printf("❌ Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read response: %v", err)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("❌ Failed to parse JSON: %v", err)
		return
	}

	fmt.Printf("✅ Status: %d\n", resp.StatusCode)
	prettyJSON, _ := json.MarshalIndent(data, "   ", "  ")
	fmt.Printf("   Data:\n   %s\n", string(prettyJSON))
}

func testEchoEndpoint(client *http.Client) {
	testData := map[string]interface{}{
		"message": "Hello from mTLS client!",
		"timestamp": time.Now(),
		"test": true,
	}

	jsonData, err := json.Marshal(testData)
	if err != nil {
		log.Printf("❌ Failed to marshal JSON: %v", err)
		return
	}

	resp, err := client.Post(
		serverURL+"/api/echo",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.Printf("❌ Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read response: %v", err)
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("❌ Failed to parse JSON: %v", err)
		return
	}

	fmt.Printf("✅ Status: %d\n", resp.StatusCode)
	prettyJSON, _ := json.MarshalIndent(response, "   ", "  ")
	fmt.Printf("   Response:\n   %s\n", string(prettyJSON))
}
