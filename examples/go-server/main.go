package main

import (
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

type Response struct {
	Status      string    `json:"status"`
	Message     string    `json:"message"`
	ClientCert  string    `json:"client_cert"`
	ServerTime  time.Time `json:"server_time"`
	Verified    bool      `json:"verified"`
}

func main() {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(
		"../../certs/servers/localhost/server-cert.pem",
		"../../certs/servers/localhost/server-key.pem",
	)
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile("../../certs/ca/ca-cert.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// Create certificate pool and add CA cert
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to append CA certificate")
	}

	// Configure TLS with mTLS (mutual authentication)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require client certificate
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP server
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	// Main endpoint with client cert info
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Get client certificate information
		var clientCN string
		var verified bool

		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			clientCN = clientCert.Subject.CommonName
			verified = true
			
			log.Printf("Client connected: %s", clientCN)
			log.Printf("  Organization: %v", clientCert.Subject.Organization)
			log.Printf("  Valid from: %s", clientCert.NotBefore.Format(time.RFC3339))
			log.Printf("  Valid until: %s", clientCert.NotAfter.Format(time.RFC3339))
		}

		response := Response{
			Status:     "success",
			Message:    "mTLS connection established successfully",
			ClientCert: clientCN,
			ServerTime: time.Now(),
			Verified:   verified,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// API endpoint
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		data := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"items": []string{"item1", "item2", "item3"},
				"count": 3,
			},
			"timestamp": time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	})

	// Echo endpoint (for testing)
	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		response := map[string]interface{}{
			"status":   "success",
			"echo":     string(body),
			"received": time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("🔒 mTLS Server starting...")
	log.Println("📍 Address: https://localhost:8443")
	log.Println("🔑 Client certificates required")
	log.Println("")
	log.Println("Available endpoints:")
	log.Println("  GET  /              - Main endpoint with client cert info")
	log.Println("  GET  /health        - Health check")
	log.Println("  GET  /api/data      - API data endpoint")
	log.Println("  POST /api/echo      - Echo endpoint")
	log.Println("")
	log.Println("Press Ctrl+C to stop the server")
	log.Println("")

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
