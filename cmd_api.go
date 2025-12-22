package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func serverCmd() *cobra.Command {
	var port int
	var host string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the REST API server",
		Long:  "Start a REST API server to manage certificates via HTTP requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			mux := http.NewServeMux()

			// CA endpoints
			mux.HandleFunc("POST /ca", handleCreateCA)
			mux.HandleFunc("GET /ca", handleListCAs)

			// Server Cert endpoints
			mux.HandleFunc("POST /cert/server", handleCreateServerCert)
			mux.HandleFunc("GET /cert/server", handleListServerCerts)

			// Client Cert endpoints
			mux.HandleFunc("POST /cert/client", handleCreateClientCert)
			mux.HandleFunc("GET /cert/client", handleListClientCerts)

			addr := fmt.Sprintf("%s:%d", host, port)
			infoColor.Printf("Starting server on %s\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	cmd.Flags().StringVarP(&host, "host", "H", "0.0.0.0", "Host to listen on")

	return cmd
}

// API Response structures
type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, ErrorResponse{Error: message})
}

// Request structures
type CreateCARequest struct {
	CommonName   string `json:"commonName"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	ValidYears   int    `json:"validYears"`
	KeyType      string `json:"keyType"`
	Type         string `json:"type"`     // "root" or "intermediate"
	ParentCA     string `json:"parentCA"` // Common Name of parent CA
}

func handleCreateCA(w http.ResponseWriter, r *http.Request) {
	var req CreateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate inputs
	if req.CommonName == "" {
		jsonError(w, http.StatusBadRequest, "commonName is required")
		return
	}
	if req.Type == "intermediate" && req.ParentCA == "" {
		jsonError(w, http.StatusBadRequest, "parentCA is required for intermediate CA")
		return
	}
	if req.ValidYears <= 0 {
		req.ValidYears = 10 // Default
	}
	if req.KeyType == "" {
		req.KeyType = string(KeyTypeRSA4096) // Default
	}

	// Create CA options
	opts := DefaultCAOptions(req.CommonName)
	if req.Organization != "" {
		opts.Subject.Organization = []string{req.Organization}
	}
	if req.Country != "" {
		opts.Subject.Country = []string{req.Country}
	}
	opts.ValidYears = req.ValidYears
	opts.KeyType = KeyType(req.KeyType)

	var ca *CertificateAuthority
	var err error
	var parentCertPath string

	if req.Type == "intermediate" {
		// Load parent CA
		parentCert, err := GetCertificateByCN(context.Background(), req.ParentCA)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load parent CA from DB: %v", err))
			return
		}
		if parentCert == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("parent CA '%s' not found", req.ParentCA))
			return
		}
		parentCertPath = parentCert.CertPath

		parent, err := LoadCAFromFiles(parentCert.CertPath, parentCert.KeyPath)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load parent CA: %v", err))
			return
		}

		ca, err = parent.GenerateIntermediateCAWithOptions(opts)
	} else {
		ca, err = GenerateRootCAWithOptions(opts)
	}

	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate CA: %v", err))
		return
	}

	// Save files
	saveDir := defaultCADir
	saveDir = filepath.Join(saveDir, strings.ReplaceAll(req.CommonName, " ", "_"))

	if err := os.MkdirAll(saveDir, 0755); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create directory: %v", err))
		return
	}

	certPath := filepath.Join(saveDir, "ca-cert.pem")
	keyPath := filepath.Join(saveDir, "ca-key.pem")
	metadataPath := filepath.Join(saveDir, ".metadata.json")

	if err := ca.SaveCAToFiles(certPath, keyPath); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save CA files: %v", err))
		return
	}

	// Calculate fingerprint
	fingerprint, err := CalculateFingerprint(certPath)
	if err != nil {
		fingerprint = "unknown"
	}

	// Save metadata
	metadata := CertMetadata{
		Type:              "root-ca",
		CommonName:        req.CommonName,
		Organization:      req.Organization,
		Country:           req.Country,
		KeyType:           req.KeyType,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().AddDate(req.ValidYears, 0, 0),
		SerialNumber:      ca.Certificate.SerialNumber.String(),
		FingerprintSHA256: fingerprint,
		CertPath:          certPath,
		KeyPath:           keyPath,
		CAPath:            parentCertPath,
	}

	if req.Type == "intermediate" {
		metadata.Type = "intermediate-ca"
		metadata.Issuer = req.ParentCA
	}

	if err := SaveMetadata(&metadata, metadataPath); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: Could not save metadata: %v\n", err)
	}

	// Save to DB
	if err := SaveCertificateToDB(context.Background(), metadata); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: Could not save to database: %v\n", err)
	}

	jsonResponse(w, http.StatusCreated, SuccessResponse{
		Message: "CA created successfully",
		Data:    metadata,
	})
}

func handleListCAs(w http.ResponseWriter, r *http.Request) {
	// This would ideally query the DB
	// For now, let's reuse the logic from listCACmd if possible, or query DB directly
	// Since we have dbClient in registry_ent.go, we can use it.

	if dbClient == nil {
		jsonError(w, http.StatusInternalServerError, "Database client not initialized")
		return
	}

	// Query all CAs (root and intermediate)
	// We need to import "github.com/snowmerak/mtls/ent/certificate"
	// But we can't import it here if it's not already imported in the file.
	// I'll add the import in the file creation.

	// Wait, I can't easily use ent query here without importing the generated code.
	// I'll assume I can use GetCertificates from registry_ent.go if it exists, or implement a helper.
	// Let's check registry_ent.go again for list functions.

	// For now, I'll return a placeholder or implement a simple DB query if I can.
	// I'll use a helper function to list certs.

	certs, err := ListCertificates(context.Background(), "root-ca")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list root CAs: %v", err))
		return
	}

	intermediateCerts, err := ListCertificates(context.Background(), "intermediate-ca")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list intermediate CAs: %v", err))
		return
	}

	allCerts := append(certs, intermediateCerts...)

	jsonResponse(w, http.StatusOK, SuccessResponse{
		Message: "CAs listed successfully",
		Data:    allCerts,
	})
}

// Placeholder handlers for other endpoints
type CreateServerCertRequest struct {
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
	ValidYears   int      `json:"validYears"`
	KeyType      string   `json:"keyType"`
	CAName       string   `json:"caName"` // Common Name of CA
}

func handleCreateServerCert(w http.ResponseWriter, r *http.Request) {
	var req CreateServerCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CommonName == "" {
		jsonError(w, http.StatusBadRequest, "commonName is required")
		return
	}
	if req.CAName == "" {
		jsonError(w, http.StatusBadRequest, "caName is required")
		return
	}
	if req.ValidYears <= 0 {
		req.ValidYears = 5 // Default
	}
	if req.KeyType == "" {
		req.KeyType = string(KeyTypeRSA2048) // Default
	}

	// Load CA
	caCert, err := GetCertificateByCN(context.Background(), req.CAName)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load CA from DB: %v", err))
		return
	}
	if caCert == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("CA '%s' not found", req.CAName))
		return
	}

	ca, err := LoadCAFromFiles(caCert.CertPath, caCert.KeyPath)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load CA files: %v", err))
		return
	}

	// Parse IPs
	var ips []net.IP
	for _, ipStr := range req.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("invalid IP address: %s", ipStr))
			return
		}
		ips = append(ips, ip)
	}

	// Create Server Cert options
	opts := DefaultServerCertOptions(req.CommonName)
	if req.Organization != "" {
		opts.Subject.Organization = []string{req.Organization}
	}
	opts.DNSNames = req.DNSNames
	opts.IPAddresses = ips
	opts.ValidYears = req.ValidYears
	opts.KeyType = KeyType(req.KeyType)

	cert, err := ca.GenerateServerCertificateWithOptions(opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate server certificate: %v", err))
		return
	}

	// Save files
	saveDir := defaultServerDir
	saveDir = filepath.Join(saveDir, strings.ReplaceAll(req.CommonName, " ", "_"))

	if err := os.MkdirAll(saveDir, 0755); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create directory: %v", err))
		return
	}

	certPath := filepath.Join(saveDir, "server-cert.pem")
	keyPath := filepath.Join(saveDir, "server-key.pem")
	metadataPath := filepath.Join(saveDir, ".metadata.json")

	if err := cert.SaveServerCertToFiles(certPath, keyPath); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save server certificate files: %v", err))
		return
	}

	// Calculate fingerprint
	fingerprint, err := CalculateFingerprint(certPath)
	if err != nil {
		fingerprint = "unknown"
	}

	// Save metadata
	metadata := CertMetadata{
		Type:              "server",
		CommonName:        req.CommonName,
		Organization:      req.Organization,
		DNSNames:          req.DNSNames,
		IPAddresses:       req.IPAddresses,
		KeyType:           req.KeyType,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().AddDate(req.ValidYears, 0, 0),
		SerialNumber:      cert.Certificate.SerialNumber.String(),
		FingerprintSHA256: fingerprint,
		CertPath:          certPath,
		KeyPath:           keyPath,
		Issuer:            req.CAName,
	}

	if err := SaveMetadata(&metadata, metadataPath); err != nil {
		fmt.Printf("Warning: Could not save metadata: %v\n", err)
	}

	// Save to DB
	if err := SaveCertificateToDB(context.Background(), metadata); err != nil {
		fmt.Printf("Warning: Could not save to database: %v\n", err)
	}

	jsonResponse(w, http.StatusCreated, SuccessResponse{
		Message: "Server certificate created successfully",
		Data:    metadata,
	})
}

func handleListServerCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := ListCertificates(context.Background(), "server")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list server certs: %v", err))
		return
	}
	jsonResponse(w, http.StatusOK, SuccessResponse{
		Message: "Server certificates listed successfully",
		Data:    certs,
	})
}

type CreateClientCertRequest struct {
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
	ValidYears   int      `json:"validYears"`
	KeyType      string   `json:"keyType"`
	CAName       string   `json:"caName"` // Common Name of CA
}

func handleCreateClientCert(w http.ResponseWriter, r *http.Request) {
	var req CreateClientCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CommonName == "" {
		jsonError(w, http.StatusBadRequest, "commonName is required")
		return
	}
	if req.CAName == "" {
		jsonError(w, http.StatusBadRequest, "caName is required")
		return
	}
	if req.ValidYears <= 0 {
		req.ValidYears = 5 // Default
	}
	if req.KeyType == "" {
		req.KeyType = string(KeyTypeRSA2048) // Default
	}

	// Load CA
	caCert, err := GetCertificateByCN(context.Background(), req.CAName)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load CA from DB: %v", err))
		return
	}
	if caCert == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("CA '%s' not found", req.CAName))
		return
	}

	ca, err := LoadCAFromFiles(caCert.CertPath, caCert.KeyPath)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load CA files: %v", err))
		return
	}

	// Parse IPs
	var ips []net.IP
	for _, ipStr := range req.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("invalid IP address: %s", ipStr))
			return
		}
		ips = append(ips, ip)
	}

	// Create Client Cert options
	opts := DefaultClientCertOptions(req.CommonName)
	if req.Organization != "" {
		opts.Subject.Organization = []string{req.Organization}
	}
	opts.DNSNames = req.DNSNames
	opts.IPAddresses = ips
	opts.ValidYears = req.ValidYears
	opts.KeyType = KeyType(req.KeyType)

	cert, err := ca.GenerateClientCertificateWithOptions(opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate client certificate: %v", err))
		return
	}

	// Save files
	saveDir := defaultClientDir
	saveDir = filepath.Join(saveDir, strings.ReplaceAll(req.CommonName, " ", "_"))

	if err := os.MkdirAll(saveDir, 0755); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create directory: %v", err))
		return
	}

	certPath := filepath.Join(saveDir, "client-cert.pem")
	keyPath := filepath.Join(saveDir, "client-key.pem")
	metadataPath := filepath.Join(saveDir, ".metadata.json")

	if err := cert.SaveClientCertToFiles(certPath, keyPath); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save client certificate files: %v", err))
		return
	}

	// Calculate fingerprint
	fingerprint, err := CalculateFingerprint(certPath)
	if err != nil {
		fingerprint = "unknown"
	}

	// Save metadata
	metadata := CertMetadata{
		Type:              "client",
		CommonName:        req.CommonName,
		Organization:      req.Organization,
		DNSNames:          req.DNSNames,
		IPAddresses:       req.IPAddresses,
		KeyType:           req.KeyType,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().AddDate(req.ValidYears, 0, 0),
		SerialNumber:      cert.Certificate.SerialNumber.String(),
		FingerprintSHA256: fingerprint,
		CertPath:          certPath,
		KeyPath:           keyPath,
		Issuer:            req.CAName,
	}

	if err := SaveMetadata(&metadata, metadataPath); err != nil {
		fmt.Printf("Warning: Could not save metadata: %v\n", err)
	}

	// Save to DB
	if err := SaveCertificateToDB(context.Background(), metadata); err != nil {
		fmt.Printf("Warning: Could not save to database: %v\n", err)
	}

	jsonResponse(w, http.StatusCreated, SuccessResponse{
		Message: "Client certificate created successfully",
		Data:    metadata,
	})
}

func handleListClientCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := ListCertificates(context.Background(), "client")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list client certs: %v", err))
		return
	}
	jsonResponse(w, http.StatusOK, SuccessResponse{
		Message: "Client certificates listed successfully",
		Data:    certs,
	})
}
