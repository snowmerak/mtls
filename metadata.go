package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CertMetadata contains metadata about a certificate
type CertMetadata struct {
	Type              string    `json:"type"` // "ca" or "server"
	CommonName        string    `json:"common_name"`
	Organization      string    `json:"organization"`
	Country           string    `json:"country"`
	KeyType           string    `json:"key_type"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	SerialNumber      string    `json:"serial_number"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	CertPath          string    `json:"cert_path"`
	KeyPath           string    `json:"key_path"`
	Issuer            string    `json:"issuer,omitempty"` // Common Name of the issuer
	DNSNames          []string  `json:"dns_names,omitempty"`
	IPAddresses       []string  `json:"ip_addresses,omitempty"`
	CAPath            string    `json:"ca_path,omitempty"` // For server certs
	Revoked           bool      `json:"revoked,omitempty"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
}

// Registry manages all certificates and CAs
type Registry struct {
	CAs     []CertMetadata `json:"cas"`
	Servers []CertMetadata `json:"servers"`
}

// SaveMetadata saves metadata to a JSON file
func SaveMetadata(metadata *CertMetadata, path string) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// LoadMetadata loads metadata from a JSON file
func LoadMetadata(path string) (*CertMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var metadata CertMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// LoadRegistry loads the certificate registry
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{
				CAs:     []CertMetadata{},
				Servers: []CertMetadata{},
			}, nil
		}
		return nil, err
	}

	var registry Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}

	return &registry, nil
}

// SaveRegistry saves the certificate registry
func SaveRegistry(registry *Registry, path string) error {
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// AddCA adds a CA to the registry
func (r *Registry) AddCA(metadata CertMetadata) {
	r.CAs = append(r.CAs, metadata)
}

// AddServer adds a server certificate to the registry
func (r *Registry) AddServer(metadata CertMetadata) {
	r.Servers = append(r.Servers, metadata)
}

// CalculateFingerprint calculates SHA256 fingerprint of a certificate file
func CalculateFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
