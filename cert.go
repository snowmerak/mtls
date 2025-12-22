package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertificateAuthority represents a Certificate Authority
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey // Can be *rsa.PrivateKey or *ecdsa.PrivateKey
	Chain       []*x509.Certificate
}

// ServerCertificate represents a server certificate with its private key
type ServerCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey // Can be *rsa.PrivateKey or *ecdsa.PrivateKey
	Chain       []*x509.Certificate
}

// ClientCertificate represents a client certificate with its private key
type ClientCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey // Can be *rsa.PrivateKey or *ecdsa.PrivateKey
	Chain       []*x509.Certificate
}

// KeyType represents the type of cryptographic key to use
type KeyType string

const (
	KeyTypeRSA2048 KeyType = "rsa2048"
	KeyTypeRSA4096 KeyType = "rsa4096"
	KeyTypeECP256  KeyType = "ecp256" // ECDSA P-256
	KeyTypeECP384  KeyType = "ecp384" // ECDSA P-384
	KeyTypeECP521  KeyType = "ecp521" // ECDSA P-521
)

// CAOptions contains options for generating a Certificate Authority
type CAOptions struct {
	// Subject information
	Subject pkix.Name

	// Validity period in years
	ValidYears int

	// Key type and size
	KeyType KeyType

	// Serial number (if nil, will be set to 1)
	SerialNumber *big.Int

	// Key usage (if nil, will use default CA key usages)
	KeyUsage *x509.KeyUsage

	// Extended key usage (if nil, will use default)
	ExtKeyUsage []x509.ExtKeyUsage

	// Maximum path length for certificate chain
	MaxPathLen int
}

// ServerCertOptions contains options for generating a server certificate
type ServerCertOptions struct {
	// Subject information
	Subject pkix.Name

	// DNS names for Subject Alternative Names
	DNSNames []string

	// IP addresses for Subject Alternative Names
	IPAddresses []net.IP

	// Validity period in years
	ValidYears int

	// Key type and size
	KeyType KeyType

	// Key usage (if nil, will use default server key usages)
	KeyUsage *x509.KeyUsage

	// Extended key usage (if nil, will use default)
	ExtKeyUsage []x509.ExtKeyUsage
}

// ClientCertOptions contains options for generating a client certificate
type ClientCertOptions struct {
	// Subject information
	Subject pkix.Name

	// Validity period in years
	ValidYears int

	// Key type and size
	KeyType KeyType

	// Key usage (if nil, will use default client key usages)
	KeyUsage *x509.KeyUsage

	// Extended key usage (if nil, will use default)
	ExtKeyUsage []x509.ExtKeyUsage
}

// DefaultCAOptions returns default options for CA generation
func DefaultCAOptions(commonName string) *CAOptions {
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	return &CAOptions{
		Subject: pkix.Name{
			Country:            []string{"KR"},
			Organization:       []string{"Self-Signed CA"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         commonName,
		},
		ValidYears:  10,
		KeyType:     KeyTypeRSA4096,
		KeyUsage:    &keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		MaxPathLen:  1,
	}
}

// DefaultServerCertOptions returns default options for server certificate generation
func DefaultServerCertOptions(commonName string) *ServerCertOptions {
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	return &ServerCertOptions{
		Subject: pkix.Name{
			Country:            []string{"KR"},
			Organization:       []string{"Server Certificate"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         commonName,
		},
		ValidYears:  5,
		KeyType:     KeyTypeRSA2048,
		KeyUsage:    &keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// DefaultClientCertOptions returns default options for client certificate generation
func DefaultClientCertOptions(commonName string) *ClientCertOptions {
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	return &ClientCertOptions{
		Subject: pkix.Name{
			Country:            []string{"KR"},
			Organization:       []string{"Client Certificate"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         commonName,
		},
		ValidYears:  5,
		KeyType:     KeyTypeRSA2048,
		KeyUsage:    &keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// generatePrivateKey generates a private key based on the specified key type
func generatePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyTypeECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeECP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// getPublicKey extracts the public key from a private key
func getPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// GenerateRootCA creates a self-signed root CA certificate
func GenerateRootCA(commonName string, validYears int) (*CertificateAuthority, error) {
	opts := DefaultCAOptions(commonName)
	opts.ValidYears = validYears
	return GenerateRootCAWithOptions(opts)
}

// GenerateRootCAWithOptions creates a self-signed root CA certificate with custom options
func GenerateRootCAWithOptions(opts *CAOptions) (*CertificateAuthority, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Generate private key
	privateKey, err := generatePrivateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get public key
	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Set serial number
	serialNumber := opts.SerialNumber
	if serialNumber == nil {
		serialNumber = big.NewInt(1)
	}

	// Set key usage
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if opts.KeyUsage != nil {
		keyUsage = *opts.KeyUsage
	}

	// Set extended key usage
	extKeyUsage := opts.ExtKeyUsage
	if extKeyUsage == nil {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               opts.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(opts.ValidYears, 0, 0),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            opts.MaxPathLen,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateAuthority{
		Chain:       []*x509.Certificate{cert},
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// GenerateIntermediateCA creates an intermediate CA certificate signed by the parent CA
func (ca *CertificateAuthority) GenerateIntermediateCA(commonName string, validYears int) (*CertificateAuthority, error) {
	opts := DefaultCAOptions(commonName)
	opts.ValidYears = validYears
	// Intermediate CA usually has pathlen constraint less than parent
	if ca.Certificate.BasicConstraintsValid && ca.Certificate.MaxPathLen > 0 {
		opts.MaxPathLen = ca.Certificate.MaxPathLen - 1
	} else {
		opts.MaxPathLen = 0
	}
	return ca.GenerateIntermediateCAWithOptions(opts)
}

// GenerateIntermediateCAWithOptions creates an intermediate CA certificate signed by the parent CA with custom options
func (ca *CertificateAuthority) GenerateIntermediateCAWithOptions(opts *CAOptions) (*CertificateAuthority, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Generate private key for intermediate CA
	privateKey, err := generatePrivateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate CA private key: %w", err)
	}

	// Get public key
	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Generate serial number
	serialNumber := opts.SerialNumber
	if serialNumber == nil {
		var err error
		serialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
	}

	// Set key usage
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if opts.KeyUsage != nil {
		keyUsage = *opts.KeyUsage
	}

	// Set extended key usage
	extKeyUsage := opts.ExtKeyUsage
	if extKeyUsage == nil {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               opts.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(opts.ValidYears, 0, 0),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            opts.MaxPathLen,
	}

	// Get CA private key as crypto.Signer
	caSigner, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key does not implement crypto.Signer")
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}
	chain := append([]*x509.Certificate{cert}, ca.Chain...)

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privateKey,
		Chain:       chain,
	}, nil
}

// GenerateServerCertificate creates a server certificate signed by the CA
func (ca *CertificateAuthority) GenerateServerCertificate(commonName string, dnsNames []string, ipAddresses []net.IP, validYears int) (*ServerCertificate, error) {
	opts := DefaultServerCertOptions(commonName)
	opts.DNSNames = dnsNames
	opts.IPAddresses = ipAddresses
	opts.ValidYears = validYears
	return ca.GenerateServerCertificateWithOptions(opts)
}

// GenerateServerCertificateWithOptions creates a server certificate signed by the CA with custom options
func (ca *CertificateAuthority) GenerateServerCertificateWithOptions(opts *ServerCertOptions) (*ServerCertificate, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Generate private key for server
	privateKey, err := generatePrivateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Get public key
	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Set key usage
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if opts.KeyUsage != nil {
		keyUsage = *opts.KeyUsage
	}

	// Set extended key usage
	extKeyUsage := opts.ExtKeyUsage
	if extKeyUsage == nil {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      opts.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(opts.ValidYears, 0, 0),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  extKeyUsage,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPAddresses,
	}

	// Get CA private key as crypto.Signer
	caSigner, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key does not implement crypto.Signer")
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	chain := append([]*x509.Certificate{cert}, ca.Chain...)

	return &ServerCertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		Chain:       chain,
	}, nil
}

// GenerateClientCertificate creates a client certificate signed by the CA
func (ca *CertificateAuthority) GenerateClientCertificate(commonName string, validYears int) (*ClientCertificate, error) {
	opts := DefaultClientCertOptions(commonName)
	opts.ValidYears = validYears
	return ca.GenerateClientCertificateWithOptions(opts)
}

// GenerateClientCertificateWithOptions creates a client certificate signed by the CA with custom options
func (ca *CertificateAuthority) GenerateClientCertificateWithOptions(opts *ClientCertOptions) (*ClientCertificate, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Generate private key for client
	privateKey, err := generatePrivateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Get public key
	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Set key usage
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if opts.KeyUsage != nil {
		keyUsage = *opts.KeyUsage
	}

	// Set extended key usage
	extKeyUsage := opts.ExtKeyUsage
	if extKeyUsage == nil {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      opts.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(opts.ValidYears, 0, 0),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  extKeyUsage,
	}

	// Get CA private key as crypto.Signer
	caSigner, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key does not implement crypto.Signer")
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	chain := append([]*x509.Certificate{cert}, ca.Chain...)

	return &ClientCertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		Chain:       chain,
	}, nil
}

// SignCSR signs a Certificate Signing Request and returns a certificate
func (ca *CertificateAuthority) SignCSR(csr *x509.CertificateRequest, validYears int) (*x509.Certificate, error) {
	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(validYears, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	// Get CA private key as crypto.Signer
	caSigner, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key does not implement crypto.Signer")
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// LoadCSRFromFile loads a CSR from a file
func LoadCSRFromFile(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSR file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, nil
}

// SaveCertificateToFile saves a certificate to a file
func SaveCertificateToFile(cert *x509.Certificate, path string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// SaveCAToFiles saves the CA certificate and private key to files
func (ca *CertificateAuthority) SaveCAToFiles(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save full chain to certPath
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	// Use Chain if available, otherwise just Certificate
	certsToWrite := ca.Chain
	if len(certsToWrite) == 0 {
		certsToWrite = []*x509.Certificate{ca.Certificate}
	}

	for _, cert := range certsToWrite {
		if err := pem.Encode(certOut, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to write certificate chain: %w", err)
		}
	}

	// Save leaf certificate separately
	ext := filepath.Ext(certPath)
	base := certPath[:len(certPath)-len(ext)]
	leafPath := base + "-leaf" + ext

	leafOut, err := os.Create(leafPath)
	if err != nil {
		return fmt.Errorf("failed to create leaf cert file: %w", err)
	}
	defer leafOut.Close()

	if err := pem.Encode(leafOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate.Raw,
	}); err != nil {
		return fmt.Errorf("failed to write leaf certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	return nil
}

// SaveClientCertToFiles saves the client certificate and private key to files
func (cc *ClientCertificate) SaveClientCertToFiles(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save full chain to certPath
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	// Use Chain if available, otherwise just Certificate
	certsToWrite := cc.Chain
	if len(certsToWrite) == 0 {
		certsToWrite = []*x509.Certificate{cc.Certificate}
	}

	for _, cert := range certsToWrite {
		if err := pem.Encode(certOut, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to write certificate chain: %w", err)
		}
	}

	// Save leaf certificate separately
	ext := filepath.Ext(certPath)
	base := certPath[:len(certPath)-len(ext)]
	leafPath := base + "-leaf" + ext

	leafOut, err := os.Create(leafPath)
	if err != nil {
		return fmt.Errorf("failed to create leaf cert file: %w", err)
	}
	defer leafOut.Close()

	if err := pem.Encode(leafOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cc.Certificate.Raw,
	}); err != nil {
		return fmt.Errorf("failed to write leaf certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(cc.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	return nil
}

// SaveServerCertToFiles saves the server certificate and private key to files
func (sc *ServerCertificate) SaveServerCertToFiles(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save full chain to certPath
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	// Use Chain if available, otherwise just Certificate
	certsToWrite := sc.Chain
	if len(certsToWrite) == 0 {
		certsToWrite = []*x509.Certificate{sc.Certificate}
	}

	for _, cert := range certsToWrite {
		if err := pem.Encode(certOut, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to write certificate chain: %w", err)
		}
	}

	// Save leaf certificate separately
	ext := filepath.Ext(certPath)
	base := certPath[:len(certPath)-len(ext)]
	leafPath := base + "-leaf" + ext

	leafOut, err := os.Create(leafPath)
	if err != nil {
		return fmt.Errorf("failed to create leaf cert file: %w", err)
	}
	defer leafOut.Close()

	if err := pem.Encode(leafOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: sc.Certificate.Raw,
	}); err != nil {
		return fmt.Errorf("failed to write leaf certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(sc.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	return nil
}

// LoadCAFromFiles loads CA certificate and private key from files
func LoadCAFromFiles(certPath, keyPath string) (*CertificateAuthority, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Verify the private key is supported (RSA or ECDSA)
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		// Supported key types
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}

	// Try to load full chain
	var chain []*x509.Certificate
	chainPath := filepath.Join(filepath.Dir(certPath), "fullchain.pem")
	chainPEM, err := os.ReadFile(chainPath)
	if err == nil {
		// Parse all certificates in the chain
		var block *pem.Block
		rest := chainPEM
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					chain = append(chain, c)
				}
			}
		}
	} else {
		// If no chain file, assume self-signed root
		chain = []*x509.Certificate{cert}
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privateKey,
		Chain:       chain,
	}, nil
}

// GenerateCRL creates a Certificate Revocation List
func (ca *CertificateAuthority) GenerateCRL(revokedCerts []pkix.RevokedCertificate, validDays int) ([]byte, error) {
	// Get CA private key as crypto.Signer
	caSigner, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key does not implement crypto.Signer")
	}

	now := time.Now()
	expiry := now.AddDate(0, 0, validDays)

	crlBytes, err := ca.Certificate.CreateCRL(rand.Reader, caSigner, revokedCerts, now, expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	return crlBytes, nil
}

// VerifyCertificate verifies a certificate against a CA chain
func VerifyCertificate(rootPEM, interPEM, certPEM []byte) error {
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootPEM); !ok {
		return fmt.Errorf("failed to parse root certificate")
	}

	intermediates := x509.NewCertPool()
	if len(interPEM) > 0 {
		if ok := intermediates.AppendCertsFromPEM(interPEM); !ok {
			return fmt.Errorf("failed to parse intermediate certificates")
		}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

// InspectCertificate returns a human-readable string of the certificate
func InspectCertificate(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	var out string
	out += fmt.Sprintf("Subject: %s\n", cert.Subject)
	out += fmt.Sprintf("Issuer: %s\n", cert.Issuer)
	out += fmt.Sprintf("Serial Number: %s\n", cert.SerialNumber)
	out += fmt.Sprintf("Not Before: %s\n", cert.NotBefore)
	out += fmt.Sprintf("Not After: %s\n", cert.NotAfter)
	out += fmt.Sprintf("DNS Names: %v\n", cert.DNSNames)
	out += fmt.Sprintf("IP Addresses: %v\n", cert.IPAddresses)
	out += fmt.Sprintf("Key Usage: %v\n", cert.KeyUsage)
	out += fmt.Sprintf("Ext Key Usage: %v\n", cert.ExtKeyUsage)
	out += fmt.Sprintf("Is CA: %v\n", cert.IsCA)

	return out, nil
}

// CreateMTLSCertificates is a convenience function to create a complete mTLS certificate setup
func CreateMTLSCertificates(caCommonName string, serverConfigs []ServerConfig, outputDir string) error {
	// Generate Root CA
	fmt.Println("Generating Root CA...")
	ca, err := GenerateRootCA(caCommonName, 10) // Valid for 10 years
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}

	// Save Root CA
	caDir := filepath.Join(outputDir, "ca")
	if err := ca.SaveCAToFiles(
		filepath.Join(caDir, "ca-cert.pem"),
		filepath.Join(caDir, "ca-key.pem"),
	); err != nil {
		return fmt.Errorf("failed to save root CA: %w", err)
	}
	fmt.Printf("Root CA saved to %s", caDir)

	// Generate server certificates
	for i, config := range serverConfigs {
		fmt.Printf("Generating server certificate %d for %s...", i+1, config.CommonName)

		serverCert, err := ca.GenerateServerCertificate(
			config.CommonName,
			config.DNSNames,
			config.IPAddresses,
			5, // Valid for 5 years
		)
		if err != nil {
			return fmt.Errorf("failed to generate server certificate for %s: %w", config.CommonName, err)
		}

		// Save server certificate
		serverDir := filepath.Join(outputDir, "servers", config.CommonName)
		if err := serverCert.SaveServerCertToFiles(
			filepath.Join(serverDir, "server-cert.pem"),
			filepath.Join(serverDir, "server-key.pem"),
		); err != nil {
			return fmt.Errorf("failed to save server certificate for %s: %w", config.CommonName, err)
		}

		// Also copy CA cert to server directory for easy access
		caCertBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Certificate.Raw,
		})
		if err := os.WriteFile(filepath.Join(serverDir, "ca-cert.pem"), caCertBytes, 0644); err != nil {
			return fmt.Errorf("failed to copy CA cert to server directory: %w", err)
		}

		fmt.Printf("Server certificate for %s saved to %s", config.CommonName, serverDir)
	}

	return nil
}

// ServerConfig holds configuration for generating server certificates
type ServerConfig struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
}
