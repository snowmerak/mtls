package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateRootCAWithOptions(t *testing.T) {
	t.Run("Generate CA with custom subject", func(t *testing.T) {
		opts := &CAOptions{
			Subject: pkix.Name{
				Country:            []string{"US"},
				Province:           []string{"California"},
				Locality:           []string{"San Francisco"},
				Organization:       []string{"My Custom Org"},
				OrganizationalUnit: []string{"Engineering"},
				CommonName:         "Custom Root CA",
			},
			ValidYears: 15,
			KeyType:    KeyTypeRSA4096,
			MaxPathLen: 2,
		}

		ca, err := GenerateRootCAWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate CA with options: %v", err)
		}

		if ca.Certificate.Subject.CommonName != "Custom Root CA" {
			t.Errorf("Expected CN 'Custom Root CA', got '%s'", ca.Certificate.Subject.CommonName)
		}

		if len(ca.Certificate.Subject.Country) == 0 || ca.Certificate.Subject.Country[0] != "US" {
			t.Errorf("Expected Country 'US', got '%v'", ca.Certificate.Subject.Country)
		}

		if len(ca.Certificate.Subject.Organization) == 0 || ca.Certificate.Subject.Organization[0] != "My Custom Org" {
			t.Errorf("Expected Organization 'My Custom Org', got '%v'", ca.Certificate.Subject.Organization)
		}
	})

	t.Run("Generate CA with ECDSA P-256", func(t *testing.T) {
		opts := DefaultCAOptions("ECDSA P-256 CA")
		opts.KeyType = KeyTypeECP256

		ca, err := GenerateRootCAWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA CA: %v", err)
		}

		if ca == nil || ca.Certificate == nil {
			t.Fatal("CA is nil")
		}

		// Verify it's an ECDSA key
		_, ok := ca.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Error("Private key is not ECDSA")
		}
	})

	t.Run("Generate CA with ECDSA P-384", func(t *testing.T) {
		opts := DefaultCAOptions("ECDSA P-384 CA")
		opts.KeyType = KeyTypeECP384

		ca, err := GenerateRootCAWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA P-384 CA: %v", err)
		}

		ecKey, ok := ca.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("Private key is not ECDSA")
		}

		if ecKey.Curve != elliptic.P384() {
			t.Error("Expected P-384 curve")
		}
	})

	t.Run("Generate CA with ECDSA P-521", func(t *testing.T) {
		opts := DefaultCAOptions("ECDSA P-521 CA")
		opts.KeyType = KeyTypeECP521

		ca, err := GenerateRootCAWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA P-521 CA: %v", err)
		}

		ecKey, ok := ca.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("Private key is not ECDSA")
		}

		if ecKey.Curve != elliptic.P521() {
			t.Error("Expected P-521 curve")
		}
	})

	t.Run("Generate CA with RSA 2048", func(t *testing.T) {
		opts := DefaultCAOptions("RSA 2048 CA")
		opts.KeyType = KeyTypeRSA2048

		ca, err := GenerateRootCAWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate RSA 2048 CA: %v", err)
		}

		rsaKey, ok := ca.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("Private key is not RSA")
		}

		if rsaKey.N.BitLen() != 2048 {
			t.Errorf("Expected 2048-bit key, got %d-bit", rsaKey.N.BitLen())
		}
	})
}

func TestGenerateServerCertificateWithOptions(t *testing.T) {
	// Generate CA with ECDSA
	caOpts := DefaultCAOptions("Test ECDSA CA")
	caOpts.KeyType = KeyTypeECP256
	ca, err := GenerateRootCAWithOptions(caOpts)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	t.Run("Generate server certificate with custom subject", func(t *testing.T) {
		opts := &ServerCertOptions{
			Subject: pkix.Name{
				Country:            []string{"JP"},
				Province:           []string{"Tokyo"},
				Locality:           []string{"Shibuya"},
				Organization:       []string{"Custom Server Org"},
				OrganizationalUnit: []string{"DevOps"},
				CommonName:         "api.example.jp",
			},
			DNSNames:    []string{"api.example.jp", "*.api.example.jp"},
			IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
			ValidYears:  3,
			KeyType:     KeyTypeECP256,
		}

		serverCert, err := ca.GenerateServerCertificateWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate server certificate: %v", err)
		}

		if serverCert.Certificate.Subject.CommonName != "api.example.jp" {
			t.Errorf("Expected CN 'api.example.jp', got '%s'", serverCert.Certificate.Subject.CommonName)
		}

		if len(serverCert.Certificate.Subject.Country) == 0 || serverCert.Certificate.Subject.Country[0] != "JP" {
			t.Errorf("Expected Country 'JP', got '%v'", serverCert.Certificate.Subject.Country)
		}

		// Verify it's an ECDSA key
		_, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Error("Server private key is not ECDSA")
		}
	})

	t.Run("Generate server certificate with RSA from ECDSA CA", func(t *testing.T) {
		opts := DefaultServerCertOptions("rsa.example.com")
		opts.KeyType = KeyTypeRSA2048
		opts.DNSNames = []string{"rsa.example.com"}

		serverCert, err := ca.GenerateServerCertificateWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate RSA server certificate from ECDSA CA: %v", err)
		}

		// Verify server uses RSA
		_, ok := serverCert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Error("Server private key is not RSA")
		}

		// Verify certificate was signed by ECDSA CA
		if err := serverCert.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
			t.Errorf("Certificate signature verification failed: %v", err)
		}
	})
}

func TestSaveAndLoadECDSACA(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mtls-test-ecdsa-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	// Generate ECDSA CA
	opts := DefaultCAOptions("ECDSA Test CA")
	opts.KeyType = KeyTypeECP256
	originalCA, err := GenerateRootCAWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA CA: %v", err)
	}

	// Save CA
	if err := originalCA.SaveCAToFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to save ECDSA CA: %v", err)
	}

	// Load CA
	loadedCA, err := LoadCAFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load ECDSA CA: %v", err)
	}

	// Verify loaded CA is ECDSA
	_, ok := loadedCA.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("Loaded CA private key is not ECDSA")
	}

	// Verify we can use the loaded CA to sign certificates
	serverOpts := DefaultServerCertOptions("test.example.com")
	serverCert, err := loadedCA.GenerateServerCertificateWithOptions(serverOpts)
	if err != nil {
		t.Fatalf("Failed to generate server certificate with loaded ECDSA CA: %v", err)
	}

	if serverCert == nil {
		t.Fatal("Server certificate is nil")
	}
}

func TestMixedKeyTypes(t *testing.T) {
	t.Run("RSA CA with ECDSA server cert", func(t *testing.T) {
		// Create RSA CA
		caOpts := DefaultCAOptions("RSA CA")
		caOpts.KeyType = KeyTypeRSA2048
		ca, err := GenerateRootCAWithOptions(caOpts)
		if err != nil {
			t.Fatalf("Failed to generate RSA CA: %v", err)
		}

		// Create ECDSA server certificate
		serverOpts := DefaultServerCertOptions("ecdsa-server.com")
		serverOpts.KeyType = KeyTypeECP256
		serverCert, err := ca.GenerateServerCertificateWithOptions(serverOpts)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA server cert from RSA CA: %v", err)
		}

		// Verify key types
		_, caIsRSA := ca.PrivateKey.(*rsa.PrivateKey)
		_, serverIsECDSA := serverCert.PrivateKey.(*ecdsa.PrivateKey)

		if !caIsRSA {
			t.Error("CA should be RSA")
		}
		if !serverIsECDSA {
			t.Error("Server should be ECDSA")
		}

		// Verify signature
		if err := serverCert.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	t.Run("ECDSA CA with RSA server cert", func(t *testing.T) {
		// Create ECDSA CA
		caOpts := DefaultCAOptions("ECDSA CA")
		caOpts.KeyType = KeyTypeECP384
		ca, err := GenerateRootCAWithOptions(caOpts)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA CA: %v", err)
		}

		// Create RSA server certificate
		serverOpts := DefaultServerCertOptions("rsa-server.com")
		serverOpts.KeyType = KeyTypeRSA4096
		serverCert, err := ca.GenerateServerCertificateWithOptions(serverOpts)
		if err != nil {
			t.Fatalf("Failed to generate RSA server cert from ECDSA CA: %v", err)
		}

		// Verify key types
		_, caIsECDSA := ca.PrivateKey.(*ecdsa.PrivateKey)
		_, serverIsRSA := serverCert.PrivateKey.(*rsa.PrivateKey)

		if !caIsECDSA {
			t.Error("CA should be ECDSA")
		}
		if !serverIsRSA {
			t.Error("Server should be RSA")
		}

		// Verify signature
		if err := serverCert.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})
}

func TestIPOnlyServerCertificate(t *testing.T) {
	// Generate CA
	ca, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	t.Run("Server certificate with only IP addresses", func(t *testing.T) {
		opts := DefaultServerCertOptions("10.0.0.1")
		opts.DNSNames = nil // No DNS names
		opts.IPAddresses = []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("192.168.1.100"),
			net.ParseIP("::1"),
		}

		serverCert, err := ca.GenerateServerCertificateWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate IP-only server certificate: %v", err)
		}

		if serverCert == nil {
			t.Fatal("Server certificate is nil")
		}

		// Verify no DNS names
		if len(serverCert.Certificate.DNSNames) != 0 {
			t.Errorf("Expected no DNS names, got %d", len(serverCert.Certificate.DNSNames))
		}

		// Verify IP addresses
		if len(serverCert.Certificate.IPAddresses) != 3 {
			t.Fatalf("Expected 3 IP addresses, got %d", len(serverCert.Certificate.IPAddresses))
		}

		// Verify specific IPs
		expectedIPs := []string{"10.0.0.1", "192.168.1.100", "::1"}
		for i, ip := range serverCert.Certificate.IPAddresses {
			if ip.String() != expectedIPs[i] {
				t.Errorf("Expected IP %s, got %s", expectedIPs[i], ip.String())
			}
		}

		// Verify certificate chain
		if err := serverCert.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
			t.Errorf("Certificate signature verification failed: %v", err)
		}
	})

	t.Run("Verify certificate with IP address", func(t *testing.T) {
		opts := DefaultServerCertOptions("192.168.1.50")
		opts.DNSNames = nil
		opts.IPAddresses = []net.IP{net.ParseIP("192.168.1.50")}

		serverCert, err := ca.GenerateServerCertificateWithOptions(opts)
		if err != nil {
			t.Fatalf("Failed to generate server certificate: %v", err)
		}

		// Create a certificate pool with the CA
		roots := x509.NewCertPool()
		roots.AddCert(ca.Certificate)

		// Verify the server certificate against the CA with IP verification
		verifyOpts := x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		// Note: x509.VerifyOptions doesn't have a direct IP verification field,
		// but the certificate will be valid for the IP in IPAddresses
		if _, err := serverCert.Certificate.Verify(verifyOpts); err != nil {
			t.Errorf("Server certificate verification failed: %v", err)
		}

		// Verify the IP is in the certificate
		found := false
		targetIP := net.ParseIP("192.168.1.50")
		for _, ip := range serverCert.Certificate.IPAddresses {
			if ip.Equal(targetIP) {
				found = true
				break
			}
		}
		if !found {
			t.Error("Target IP not found in certificate")
		}
	})
}

func TestGenerateRootCA(t *testing.T) {
	t.Run("Generate valid root CA", func(t *testing.T) {
		ca, err := GenerateRootCA("Test Root CA", 10)
		if err != nil {
			t.Fatalf("Failed to generate root CA: %v", err)
		}

		if ca == nil {
			t.Fatal("CA is nil")
		}

		if ca.Certificate == nil {
			t.Fatal("CA certificate is nil")
		}

		if ca.PrivateKey == nil {
			t.Fatal("CA private key is nil")
		}

		// Verify it's a CA certificate
		if !ca.Certificate.IsCA {
			t.Error("Certificate is not marked as CA")
		}

		// Verify key usage
		if ca.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Error("Certificate does not have CertSign key usage")
		}

		// Verify common name
		if ca.Certificate.Subject.CommonName != "Test Root CA" {
			t.Errorf("Expected CN 'Test Root CA', got '%s'", ca.Certificate.Subject.CommonName)
		}
	})

	t.Run("Generate CA with different validity periods", func(t *testing.T) {
		testCases := []int{1, 5, 10, 20}
		for _, years := range testCases {
			ca, err := GenerateRootCA("Test CA", years)
			if err != nil {
				t.Fatalf("Failed to generate CA with %d years validity: %v", years, err)
			}

			if ca == nil {
				t.Fatalf("CA is nil for %d years validity", years)
			}
		}
	})
}

func TestGenerateServerCertificate(t *testing.T) {
	// First, create a CA
	ca, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	t.Run("Generate valid server certificate", func(t *testing.T) {
		dnsNames := []string{"localhost", "example.com", "*.example.com"}
		ipAddresses := []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("192.168.1.100"),
		}

		serverCert, err := ca.GenerateServerCertificate(
			"example.com",
			dnsNames,
			ipAddresses,
			5,
		)

		if err != nil {
			t.Fatalf("Failed to generate server certificate: %v", err)
		}

		if serverCert == nil {
			t.Fatal("Server certificate is nil")
		}

		if serverCert.Certificate == nil {
			t.Fatal("Server certificate is nil")
		}

		if serverCert.PrivateKey == nil {
			t.Fatal("Server private key is nil")
		}

		// Verify it's NOT a CA certificate
		if serverCert.Certificate.IsCA {
			t.Error("Server certificate is incorrectly marked as CA")
		}

		// Verify DNS names
		if len(serverCert.Certificate.DNSNames) != len(dnsNames) {
			t.Errorf("Expected %d DNS names, got %d", len(dnsNames), len(serverCert.Certificate.DNSNames))
		}

		// Verify IP addresses
		if len(serverCert.Certificate.IPAddresses) != len(ipAddresses) {
			t.Errorf("Expected %d IP addresses, got %d", len(ipAddresses), len(serverCert.Certificate.IPAddresses))
		}

		// Verify the certificate was signed by the CA
		if err := serverCert.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
			t.Errorf("Server certificate signature verification failed: %v", err)
		}
	})

	t.Run("Generate server certificate with no DNS names or IPs", func(t *testing.T) {
		serverCert, err := ca.GenerateServerCertificate(
			"simple.example.com",
			nil,
			nil,
			5,
		)

		if err != nil {
			t.Fatalf("Failed to generate simple server certificate: %v", err)
		}

		if serverCert == nil {
			t.Fatal("Server certificate is nil")
		}
	})
}

func TestSaveAndLoadCA(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "mtls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	// Generate CA
	originalCA, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Save CA to files
	if err := originalCA.SaveCAToFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to save CA to files: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file was not created: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file was not created: %s", keyPath)
	}

	// Load CA from files
	loadedCA, err := LoadCAFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load CA from files: %v", err)
	}

	// Verify loaded CA matches original
	if loadedCA.Certificate.Subject.CommonName != originalCA.Certificate.Subject.CommonName {
		t.Errorf("Loaded CA CN doesn't match: expected '%s', got '%s'",
			originalCA.Certificate.Subject.CommonName,
			loadedCA.Certificate.Subject.CommonName)
	}

	if !loadedCA.Certificate.Equal(originalCA.Certificate) {
		t.Error("Loaded certificate does not match original")
	}

	// Verify we can use the loaded CA to sign certificates
	serverCert, err := loadedCA.GenerateServerCertificate(
		"test.example.com",
		[]string{"test.example.com"},
		nil,
		5,
	)
	if err != nil {
		t.Fatalf("Failed to generate server certificate with loaded CA: %v", err)
	}

	if serverCert == nil {
		t.Fatal("Server certificate is nil")
	}
}

func TestSaveServerCert(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "mtls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate CA and server certificate
	ca, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	serverCert, err := ca.GenerateServerCertificate(
		"test.example.com",
		[]string{"test.example.com", "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		5,
	)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Save server certificate
	certPath := filepath.Join(tmpDir, "server-cert.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")

	if err := serverCert.SaveServerCertToFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to save server certificate: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file was not created: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file was not created: %s", keyPath)
	}

	// Verify file permissions on key
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	expectedPerm := os.FileMode(0600)
	if keyInfo.Mode().Perm() != expectedPerm {
		t.Errorf("Key file has wrong permissions: expected %o, got %o",
			expectedPerm, keyInfo.Mode().Perm())
	}
}

func TestCreateMTLSCertificates(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "mtls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Define server configurations
	serverConfigs := []ServerConfig{
		{
			CommonName:  "server1.local",
			DNSNames:    []string{"server1.local", "localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		},
		{
			CommonName:  "server2.local",
			DNSNames:    []string{"server2.local", "localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		},
	}

	// Create certificates
	if err := CreateMTLSCertificates("Test Root CA", serverConfigs, tmpDir); err != nil {
		t.Fatalf("Failed to create mTLS certificates: %v", err)
	}

	// Verify CA files exist
	caDir := filepath.Join(tmpDir, "ca")
	caCertPath := filepath.Join(caDir, "ca-cert.pem")
	caKeyPath := filepath.Join(caDir, "ca-key.pem")

	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Errorf("CA certificate was not created: %s", caCertPath)
	}

	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Errorf("CA key was not created: %s", caKeyPath)
	}

	// Verify server certificate files exist
	for _, config := range serverConfigs {
		serverDir := filepath.Join(tmpDir, "servers", config.CommonName)
		serverCertPath := filepath.Join(serverDir, "server-cert.pem")
		serverKeyPath := filepath.Join(serverDir, "server-key.pem")
		caCertCopyPath := filepath.Join(serverDir, "ca-cert.pem")

		if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
			t.Errorf("Server certificate was not created for %s: %s", config.CommonName, serverCertPath)
		}

		if _, err := os.Stat(serverKeyPath); os.IsNotExist(err) {
			t.Errorf("Server key was not created for %s: %s", config.CommonName, serverKeyPath)
		}

		if _, err := os.Stat(caCertCopyPath); os.IsNotExist(err) {
			t.Errorf("CA certificate copy was not created for %s: %s", config.CommonName, caCertCopyPath)
		}
	}

	// Load CA and verify it can validate server certificates
	ca, err := LoadCAFromFiles(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	// Test generating a new server certificate with the loaded CA
	newServerCert, err := ca.GenerateServerCertificate(
		"new-server.local",
		[]string{"new-server.local"},
		nil,
		5,
	)
	if err != nil {
		t.Fatalf("Failed to generate new server certificate: %v", err)
	}

	if newServerCert == nil {
		t.Fatal("New server certificate is nil")
	}
}

func TestCertificateChainValidation(t *testing.T) {
	// Generate CA
	ca, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Generate server certificate
	serverCert, err := ca.GenerateServerCertificate(
		"test.example.com",
		[]string{"test.example.com"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		5,
	)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Create a certificate pool with the CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	// Verify the server certificate against the CA
	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "test.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := serverCert.Certificate.Verify(opts); err != nil {
		t.Errorf("Server certificate verification failed: %v", err)
	}
}

func BenchmarkGenerateRootCA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateRootCA("Benchmark Root CA", 10)
		if err != nil {
			b.Fatalf("Failed to generate root CA: %v", err)
		}
	}
}

func BenchmarkGenerateServerCertificate(b *testing.B) {
	ca, err := GenerateRootCA("Benchmark Root CA", 10)
	if err != nil {
		b.Fatalf("Failed to generate root CA: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ca.GenerateServerCertificate(
			"test.example.com",
			[]string{"test.example.com"},
			[]net.IP{net.ParseIP("127.0.0.1")},
			5,
		)
		if err != nil {
			b.Fatalf("Failed to generate server certificate: %v", err)
		}
	}
}

func TestIntermediateCA(t *testing.T) {
	// 1. Generate Root CA
	rootCA, err := GenerateRootCA("Test Root CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// 2. Generate Intermediate CA
	interCA, err := rootCA.GenerateIntermediateCA("Test Intermediate CA", 5)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA: %v", err)
	}

	// Verify Intermediate CA properties
	if !interCA.Certificate.IsCA {
		t.Error("Intermediate certificate is not marked as CA")
	}
	if interCA.Certificate.Issuer.CommonName != "Test Root CA" {
		t.Errorf("Expected Issuer 'Test Root CA', got '%s'", interCA.Certificate.Issuer.CommonName)
	}
	if interCA.Certificate.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Expected Subject 'Test Intermediate CA', got '%s'", interCA.Certificate.Subject.CommonName)
	}

	// Verify Chain
	if len(interCA.Chain) != 2 {
		t.Errorf("Expected chain length 2, got %d", len(interCA.Chain))
	}
	if !interCA.Chain[0].Equal(interCA.Certificate) {
		t.Error("First cert in chain should be intermediate cert")
	}
	if !interCA.Chain[1].Equal(rootCA.Certificate) {
		t.Error("Second cert in chain should be root cert")
	}

	// 3. Generate Server Certificate from Intermediate CA
	serverCert, err := interCA.GenerateServerCertificate("server.example.com", []string{"server.example.com"}, nil, 2)
	if err != nil {
		t.Fatalf("Failed to generate server certificate from intermediate CA: %v", err)
	}

	// Verify Server Certificate
	if serverCert.Certificate.Issuer.CommonName != "Test Intermediate CA" {
		t.Errorf("Expected Issuer 'Test Intermediate CA', got '%s'", serverCert.Certificate.Issuer.CommonName)
	}

	// Verify Chain
	if len(serverCert.Chain) != 3 {
		t.Errorf("Expected chain length 3, got %d", len(serverCert.Chain))
	}

	// 4. Verify the full chain
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(interCA.Certificate)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "server.example.com",
	}

	if _, err := serverCert.Certificate.Verify(opts); err != nil {
		t.Errorf("Server certificate verification failed: %v", err)
	}
}

func TestCSRSigning(t *testing.T) {
	// 1. Generate CA
	ca, err := GenerateRootCA("Test CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// 2. Create a CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "csr.example.com",
			Organization: []string{"CSR Org"},
		},
		DNSNames: []string{"csr.example.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// 3. Sign CSR
	cert, err := ca.SignCSR(csr, 2)
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// 4. Verify Certificate
	if cert.Subject.CommonName != "csr.example.com" {
		t.Errorf("Expected CN 'csr.example.com', got '%s'", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "Test CA" {
		t.Errorf("Expected Issuer 'Test CA', got '%s'", cert.Issuer.CommonName)
	}

	// Verify signature
	if err := cert.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}
}

func TestRevocationAndCRL(t *testing.T) {
	// 1. Generate CA
	ca, err := GenerateRootCA("Test CA", 10)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// 2. Generate a certificate to revoke
	cert1, err := ca.GenerateServerCertificate("revoked.example.com", nil, nil, 1)
	if err != nil {
		t.Fatalf("Failed to generate cert1: %v", err)
	}

	// 3. Create RevokedCertificate list
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   cert1.Certificate.SerialNumber,
			RevocationTime: time.Now(),
		},
	}

	// 4. Generate CRL
	crlBytes, err := ca.GenerateCRL(revokedCerts, 7)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	// 5. Parse CRL
	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	// 6. Verify CRL
	if err := ca.Certificate.CheckCRLSignature(crl); err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}

	// Check if cert1 is in CRL
	found := false
	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if revoked.SerialNumber.Cmp(cert1.Certificate.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Revoked certificate not found in CRL")
	}
}

func TestVerifyCertificateHelper(t *testing.T) {
	// 1. Setup Chain: Root -> Inter -> Server
	rootCA, _ := GenerateRootCA("Root", 10)
	interCA, _ := rootCA.GenerateIntermediateCA("Inter", 5)
	serverCert, _ := interCA.GenerateServerCertificate("server", nil, nil, 1)

	// Encode to PEM
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Certificate.Raw})
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interCA.Certificate.Raw})
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate.Raw})

	// 2. Verify Valid Chain
	if err := VerifyCertificate(rootPEM, interPEM, serverPEM); err != nil {
		t.Errorf("Valid chain verification failed: %v", err)
	}

	// 3. Verify Invalid Chain (wrong root)
	otherRoot, _ := GenerateRootCA("Other Root", 10)
	otherRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherRoot.Certificate.Raw})

	if err := VerifyCertificate(otherRootPEM, interPEM, serverPEM); err == nil {
		t.Error("Verification should fail with wrong root")
	}
}
