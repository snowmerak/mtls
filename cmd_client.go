package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/snowmerak/mtls/ent/certificate"
	"github.com/spf13/cobra"
)

// createClientCertCmd creates a new client certificate
func createClientCertCmd() *cobra.Command {
	var batch bool
	var caPath, commonName, organization, dnsNames, ipAddresses, outputDir string
	var validYears int
	var keyType string

	cmd := &cobra.Command{
		Use:   "create-client",
		Short: "Create a new client certificate",
		Long:  "Interactively create a new client certificate signed by a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive mode if not batch
			if !batch {
				if err := promptClientCertInfo(&caPath, &commonName, &organization, &dnsNames, &ipAddresses, &validYears, &keyType, &outputDir); err != nil {
					return err
				}
			}

			// Validate inputs
			if commonName == "" {
				return fmt.Errorf("common name is required")
			}
			if caPath == "" {
				return fmt.Errorf("CA path is required")
			}

			// Load CA
			s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = " Loading CA certificate..."
			s.Start()

			caCertPath := filepath.Join(caPath, "ca-cert.pem")
			caKeyPath := filepath.Join(caPath, "ca-key.pem")

			ca, err := LoadCAFromFiles(caCertPath, caKeyPath)
			s.Stop()
			if err != nil {
				errorColor.Printf("✗ Failed to load CA: %v\n", err)
				return err
			}
			successColor.Println("✓ CA loaded")

			// Parse DNS names and IPs
			var dnsNamesList []string
			var ipList []net.IP

			if dnsNames != "" {
				dnsNamesList = strings.Split(dnsNames, ",")
				for i := range dnsNamesList {
					dnsNamesList[i] = strings.TrimSpace(dnsNamesList[i])
				}
			}

			if ipAddresses != "" {
				ips := strings.Split(ipAddresses, ",")
				for _, ipStr := range ips {
					ipStr = strings.TrimSpace(ipStr)
					ip := net.ParseIP(ipStr)
					if ip == nil {
						warnColor.Printf("⚠ Invalid IP address: %s\n", ipStr)
						continue
					}
					ipList = append(ipList, ip)
				}
			}

			// Create client cert options
			opts := DefaultClientCertOptions(commonName)
			if organization != "" {
				opts.Subject.Organization = []string{organization}
			}
			opts.DNSNames = dnsNamesList
			opts.IPAddresses = ipList
			opts.ValidYears = validYears
			opts.KeyType = KeyType(keyType)

			// Generate client certificate
			s.Suffix = " Generating client certificate..."
			s.Start()

			clientCert, err := ca.GenerateClientCertificateWithOptions(opts)
			s.Stop()
			if err != nil {
				errorColor.Printf("✗ Failed to generate client certificate: %v\n", err)
				return err
			}
			successColor.Println("✓ Client certificate generated")

			// Set output directory
			if outputDir == "" {
				outputDir = filepath.Join(defaultClientDir, commonName)
			}

			// Save files
			certPath := filepath.Join(outputDir, "client-cert.pem")
			keyPath := filepath.Join(outputDir, "client-key.pem")
			caCertCopyPath := filepath.Join(outputDir, "ca-cert.pem")
			metadataPath := filepath.Join(outputDir, ".metadata.json")

			s.Suffix = " Saving certificate files..."
			s.Start()
			if err := clientCert.SaveClientCertToFiles(certPath, keyPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save client certificate: %v\n", err)
				return err
			}

			// Save CA cert copy
			if err := SaveCertificateToFile(ca.Certificate, caCertCopyPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save CA certificate copy: %v\n", err)
				return err
			}

			// Convert IPs to strings
			ipStrings := make([]string, len(ipList))
			for i, ip := range ipList {
				ipStrings[i] = ip.String()
			}

			// Save metadata
			metadata := &CertMetadata{
				Type:              "client",
				CommonName:        commonName,
				Organization:      organization,
				KeyType:           string(keyType),
				CreatedAt:         time.Now(),
				ExpiresAt:         clientCert.Certificate.NotAfter,
				SerialNumber:      clientCert.Certificate.SerialNumber.String(),
				FingerprintSHA256: fmt.Sprintf("%x", sha256.Sum256(clientCert.Certificate.Raw)),
				CertPath:          certPath,
				KeyPath:           keyPath,
				Issuer:            ca.Certificate.Subject.CommonName,
				CAPath:            caPath,
				DNSNames:          dnsNamesList,
				IPAddresses:       ipStrings,
			}

			if err := SaveMetadata(metadata, metadataPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save metadata: %v\n", err)
				return err
			}

			// Save to DB
			if err := SaveCertificateToDB(context.Background(), *metadata); err != nil {
				warnColor.Printf("⚠ Could not save to database: %v\n", err)
			}

			s.Stop()
			successColor.Printf("✓ Client certificate saved to %s\n", outputDir)
			return nil
		},
	}

	cmd.Flags().BoolVar(&batch, "batch", false, "Run in batch mode (non-interactive)")
	cmd.Flags().StringVar(&caPath, "ca", "", "CA directory path")
	cmd.Flags().StringVar(&commonName, "cn", "", "Common Name")
	cmd.Flags().StringVar(&organization, "org", "", "Organization")
	cmd.Flags().IntVar(&validYears, "years", 5, "Valid years")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa2048", "Key type (rsa2048, rsa4096, ecp256, ecp384, ecp521)")
	cmd.Flags().StringVar(&outputDir, "output", "", "Output directory")

	return cmd
}

// listClientCertsCmd lists all client certificates
func listClientCertsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-client",
		Short: "List all client certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, err := GetAllCertificates(context.Background())
			if err != nil {
				return err
			}

			var clients []CertMetadata
			for _, cert := range certs {
				if cert.Type == certificate.TypeClient {
					clients = append(clients, CertMetadata{
						CommonName:   cert.CommonName,
						Organization: cert.Organization,
						KeyType:      cert.KeyType,
						CreatedAt:    cert.CreatedAt,
						ExpiresAt:    cert.ExpiresAt,
						CertPath:     cert.CertPath,
					})
				}
			}

			if len(clients) == 0 {
				infoColor.Println("No client certificates found. Create one with 'mtls cert create-client'")
				return nil
			}

			fmt.Println()
			successColor.Println("Client Certificates:")
			fmt.Println()

			for i, cert := range clients {
				fmt.Printf("%d. %s\n", i+1, cert.CommonName)
				infoColor.Printf("   Organization: %s\n", cert.Organization)
				infoColor.Printf("   Key Type: %s\n", cert.KeyType)
				infoColor.Printf("   Created: %s\n", cert.CreatedAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Expires: %s\n", cert.ExpiresAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Path: %s\n", cert.CertPath)
				fmt.Println()
			}

			return nil
		},
	}
}

func promptClientCertInfo(caPath, cn, org, dnsNames, ipAddresses *string, years *int, keyType, outputDir *string) error {
	// Load registry to show available CAs
	cas, err := GetCAs(context.Background())
	if err == nil && len(cas) > 0 {
		caOptions := make([]string, len(cas))
		caPaths := make(map[string]string)

		for i, ca := range cas {
			label := fmt.Sprintf("%s (expires %s)", ca.CommonName, ca.ExpiresAt.Format("2006-01-02"))
			caOptions[i] = label
			caPaths[label] = filepath.Dir(ca.CertPath)
		}
		caOptions = append(caOptions, "Browse for CA certificate...")

		var selected string
		prompt := &survey.Select{
			Message: "Select CA:",
			Options: caOptions,
		}
		if err := survey.AskOne(prompt, &selected); err != nil {
			return err
		}

		if selected == "Browse for CA certificate..." {
			prompt := &survey.Input{
				Message: "CA directory path:",
				Default: defaultCADir,
			}
			if err := survey.AskOne(prompt, caPath); err != nil {
				return err
			}
		} else {
			*caPath = caPaths[selected]
		}
	} else {
		prompt := &survey.Input{
			Message: "CA directory path:",
			Default: defaultCADir,
		}
		if err := survey.AskOne(prompt, caPath); err != nil {
			return err
		}
	}

	questions := []*survey.Question{
		{
			Name: "commonName",
			Prompt: &survey.Input{
				Message: "Common Name:",
				Help:    "e.g., client-1 or user@example.com",
			},
			Validate: survey.Required,
		},
		{
			Name: "dnsNames",
			Prompt: &survey.Input{
				Message: "DNS names (comma separated, optional):",
				Help:    "e.g., client.example.com",
			},
		},
		{
			Name: "ipAddresses",
			Prompt: &survey.Input{
				Message: "IP addresses (comma separated, optional):",
				Help:    "e.g., 192.168.1.100",
			},
		},
		{
			Name: "organization",
			Prompt: &survey.Input{
				Message: "Organization (optional):",
			},
		},
		{
			Name: "validYears",
			Prompt: &survey.Input{
				Message: "Valid Years:",
				Default: "5",
			},
		},
		{
			Name: "keyType",
			Prompt: &survey.Select{
				Message: "Key Type:",
				Options: []string{"rsa2048", "rsa4096", "ecp256", "ecp384", "ecp521", "ed25519"},
				Default: "rsa2048",
			},
		},
	}

	answers := struct {
		CommonName   string
		Organization string
		DNSNames     string
		IPAddresses  string
		ValidYears   string
		KeyType      string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return err
	}

	*cn = answers.CommonName
	*org = answers.Organization
	*dnsNames = answers.DNSNames
	*ipAddresses = answers.IPAddresses
	*keyType = answers.KeyType
	*outputDir = filepath.Join(defaultClientDir, *cn)

	// Parse valid years
	fmt.Sscanf(answers.ValidYears, "%d", years)
	if *years <= 0 {
		*years = 5
	}

	return nil
}
