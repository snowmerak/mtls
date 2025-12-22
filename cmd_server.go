package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

// createServerCertCmd creates a new server certificate
func createServerCertCmd() *cobra.Command {
	var batch bool
	var caPath, commonName, organization, dnsNames, ipAddresses, outputDir string
	var validYears int
	var keyType string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new server certificate",
		Long:  "Interactively create a new server certificate signed by a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive mode if not batch
			if !batch {
				if err := promptServerCertInfo(&caPath, &commonName, &organization, &dnsNames, &ipAddresses, &validYears, &keyType, &outputDir); err != nil {
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

			// Create server cert options
			opts := DefaultServerCertOptions(commonName)
			if organization != "" {
				opts.Subject.Organization = []string{organization}
			}
			opts.DNSNames = dnsNamesList
			opts.IPAddresses = ipList
			opts.ValidYears = validYears
			opts.KeyType = KeyType(keyType)

			// Generate server certificate
			s.Suffix = " Generating server certificate..."
			s.Start()

			serverCert, err := ca.GenerateServerCertificateWithOptions(opts)
			s.Stop()
			if err != nil {
				errorColor.Printf("✗ Failed to generate server certificate: %v\n", err)
				return err
			}
			successColor.Println("✓ Server certificate generated")

			// Set output directory
			if outputDir == "" {
				outputDir = filepath.Join(defaultServerDir, commonName)
			}

			// Save files
			certPath := filepath.Join(outputDir, "server-cert.pem")
			keyPath := filepath.Join(outputDir, "server-key.pem")
			caCertCopyPath := filepath.Join(outputDir, "ca-cert.pem")
			metadataPath := filepath.Join(outputDir, ".metadata.json")

			s.Suffix = " Saving certificate files..."
			s.Start()
			if err := serverCert.SaveServerCertToFiles(certPath, keyPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save server certificate: %v\n", err)
				return err
			}

			// Copy CA certificate
			caData, _ := os.ReadFile(caCertPath)
			os.WriteFile(caCertCopyPath, caData, 0644)

			s.Stop()
			successColor.Println("✓ Certificate files saved")

			// Calculate fingerprint
			fingerprint, err := CalculateFingerprint(certPath)
			if err != nil {
				warnColor.Printf("⚠ Could not calculate fingerprint: %v\n", err)
				fingerprint = "unknown"
			}

			// Save metadata
			ipStrings := make([]string, len(ipList))
			for i, ip := range ipList {
				ipStrings[i] = ip.String()
			}

			metadata := CertMetadata{
				Type:              "server",
				CommonName:        commonName,
				Organization:      organization,
				KeyType:           keyType,
				CreatedAt:         time.Now(),
				ExpiresAt:         time.Now().AddDate(validYears, 0, 0),
				FingerprintSHA256: fingerprint,
				CertPath:          certPath,
				KeyPath:           keyPath,
				DNSNames:          dnsNamesList,
				IPAddresses:       ipStrings,
				CAPath:            caPath,
			}

			if err := SaveMetadata(&metadata, metadataPath); err != nil {
				warnColor.Printf("⚠ Could not save metadata: %v\n", err)
			}

			// Update registry
			registry, err := LoadRegistry(defaultRegistryPath)
			if err != nil {
				warnColor.Printf("⚠ Could not load registry: %v\n", err)
			} else {
				registry.AddServer(metadata)
				if err := SaveRegistry(registry, defaultRegistryPath); err != nil {
					warnColor.Printf("⚠ Could not update registry: %v\n", err)
				}
			}

			// Print success message
			fmt.Println()
			successColor.Println("✓ Server certificate created successfully!")
			infoColor.Printf("  Certificate: %s\n", certPath)
			infoColor.Printf("  Private Key: %s (permissions: 0600)\n", keyPath)
			infoColor.Printf("  CA Certificate (copy): %s\n", caCertCopyPath)
			infoColor.Printf("  Fingerprint: SHA256:%s\n", fingerprint[:16]+"...")
			fmt.Println()
			infoColor.Println("  Usage example (Go):")
			fmt.Printf("    cert, _ := tls.LoadX509KeyPair(\"%s\", \"%s\")\n", certPath, keyPath)
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().BoolVar(&batch, "batch", false, "Non-interactive mode")
	cmd.Flags().StringVar(&caPath, "ca", "", "CA directory path")
	cmd.Flags().StringVar(&commonName, "cn", "", "Common Name")
	cmd.Flags().StringVar(&organization, "org", "Server Certificate", "Organization")
	cmd.Flags().StringVar(&dnsNames, "dns", "", "DNS names (comma separated)")
	cmd.Flags().StringVar(&ipAddresses, "ip", "", "IP addresses (comma separated)")
	cmd.Flags().IntVar(&validYears, "years", 5, "Valid years")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa2048", "Key type (rsa2048, rsa4096, ecp256, ecp384, ecp521)")
	cmd.Flags().StringVar(&outputDir, "output", "", "Output directory")

	return cmd
}

// listServerCertsCmd lists all server certificates
func listServerCertsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all server certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := LoadRegistry(defaultRegistryPath)
			if err != nil {
				return err
			}

			if len(registry.Servers) == 0 {
				infoColor.Println("No server certificates found. Create one with 'mtls cert create'")
				return nil
			}

			fmt.Println()
			successColor.Println("Server Certificates:")
			fmt.Println()

			for i, cert := range registry.Servers {
				fmt.Printf("%d. %s\n", i+1, cert.CommonName)
				infoColor.Printf("   Organization: %s\n", cert.Organization)
				infoColor.Printf("   Key Type: %s\n", cert.KeyType)
				infoColor.Printf("   Created: %s\n", cert.CreatedAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Expires: %s\n", cert.ExpiresAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Path: %s\n", cert.CertPath)
				if len(cert.DNSNames) > 0 {
					infoColor.Printf("   DNS: %s\n", strings.Join(cert.DNSNames, ", "))
				}
				if len(cert.IPAddresses) > 0 {
					infoColor.Printf("   IP: %s\n", strings.Join(cert.IPAddresses, ", "))
				}
				fmt.Println()
			}

			return nil
		},
	}
}

// inspectCmd inspects a certificate
func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect [cert-file]",
		Short: "Inspect a certificate file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath := args[0]
			data, err := os.ReadFile(certPath)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			info, err := InspectCertificate(data)
			if err != nil {
				return err
			}

			fmt.Println(info)
			return nil
		},
	}
}

// verifyCmd verifies a certificate
func verifyCmd() *cobra.Command {
	var rootPath, interPath string

	cmd := &cobra.Command{
		Use:   "verify [cert-file]",
		Short: "Verify a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath := args[0]
			certData, err := os.ReadFile(certPath)
			if err != nil {
				return fmt.Errorf("failed to read certificate: %w", err)
			}

			var rootData, interData []byte

			if rootPath != "" {
				rootData, err = os.ReadFile(rootPath)
				if err != nil {
					return fmt.Errorf("failed to read root CA: %w", err)
				}
			}

			if interPath != "" {
				interData, err = os.ReadFile(interPath)
				if err != nil {
					return fmt.Errorf("failed to read intermediate CA: %w", err)
				}
			}

			if err := VerifyCertificate(rootData, interData, certData); err != nil {
				errorColor.Printf("✗ Verification failed: %v\n", err)
				return nil // Don't return error to avoid cobra usage printing
			}

			successColor.Println("✓ Certificate is valid")
			return nil
		},
	}

	cmd.Flags().StringVar(&rootPath, "root", "", "Root CA certificate path")
	cmd.Flags().StringVar(&interPath, "intermediate", "", "Intermediate CA certificate path")
	cmd.MarkFlagRequired("root")

	return cmd
}

func promptServerCertInfo(caPath, cn, org, dnsNames, ipAddresses *string, years *int, keyType, outputDir *string) error {
	// Load registry to show available CAs
	registry, err := LoadRegistry(defaultRegistryPath)
	if err == nil && len(registry.CAs) > 0 {
		caOptions := make([]string, len(registry.CAs))
		caPaths := make(map[string]string)

		for i, ca := range registry.CAs {
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
				Help:    "e.g., api.example.com or 192.168.1.100",
			},
			Validate: survey.Required,
		},
		{
			Name: "dnsNames",
			Prompt: &survey.Input{
				Message: "DNS names (comma separated):",
				Help:    "e.g., api.example.com,*.api.example.com,localhost",
			},
		},
		{
			Name: "ipAddresses",
			Prompt: &survey.Input{
				Message: "IP addresses (comma separated):",
				Help:    "e.g., 127.0.0.1,192.168.1.100",
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
		DNSNames     string
		IPAddresses  string
		Organization string
		ValidYears   string
		KeyType      string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return err
	}

	*cn = answers.CommonName
	*dnsNames = answers.DNSNames
	*ipAddresses = answers.IPAddresses
	*org = answers.Organization
	*keyType = answers.KeyType
	*outputDir = filepath.Join(defaultServerDir, *cn)

	// Parse valid years
	fmt.Sscanf(answers.ValidYears, "%d", years)
	if *years <= 0 {
		*years = 5
	}

	return nil
}
