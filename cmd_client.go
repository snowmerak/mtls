package main

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

// createClientCertCmd creates a new client certificate
func createClientCertCmd() *cobra.Command {
	var batch bool
	var caPath, commonName, organization, outputDir string
	var validYears int
	var keyType string

	cmd := &cobra.Command{
		Use:   "create-client",
		Short: "Create a new client certificate",
		Long:  "Interactively create a new client certificate signed by a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive mode if not batch
			if !batch {
				if err := promptClientCertInfo(&caPath, &commonName, &organization, &validYears, &keyType, &outputDir); err != nil {
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

			// Create client cert options
			opts := DefaultClientCertOptions(commonName)
			opts.Subject.Organization = []string{organization}
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
			}

			if err := SaveMetadata(metadata, metadataPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save metadata: %v\n", err)
				return err
			}

			// Update registry
			registry, err := LoadRegistry(defaultRegistryPath)
			if err != nil {
				warnColor.Printf("⚠ Could not load registry: %v\n", err)
			} else {
				registry.AddClient(*metadata)
				if err := SaveRegistry(registry, defaultRegistryPath); err != nil {
					warnColor.Printf("⚠ Could not update registry: %v\n", err)
				}
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
			registry, err := LoadRegistry(defaultRegistryPath)
			if err != nil {
				return err
			}

			if len(registry.Clients) == 0 {
				infoColor.Println("No client certificates found. Create one with 'mtls cert create-client'")
				return nil
			}

			fmt.Println()
			successColor.Println("Client Certificates:")
			fmt.Println()

			for i, cert := range registry.Clients {
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

func promptClientCertInfo(caPath, cn, org *string, years *int, keyType, outputDir *string) error {
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
				Help:    "e.g., client-1 or user@example.com",
			},
			Validate: survey.Required,
		},
		{
			Name: "organization",
			Prompt: &survey.Input{
				Message: "Organization:",
				Default: "Client Certificate",
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
				Options: []string{"rsa2048", "rsa4096", "ecp256", "ecp384", "ecp521"},
				Default: "rsa2048",
			},
		},
	}

	answers := struct {
		CommonName   string
		Organization string
		ValidYears   string
		KeyType      string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return err
	}

	*cn = answers.CommonName
	*org = answers.Organization
	*keyType = answers.KeyType
	*outputDir = filepath.Join(defaultClientDir, *cn)

	// Parse valid years
	fmt.Sscanf(answers.ValidYears, "%d", years)
	if *years <= 0 {
		*years = 5
	}

	return nil
}
