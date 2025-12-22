package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/snowmerak/mtls/ent/certificate"
	"github.com/spf13/cobra"
)

// createCACmd creates a new Root CA or Intermediate CA
func createCACmd() *cobra.Command {
	var batch bool
	var caType string // "root" or "intermediate"
	var parentCA string
	var commonName, organization, country, outputDir string
	var validYears int
	var keyType string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Root CA or Intermediate CA certificate",
		Long:  "Interactively create a new self-signed Root CA or Intermediate CA certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive mode if not batch
			if !batch {
				if err := promptCAInfo(&caType, &parentCA, &commonName, &organization, &country, &validYears, &keyType, &outputDir); err != nil {
					return err
				}
			}

			// Validate inputs
			if commonName == "" {
				return fmt.Errorf("common name is required")
			}
			if caType == "intermediate" && parentCA == "" {
				return fmt.Errorf("parent CA is required for intermediate CA")
			}

			// Create CA options
			opts := DefaultCAOptions(commonName)
			if organization != "" {
				opts.Subject.Organization = []string{organization}
			}
			if country != "" {
				opts.Subject.Country = []string{country}
			}
			opts.ValidYears = validYears
			opts.KeyType = KeyType(keyType)

			// Show spinner
			s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = " Generating CA..."
			s.Start()

			var ca *CertificateAuthority
			var err error
			var parentCertPath string

			if caType == "intermediate" {
				// Load parent CA
				parentCert, err := GetCertificateByCN(context.Background(), parentCA)
				if err != nil {
					s.Stop()
					return fmt.Errorf("failed to load parent CA from DB: %w", err)
				}
				if parentCert == nil {
					s.Stop()
					return fmt.Errorf("parent CA '%s' not found", parentCA)
				}
				parentCertPath = parentCert.CertPath

				parent, err := LoadCAFromFiles(parentCert.CertPath, parentCert.KeyPath)
				if err != nil {
					s.Stop()
					return fmt.Errorf("failed to load parent CA: %w", err)
				}

				ca, err = parent.GenerateIntermediateCAWithOptions(opts)
			} else {
				ca, err = GenerateRootCAWithOptions(opts)
			}

			s.Stop()
			if err != nil {
				errorColor.Printf("✗ Failed to generate CA: %v\n", err)
				return err
			}
			successColor.Println("✓ CA generated")

			// Save files
			// Use a subdirectory for the CA to keep things organized
			// If outputDir is default, append common name
			saveDir := outputDir
			if outputDir == defaultCADir {
				saveDir = filepath.Join(outputDir, strings.ReplaceAll(commonName, " ", "_"))
			}

			certPath := filepath.Join(saveDir, "ca-cert.pem")
			keyPath := filepath.Join(saveDir, "ca-key.pem")
			metadataPath := filepath.Join(saveDir, ".metadata.json")

			s.Suffix = " Saving certificate files..."
			s.Start()
			if err := ca.SaveCAToFiles(certPath, keyPath); err != nil {
				s.Stop()
				errorColor.Printf("✗ Failed to save CA: %v\n", err)
				return err
			}
			s.Stop()
			successColor.Println("✓ Certificate files saved")

			// Calculate fingerprint
			fingerprint, err := CalculateFingerprint(certPath)
			if err != nil {
				warnColor.Printf("⚠ Could not calculate fingerprint: %v\n", err)
				fingerprint = "unknown"
			}

			// Save metadata
			metadata := CertMetadata{
				Type:              "root-ca",
				CommonName:        commonName,
				Organization:      organization,
				Country:           country,
				KeyType:           keyType,
				CreatedAt:         time.Now(),
				ExpiresAt:         time.Now().AddDate(validYears, 0, 0),
				SerialNumber:      ca.Certificate.SerialNumber.String(),
				FingerprintSHA256: fingerprint,
				CertPath:          certPath,
				KeyPath:           keyPath,
				CAPath:            parentCertPath,
			}

			if caType == "intermediate" {
				metadata.Type = "intermediate-ca"
				metadata.Issuer = parentCA
			}

			if err := SaveMetadata(&metadata, metadataPath); err != nil {
				warnColor.Printf("⚠ Could not save metadata: %v\n", err)
			}

			// Save to DB
			if err := SaveCertificateToDB(context.Background(), metadata); err != nil {
				warnColor.Printf("⚠ Could not save to database: %v\n", err)
			}

			// Print success message
			fmt.Println()
			successColor.Printf("✓ %s created successfully!\n", caType)
			infoColor.Printf("  Certificate: %s\n", certPath)
			infoColor.Printf("  Private Key: %s (permissions: 0600)\n", keyPath)
			infoColor.Printf("  Fingerprint: SHA256:%s\n", fingerprint[:16]+"...")
			if caType == "intermediate" {
				infoColor.Printf("  Issuer: %s\n", parentCA)
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().BoolVar(&batch, "batch", false, "Non-interactive mode")
	cmd.Flags().StringVar(&caType, "type", "root", "CA Type (root, intermediate)")
	cmd.Flags().StringVar(&parentCA, "parent", "", "Parent CA Common Name (required for intermediate)")
	cmd.Flags().StringVar(&commonName, "cn", "", "Common Name")
	cmd.Flags().StringVar(&organization, "org", "Self-Signed CA", "Organization")
	cmd.Flags().StringVar(&country, "country", "KR", "Country Code")
	cmd.Flags().IntVar(&validYears, "years", 10, "Valid years")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa4096", "Key type (rsa2048, rsa4096, ecp256, ecp384, ecp521)")
	cmd.Flags().StringVar(&outputDir, "output", defaultCADir, "Output directory")

	return cmd
}

// listCACmd lists all CAs in the registry
func listCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all Root CAs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cas, err := GetCAs(context.Background())
			if err != nil {
				return fmt.Errorf("failed to query CAs: %w", err)
			}

			if len(cas) == 0 {
				infoColor.Println("No Root CAs found. Create one with 'mtls ca create'")
				return nil
			}

			fmt.Println()
			successColor.Println("Root Certificate Authorities:")
			fmt.Println()

			for i, ca := range cas {
				fmt.Printf("%d. %s\n", i+1, ca.CommonName)
				infoColor.Printf("   Type: %s\n", ca.Type)
				if ca.QueryIssuer().ExistX(context.Background()) {
					issuer, _ := ca.QueryIssuer().First(context.Background())
					infoColor.Printf("   Issuer: %s\n", issuer.CommonName)
				}
				infoColor.Printf("   Organization: %s\n", ca.Organization)
				infoColor.Printf("   Key Type: %s\n", ca.KeyType)
				infoColor.Printf("   Created: %s\n", ca.CreatedAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Expires: %s\n", ca.ExpiresAt.Format("2006-01-02 15:04:05"))
				infoColor.Printf("   Path: %s\n", ca.CertPath)
				fmt.Println()
			}

			return nil
		},
	}
}

// revokeCmd revokes a certificate
func revokeCmd() *cobra.Command {
	var serialNumber string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Find certificate in DB
			cert, err := dbClient.Certificate.Query().
				Where(certificate.SerialNumber(serialNumber)).
				Only(ctx)
			if err != nil {
				return fmt.Errorf("certificate with serial number %s not found: %w", serialNumber, err)
			}

			if cert.Status == certificate.StatusRevoked {
				return fmt.Errorf("certificate is already revoked")
			}

			// Mark as revoked
			revokedAt := time.Now()
			_, err = cert.Update().
				SetStatus(certificate.StatusRevoked).
				SetRevokedAt(revokedAt).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("failed to revoke certificate: %w", err)
			}

			// Try to update metadata file if it exists
			metaPath := filepath.Join(filepath.Dir(cert.CertPath), ".metadata.json")
			if _, err := os.Stat(metaPath); err == nil {
				// Read file
				data, err := os.ReadFile(metaPath)
				if err == nil {
					var meta CertMetadata
					if err := json.Unmarshal(data, &meta); err == nil {
						meta.Revoked = true
						meta.RevokedAt = revokedAt
						if err := SaveMetadata(&meta, metaPath); err != nil {
							warnColor.Printf("⚠ Could not update metadata file: %v\n", err)
						}
					}
				}
			}

			successColor.Printf("✓ Certificate %s revoked\n", serialNumber)
			return nil
		},
	}

	cmd.Flags().StringVar(&serialNumber, "serial", "", "Serial number of the certificate to revoke")
	cmd.MarkFlagRequired("serial")

	return cmd
}

// genCRLCmd generates a CRL
func genCRLCmd() *cobra.Command {
	var caName string
	var output string
	var validDays int

	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Generate Certificate Revocation List (CRL)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Find CA
			caCert, err := dbClient.Certificate.Query().
				Where(certificate.CommonName(caName)).
				Only(ctx)
			if err != nil {
				return fmt.Errorf("CA '%s' not found: %w", caName, err)
			}

			// Load CA
			ca, err := LoadCAFromFiles(caCert.CertPath, caCert.KeyPath)
			if err != nil {
				return fmt.Errorf("failed to load CA: %w", err)
			}

			// Collect revoked certificates issued by this CA
			revokedCertsDB, err := caCert.QueryIssuer().
				Where(certificate.StatusEQ(certificate.StatusRevoked)).
				All(ctx)
			if err != nil {
				return fmt.Errorf("failed to query revoked certificates: %w", err)
			}

			var revokedCerts []pkix.RevokedCertificate
			for _, cert := range revokedCertsDB {
				serial, ok := new(big.Int).SetString(cert.SerialNumber, 10)
				if !ok {
					continue
				}
				revokedAt := time.Time{}
				if cert.RevokedAt != nil {
					revokedAt = *cert.RevokedAt
				}
				revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
					SerialNumber:   serial,
					RevocationTime: revokedAt,
				})
			}

			// Generate CRL
			crlBytes, err := ca.GenerateCRL(revokedCerts, validDays)
			if err != nil {
				return fmt.Errorf("failed to generate CRL: %w", err)
			}

			// Save CRL
			if output == "" {
				output = filepath.Join(filepath.Dir(caCert.CertPath), "crl.pem")
			}

			if err := os.WriteFile(output, crlBytes, 0644); err != nil {
				return fmt.Errorf("failed to save CRL: %w", err)
			}

			successColor.Printf("✓ CRL generated at %s\n", output)
			infoColor.Printf("  Revoked certificates count: %d\n", len(revokedCerts))

			return nil
		},
	}

	cmd.Flags().StringVar(&caName, "ca", "", "CA Common Name")
	cmd.Flags().StringVar(&output, "output", "", "Output path for CRL")
	cmd.Flags().IntVar(&validDays, "days", 7, "Valid days")
	cmd.MarkFlagRequired("ca")

	return cmd
}

// signCSRCmd signs a CSR with a CA
func signCSRCmd() *cobra.Command {
	var caPath, csrPath, outputDir string
	var validYears int

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a Certificate Signing Request (CSR)",
		Long:  "Sign a CSR with a selected CA to generate a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive prompts if flags are missing
			if caPath == "" || csrPath == "" {
				if err := promptSignCSRInfo(&caPath, &csrPath, &validYears, &outputDir); err != nil {
					return err
				}
			}

			// Load CA
			s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = " Loading CA..."
			s.Start()

			caCertPath := filepath.Join(caPath, "ca-cert.pem")
			caKeyPath := filepath.Join(caPath, "ca-key.pem")
			ca, err := LoadCAFromFiles(caCertPath, caKeyPath)
			if err != nil {
				s.Stop()
				return fmt.Errorf("failed to load CA: %w", err)
			}

			// Load CSR
			s.Suffix = " Loading CSR..."
			csr, err := LoadCSRFromFile(csrPath)
			if err != nil {
				s.Stop()
				return fmt.Errorf("failed to load CSR: %w", err)
			}

			// Sign CSR
			s.Suffix = " Signing CSR..."
			cert, err := ca.SignCSR(csr, validYears)
			s.Stop()
			if err != nil {
				return fmt.Errorf("failed to sign CSR: %w", err)
			}
			successColor.Println("✓ CSR signed successfully")

			// Save certificate
			if outputDir == "" {
				outputDir = "."
			}
			certPath := filepath.Join(outputDir, fmt.Sprintf("%s.crt", strings.ReplaceAll(csr.Subject.CommonName, " ", "_")))

			if err := SaveCertificateToFile(cert, certPath); err != nil {
				return fmt.Errorf("failed to save certificate: %w", err)
			}

			successColor.Printf("✓ Certificate saved to %s\n", certPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&caPath, "ca", "", "CA directory path")
	cmd.Flags().StringVar(&csrPath, "csr", "", "CSR file path")
	cmd.Flags().IntVar(&validYears, "years", 5, "Valid years")
	cmd.Flags().StringVar(&outputDir, "output", "", "Output directory")

	return cmd
}

func promptCAInfo(caType, parentCA, cn, org, country *string, years *int, keyType, outputDir *string) error {
	// 1. Ask for CA Type
	typePrompt := &survey.Select{
		Message: "CA Type:",
		Options: []string{"Root CA", "Intermediate CA"},
		Default: "Root CA",
	}
	var typeAns string
	if err := survey.AskOne(typePrompt, &typeAns); err != nil {
		return err
	}
	if typeAns == "Root CA" {
		*caType = "root"
	} else {
		*caType = "intermediate"
	}

	// 2. If Intermediate, ask for Parent CA
	if *caType == "intermediate" {
		cas, err := GetCAs(context.Background())
		if err != nil {
			return fmt.Errorf("failed to load CAs from DB: %w", err)
		}
		if len(cas) == 0 {
			return fmt.Errorf("no CAs found in registry. Please create a Root CA first")
		}

		var caOptions []string
		for _, ca := range cas {
			caOptions = append(caOptions, ca.CommonName)
		}

		parentPrompt := &survey.Select{
			Message: "Parent CA:",
			Options: caOptions,
		}
		if err := survey.AskOne(parentPrompt, parentCA); err != nil {
			return err
		}
	}

	questions := []*survey.Question{
		{
			Name: "commonName",
			Prompt: &survey.Input{
				Message: "CA Common Name:",
				Default: "My Company CA",
			},
			Validate: survey.Required,
		},
		{
			Name: "organization",
			Prompt: &survey.Input{
				Message: "Organization (optional):",
			},
		},
		{
			Name: "country",
			Prompt: &survey.Input{
				Message: "Country Code (optional):",
			},
		},
		{
			Name: "validYears",
			Prompt: &survey.Input{
				Message: "Valid Years:",
				Default: "10",
			},
		},
		{
			Name: "keyType",
			Prompt: &survey.Select{
				Message: "Key Type:",
				Options: []string{"rsa4096", "rsa2048", "ecp256", "ecp384", "ecp521", "ed25519"},
				Default: "rsa4096",
			},
		},
		{
			Name: "outputDir",
			Prompt: &survey.Input{
				Message: "Output directory:",
				Default: defaultCADir,
			},
		},
	}

	answers := struct {
		CommonName   string
		Organization string
		Country      string
		ValidYears   string
		KeyType      string
		OutputDir    string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return err
	}

	*cn = answers.CommonName
	*org = answers.Organization
	*country = answers.Country
	*keyType = answers.KeyType
	*outputDir = answers.OutputDir

	// Parse valid years
	fmt.Sscanf(answers.ValidYears, "%d", years)
	if *years <= 0 {
		*years = 10
	}

	return nil
}

func promptSignCSRInfo(caPath, csrPath *string, years *int, outputDir *string) error {
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
			Name: "csrPath",
			Prompt: &survey.Input{
				Message: "CSR file path:",
			},
			Validate: survey.Required,
		},
		{
			Name: "validYears",
			Prompt: &survey.Input{
				Message: "Valid Years:",
				Default: "5",
			},
		},
		{
			Name: "outputDir",
			Prompt: &survey.Input{
				Message: "Output directory:",
				Default: ".",
			},
		},
	}

	answers := struct {
		CsrPath    string
		ValidYears string
		OutputDir  string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return err
	}

	*csrPath = answers.CsrPath
	*outputDir = answers.OutputDir

	// Parse valid years
	fmt.Sscanf(answers.ValidYears, "%d", years)
	if *years <= 0 {
		*years = 5
	}

	return nil
}
