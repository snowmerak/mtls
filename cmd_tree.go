package main

import (
	"context"
	"fmt"
	"time"

	"github.com/snowmerak/mtls/ent"
	"github.com/snowmerak/mtls/ent/certificate"
	"github.com/spf13/cobra"
)

func createTreeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tree",
		Short: "Show certificate hierarchy tree",
		Long:  "Display the certificate chain hierarchy and status from the database registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbClient == nil {
				return fmt.Errorf("database not initialized")
			}

			// Find all Root CAs
			roots, err := dbClient.Certificate.Query().
				Where(certificate.TypeEQ(certificate.TypeRootCa)).
				All(context.Background())

			if err != nil {
				return fmt.Errorf("failed to query root CAs: %w", err)
			}

			if len(roots) == 0 {
				fmt.Println("No Root CAs found in registry.")
				return nil
			}

			fmt.Println()
			fmt.Println("Certificate Registry Tree")
			fmt.Println("=========================")
			fmt.Println("Legend: ✓ Valid  ! Expired  ✗ Revoked")
			fmt.Println()

			for _, root := range roots {
				printCertTree(root, "", true)
				fmt.Println()
			}

			return nil
		},
	}
}

func printCertTree(cert *ent.Certificate, prefix string, isLast bool) {
	marker := "├── "
	if isLast {
		marker = "└── "
	}

	statusIcon := "✓"
	statusColor := successColor

	if cert.Status == certificate.StatusRevoked {
		statusIcon = "✗"
		statusColor = errorColor
	} else if time.Now().After(cert.ExpiresAt) {
		statusIcon = "!"
		statusColor = warnColor
	}

	// Format: [Icon] CommonName (Type) - Expires: YYYY-MM-DD
	fmt.Printf("%s%s", prefix, marker)
	statusColor.Printf("%s %s", statusIcon, cert.CommonName)
	fmt.Printf(" (%s)", cert.Type)

	daysLeft := int(time.Until(cert.ExpiresAt).Hours() / 24)
	expireMsg := fmt.Sprintf("%s (%d days left)", cert.ExpiresAt.Format("2006-01-02"), daysLeft)

	if daysLeft < 30 && daysLeft > 0 {
		warnColor.Printf(" [Expires: %s]", expireMsg)
	} else if daysLeft <= 0 {
		errorColor.Printf(" [Expired: %s]", expireMsg)
	} else {
		fmt.Printf(" [Expires: %s]", expireMsg)
	}
	fmt.Println()

	// Query children
	children, err := cert.QueryChildren().
		Order(ent.Asc(certificate.FieldType), ent.Asc(certificate.FieldCommonName)).
		All(context.Background())

	if err != nil {
		errorColor.Printf("%s    Error querying children: %v\n", prefix, err)
		return
	}

	newPrefix := prefix
	if isLast {
		newPrefix += "    "
	} else {
		newPrefix += "│   "
	}

	for i, child := range children {
		printCertTree(child, newPrefix, i == len(children)-1)
	}
}
