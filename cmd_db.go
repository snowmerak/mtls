package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func dbCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database management commands",
	}

	cmd.AddCommand(syncCmd())
	return cmd
}

func syncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Sync database with metadata files",
		Long:  "Scans the certs directory for .metadata.json files and imports them into the database if missing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			count := 0
			errors := 0

			err := filepath.Walk("./certs", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.Name() == ".metadata.json" {
					// Read metadata
					data, err := os.ReadFile(path)
					if err != nil {
						warnColor.Printf("Failed to read %s: %v\n", path, err)
						errors++
						return nil
					}

					var meta CertMetadata
					if err := json.Unmarshal(data, &meta); err != nil {
						warnColor.Printf("Failed to parse %s: %v\n", path, err)
						errors++
						return nil
					}

					// Save to DB
					if err := SaveCertificateToDB(context.Background(), meta); err != nil {
						warnColor.Printf("Failed to save %s to DB: %v\n", meta.CommonName, err)
						errors++
					} else {
						count++
						// fmt.Printf("Synced %s\n", meta.CommonName)
					}
				}
				return nil
			})

			if err != nil {
				return err
			}

			successColor.Printf("✓ Database sync completed. Processed %d certificates with %d errors.\n", count, errors)
			return nil
		},
	}
}
