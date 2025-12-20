package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mtls",
		Short: "mTLS Certificate Management Tool",
		Long:  `A CLI tool for creating and managing mTLS certificates including Root CAs and server certificates.`,
	}

	// CA commands
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage Root Certificate Authorities",
	}
	caCmd.AddCommand(createCACmd())
	caCmd.AddCommand(listCACmd())
	caCmd.AddCommand(signCSRCmd())

	// Certificate commands
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage server certificates",
	}
	certCmd.AddCommand(createServerCertCmd())
	certCmd.AddCommand(listServerCertsCmd())

	// Add commands to root
	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(certCmd)

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("mtls version 1.0.0")
		},
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
