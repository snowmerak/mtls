package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/snowmerak/mtls/ent"
	"github.com/snowmerak/mtls/ent/certificate"
	_ "modernc.org/sqlite"
)

// Global Ent client
var dbClient *ent.Client

// InitDB initializes the database connection and schema
func InitDB(dbPath string) (*ent.Client, error) {
	// Open database with modernc.org/sqlite driver (registered as "sqlite")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create ent driver with "sqlite3" dialect
	drv := entsql.OpenDB("sqlite3", db)

	client := ent.NewClient(ent.Driver(drv))

	// Run schema migration
	if err := client.Schema.Create(context.Background()); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	dbClient = client
	return client, nil
}

// SaveCertificateToDB saves certificate metadata to the database
func SaveCertificateToDB(ctx context.Context, meta CertMetadata) error {
	if dbClient == nil {
		return fmt.Errorf("database client not initialized")
	}

	// Check if certificate with same Serial Number and Common Name exists
	// We use both because Serial Number might not be unique across different CAs
	exists, err := dbClient.Certificate.Query().
		Where(
			certificate.SerialNumber(meta.SerialNumber),
			certificate.CommonName(meta.CommonName),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to check existing certificate: %w", err)
	}

	if exists {
		// Already exists, skip
		return nil
	}

	// Prepare builder
	builder := dbClient.Certificate.Create().
		SetCommonName(meta.CommonName).
		SetSerialNumber(meta.SerialNumber).
		SetStatus(certificate.StatusValid).
		SetCreatedAt(meta.CreatedAt).
		SetExpiresAt(meta.ExpiresAt).
		SetKeyType(meta.KeyType).
		SetFingerprint(meta.FingerprintSHA256).
		SetCertPath(meta.CertPath).
		SetKeyPath(meta.KeyPath)

	if meta.Organization != "" {
		builder.SetOrganization(meta.Organization)
	}
	if meta.Country != "" {
		builder.SetCountry(meta.Country)
	}
	if len(meta.DNSNames) > 0 {
		builder.SetDNSNames(meta.DNSNames)
	}
	if len(meta.IPAddresses) > 0 {
		builder.SetIPAddresses(meta.IPAddresses)
	}

	// Map string type to enum
	switch meta.Type {
	case "root-ca":
		builder.SetType(certificate.TypeRootCa)
		builder.SetIsCa(true)
	case "intermediate-ca":
		builder.SetType(certificate.TypeIntermediateCa)
		builder.SetIsCa(true)
	case "server":
		builder.SetType(certificate.TypeServer)
	case "client":
		builder.SetType(certificate.TypeClient)
	default:
		return fmt.Errorf("unknown certificate type: %s", meta.Type)
	}

	// Handle Issuer relationship
	if meta.Issuer != "" && meta.Type != "root-ca" {
		// Find issuer certificate by Common Name
		// We look for the most recently created CA with this CN
		issuer, err := dbClient.Certificate.Query().
			Where(
				certificate.CommonName(meta.Issuer),
				certificate.Or(
					certificate.TypeEQ(certificate.TypeRootCa),
					certificate.TypeEQ(certificate.TypeIntermediateCa),
				),
			).
			Order(ent.Desc(certificate.FieldCreatedAt)).
			First(ctx)

		if err == nil {
			builder.SetIssuer(issuer)
		}
	}

	_, err = builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to save certificate to DB: %w", err)
	}

	return nil
}

// GetCAs returns all CA certificates (Root and Intermediate)
func GetCAs(ctx context.Context) ([]*ent.Certificate, error) {
	if dbClient == nil {
		return nil, fmt.Errorf("database client not initialized")
	}

	return dbClient.Certificate.Query().
		Where(
			certificate.Or(
				certificate.TypeEQ(certificate.TypeRootCa),
				certificate.TypeEQ(certificate.TypeIntermediateCa),
			),
			certificate.StatusEQ(certificate.StatusValid),
		).
		Order(ent.Desc(certificate.FieldCreatedAt)).
		All(ctx)
}

// GetCertificateByCN returns a certificate by Common Name
func GetCertificateByCN(ctx context.Context, cn string) (*ent.Certificate, error) {
	if dbClient == nil {
		return nil, fmt.Errorf("database client not initialized")
	}

	return dbClient.Certificate.Query().
		Where(certificate.CommonName(cn)).
		Order(ent.Desc(certificate.FieldCreatedAt)).
		First(ctx)
}

// GetAllCertificates returns all certificates
func GetAllCertificates(ctx context.Context) ([]*ent.Certificate, error) {
	if dbClient == nil {
		return nil, fmt.Errorf("database client not initialized")
	}
	return dbClient.Certificate.Query().All(ctx)
}

// RevokeCertificateInDB marks a certificate as revoked in the database
func RevokeCertificateInDB(ctx context.Context, serialNumber string) error {
	if dbClient == nil {
		return fmt.Errorf("database client not initialized")
	}

	// Find certificate
	cert, err := dbClient.Certificate.Query().
		Where(certificate.SerialNumber(serialNumber)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	if cert.Status == certificate.StatusRevoked {
		return fmt.Errorf("certificate is already revoked")
	}

	// Update status
	_, err = cert.Update().
		SetStatus(certificate.StatusRevoked).
		SetRevokedAt(time.Now()).
		Save(ctx)

	return err
}
