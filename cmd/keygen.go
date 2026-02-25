// Package cmd provides command-line interface implementations for reseed-tools.
// This package contains all CLI commands for key generation, server operation, file verification,
// and network database sharing operations. Each command is self-contained and provides
// comprehensive functionality for I2P network reseed operations.
package cmd

import (
	"fmt"

	"github.com/urfave/cli/v3"
)

// NewKeygenCommand creates a new CLI command for generating cryptographic keys.
// It supports generating signing keys for SU3 file signing and TLS certificates for HTTPS serving.
// Users can specify either --signer for SU3 signing keys or --tlsHost for TLS certificates.
func NewKeygenCommand() *cli.Command {
	return &cli.Command{
		Name:   "keygen",
		Usage:  "Generate keys for reseed su3 signing and TLS serving.",
		Action: keygenAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "signer",
				Usage: "Generate a private key and certificate for the given su3 signing ID (ex. something@mail.i2p)",
			},
			&cli.StringFlag{
				Name:  "tlsHost",
				Usage: "Generate a self-signed TLS certificate and private key for the given host",
			},
		},
	}
}

func keygenAction(c *cli.Context) error {
	signerID := c.String("signer")
	tlsHost := c.String("tlsHost")

	// Validate that at least one key generation option is specified
	if signerID == "" && tlsHost == "" {
		fmt.Println("You must specify either --tlsHost or --signer")
		lgr.Error("Key generation requires either --tlsHost or --signer parameter")
		return fmt.Errorf("you must specify either --tlsHost or --signer")
	}

	// Generate signing certificate if signer ID is provided
	if signerID != "" {
		if err := createSigningCertificate(signerID); nil != err {
			lgr.WithError(err).WithField("signer_id", signerID).Error("Failed to create signing certificate")
			fmt.Println(err)
			return err
		}
	}

	// Generate TLS certificate if host is provided
	if tlsHost != "" {
		if err := createTLSCertificate(tlsHost); nil != err {
			lgr.WithError(err).WithField("tls_host", tlsHost).Error("Failed to create TLS certificate")
			fmt.Println(err)
			return err
		}
	}
	return nil
}
