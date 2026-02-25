package reseed

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"
)

// SignerFilename generates a certificate filename from a signer ID string.
// Appends ".crt" extension to the processed signer ID for consistent certificate file naming.
// Uses SignerFilenameFromID for consistent ID processing across the reseed system.
func SignerFilename(signer string) string {
	return SignerFilenameFromID(signer) + ".crt"
}

// NewTLSCertificate creates a new TLS certificate for the specified hostname.
// This is a convenience wrapper around NewTLSCertificateAltNames for single-host certificates.
// Returns the certificate in PEM format ready for use in TLS server configuration.
func NewTLSCertificate(host string, priv *ecdsa.PrivateKey) ([]byte, error) {
	return NewTLSCertificateAltNames(priv, host)
}

// NewTLSCertificateAltNames creates a new TLS certificate supporting multiple hostnames.
// Generates a 5-year validity certificate with specified hostnames as Subject Alternative Names
// for flexible deployment across multiple domains. Uses ECDSA private key for modern cryptography.
func NewTLSCertificateAltNames(priv *ecdsa.PrivateKey, hosts ...string) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)
	host := ""
	if len(hosts) > 0 {
		host = hosts[0]
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		lgr.WithError(err).Error("Failed to generate serial number for TLS certificate")
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         host,
		},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.ECDSAWithSHA512,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              hosts[1:],
	}

	hosts = strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		lgr.WithError(err).WithField("hosts", hosts).Error("Failed to create TLS certificate")
		return nil, err
	}

	return derBytes, nil
}
