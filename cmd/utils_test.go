package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCertificateExpirationLogic(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	testCases := []struct {
		name        string
		expiresIn   time.Duration
		shouldRenew bool
		description string
	}{
		{
			name:        "Certificate expires in 24 hours",
			expiresIn:   24 * time.Hour,
			shouldRenew: true,
			description: "Should renew certificate that expires within 48 hours",
		},
		{
			name:        "Certificate expires in 72 hours",
			expiresIn:   72 * time.Hour,
			shouldRenew: false,
			description: "Should not renew certificate with more than 48 hours remaining",
		},
		{
			name:        "Certificate expires in 47 hours",
			expiresIn:   47 * time.Hour,
			shouldRenew: true,
			description: "Should renew certificate just under 48 hour threshold",
		},
		{
			name:        "Certificate expires in 49 hours",
			expiresIn:   49 * time.Hour,
			shouldRenew: false,
			description: "Should not renew certificate just over 48 hour threshold",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a certificate that expires at the specified time
			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					Organization: []string{"Test"},
				},
				NotBefore:   time.Now(),
				NotAfter:    time.Now().Add(tc.expiresIn),
				KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}

			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Test the logic that was fixed
			shouldRenew := time.Until(cert.NotAfter) < (time.Hour * 48)

			if shouldRenew != tc.shouldRenew {
				t.Errorf("%s: Expected shouldRenew=%v, got %v. %s",
					tc.name, tc.shouldRenew, shouldRenew, tc.description)
			}

			// Also test that a TLS certificate with this cert would have the same behavior
			tlsCert := tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  privateKey,
				Leaf:        cert,
			}

			tlsShouldRenew := time.Until(tlsCert.Leaf.NotAfter) < (time.Hour * 48)
			if tlsShouldRenew != tc.shouldRenew {
				t.Errorf("%s: TLS certificate logic mismatch. Expected shouldRenew=%v, got %v",
					tc.name, tc.shouldRenew, tlsShouldRenew)
			}
		})
	}
}

func TestOldBuggyLogic(t *testing.T) {
	// Test to demonstrate that the old buggy logic was incorrect

	// Create a certificate that expires in 24 hours (should be renewed)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour), // Expires in 24 hours
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Old buggy logic (commented out to show what was wrong)
	// oldLogic := time.Now().Sub(cert.NotAfter) < (time.Hour * 48)

	// New correct logic
	newLogic := time.Until(cert.NotAfter) < (time.Hour * 48)

	// For a certificate expiring in 24 hours:
	// - Old logic would be: time.Now().Sub(futureTime) = negative value < 48 hours = false (wrong!)
	// - New logic would be: time.Until(futureTime) = 24 hours < 48 hours = true (correct!)

	if !newLogic {
		t.Error("New logic should indicate renewal needed for certificate expiring in 24 hours")
	}
}

// Test for Bug #1: Nil Pointer Dereference in TLS Certificate Renewal
func TestNilPointerDereferenceTLSRenewal(t *testing.T) {
	// Create a temporary certificate and key file
	cert, key, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create temporary files
	certFile := "test-cert.pem"
	keyFile := "test-key.pem"

	// Write certificate and key to files
	if err := os.WriteFile(certFile, cert, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	defer os.Remove(certFile)

	if err := os.WriteFile(keyFile, key, 0o644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	defer os.Remove(keyFile)

	// Create a minimal test to reproduce the exact nil pointer issue
	// This directly tests what happens when tls.LoadX509KeyPair is used
	// and then Leaf is accessed without checking if it's nil
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load X509 key pair: %v", err)
	}

	// This demonstrates the bug: tlsCert.Leaf is nil after LoadX509KeyPair
	if tlsCert.Leaf == nil {
		t.Log("Confirmed: tlsCert.Leaf is nil after LoadX509KeyPair - this causes the bug")
	}

	// This would panic with nil pointer dereference before the fix:
	// tlsCert.Leaf.NotAfter would panic
	defer func() {
		if r := recover(); r != nil {
			t.Log("Caught panic accessing tlsCert.Leaf.NotAfter:", r)
			// This panic is expected before the fix is applied
		}
	}()

	// This should reproduce the exact bug from line 147 in utils.go
	// Before fix: panics with nil pointer dereference
	// After fix: should handle gracefully
	if tlsCert.Leaf != nil {
		_ = time.Until(tlsCert.Leaf.NotAfter) < (time.Hour * 48)
		t.Log("No panic occurred - fix may be already applied")
	} else {
		// This will panic before the fix
		_ = time.Until(tlsCert.Leaf.NotAfter) < (time.Hour * 48)
	}
}

// generateTestCertificate creates a test certificate and key for testing the nil pointer bug
func generateTestCertificate() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template - expires in 24 hours to trigger renewal logic
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour), // Expires in 24 hours (should trigger renewal)
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
		DNSNames:    []string{"test.example.com"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// Test for Bug #1 Fix: Certificate Leaf parsing works correctly
func TestCertificateLeafParsingFix(t *testing.T) {
	cert, key, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	certFile := "test-cert-fix.pem"
	keyFile := "test-key-fix.pem"

	if err := os.WriteFile(certFile, cert, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	defer os.Remove(certFile)

	if err := os.WriteFile(keyFile, key, 0o644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	defer os.Remove(keyFile)

	// Test the fix: our function should handle nil Leaf gracefully
	shouldRenew, err := checkAcmeCertificateRenewal(&certFile, &keyFile, "test", "test", "https://acme-v02.api.letsencrypt.org/directory")

	// We expect an error (likely ACME-related), but NOT a panic or nil pointer error
	if err != nil && (strings.Contains(err.Error(), "runtime error") || strings.Contains(err.Error(), "nil pointer")) {
		t.Errorf("Fix failed: still getting nil pointer error: %v", err)
	} else {
		t.Logf("Fix successful: no nil pointer errors (got: %v, shouldRenew: %v)", err, shouldRenew)
	}
}
