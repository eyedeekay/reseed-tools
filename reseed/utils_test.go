package reseed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignerFilename(t *testing.T) {
	tests := []struct {
		name     string
		signer   string
		expected string
	}{
		{
			name:     "Simple email address",
			signer:   "test@example.com",
			expected: "test_at_example.com.crt",
		},
		{
			name:     "I2P email address",
			signer:   "user@mail.i2p",
			expected: "user_at_mail.i2p.crt",
		},
		{
			name:     "Complex email with dots",
			signer:   "test.user@sub.domain.com",
			expected: "test.user_at_sub.domain.com.crt",
		},
		{
			name:     "Email with numbers",
			signer:   "user123@example456.org",
			expected: "user123_at_example456.org.crt",
		},
		{
			name:     "Empty string",
			signer:   "",
			expected: ".crt",
		},
		{
			name:     "String without @ symbol",
			signer:   "no-at-symbol",
			expected: "no-at-symbol.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SignerFilename(tt.signer)
			if result != tt.expected {
				t.Errorf("SignerFilename(%q) = %q, want %q", tt.signer, result, tt.expected)
			}
		})
	}
}

func TestNewTLSCertificate(t *testing.T) {
	// Generate a test private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	tests := []struct {
		name    string
		host    string
		wantErr bool
		checkCN bool
	}{
		{
			name:    "Valid hostname",
			host:    "example.com",
			wantErr: false,
			checkCN: true,
		},
		{
			name:    "Valid IP address",
			host:    "192.168.1.1",
			wantErr: false,
			checkCN: true,
		},
		{
			name:    "Localhost",
			host:    "localhost",
			wantErr: false,
			checkCN: true,
		},
		{
			name:    "Empty host",
			host:    "",
			wantErr: false,
			checkCN: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certBytes, err := NewTLSCertificate(tt.host, priv)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Parse the certificate to verify it's valid
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					t.Errorf("Failed to parse generated certificate: %v", err)
					return
				}

				// Verify certificate properties
				if tt.checkCN && cert.Subject.CommonName != tt.host {
					t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, tt.host)
				}

				// Check if it's a valid CA certificate
				if !cert.IsCA {
					t.Error("Certificate should be marked as CA")
				}

				// Check key usage
				expectedKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
				if cert.KeyUsage != expectedKeyUsage {
					t.Errorf("Certificate KeyUsage = %v, want %v", cert.KeyUsage, expectedKeyUsage)
				}

				// Check validity period (should be 5 years)
				validityDuration := cert.NotAfter.Sub(cert.NotBefore)
				expectedDuration := 5 * 365 * 24 * time.Hour
				tolerance := 24 * time.Hour // Allow 1 day tolerance

				if validityDuration < expectedDuration-tolerance || validityDuration > expectedDuration+tolerance {
					t.Errorf("Certificate validity duration = %v, want approximately %v", validityDuration, expectedDuration)
				}
			}
		})
	}
}

func TestNewTLSCertificateAltNames_SingleHost(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	host := "test.example.com"
	certBytes, err := NewTLSCertificateAltNames(priv, host)
	if err != nil {
		t.Fatalf("NewTLSCertificateAltNames() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != host {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, host)
	}

	// Should have the host in DNS names (since it gets added after splitting)
	found := false
	for _, dnsName := range cert.DNSNames {
		if dnsName == host {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DNS names %v should contain %q", cert.DNSNames, host)
	}
}

func TestNewTLSCertificateAltNames_MultipleHosts(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	hosts := []string{"primary.example.com", "alt1.example.com", "alt2.example.com"}
	certBytes, err := NewTLSCertificateAltNames(priv, hosts...)
	if err != nil {
		t.Fatalf("NewTLSCertificateAltNames() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Primary host should be the CommonName
	if cert.Subject.CommonName != hosts[0] {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, hosts[0])
	}

	// All hosts should be in DNS names
	for _, expectedHost := range hosts {
		found := false
		for _, dnsName := range cert.DNSNames {
			if dnsName == expectedHost {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DNS names %v should contain %q", cert.DNSNames, expectedHost)
		}
	}
}

func TestNewTLSCertificateAltNames_IPAddresses(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	// Test with comma-separated IPs and hostnames
	hostString := "192.168.1.1,example.com,10.0.0.1"
	certBytes, err := NewTLSCertificateAltNames(priv, hostString)
	if err != nil {
		t.Fatalf("NewTLSCertificateAltNames() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Check IP addresses
	expectedIPs := []string{"192.168.1.1", "10.0.0.1"}
	for _, expectedIP := range expectedIPs {
		ip := net.ParseIP(expectedIP)
		found := false
		for _, certIP := range cert.IPAddresses {
			if certIP.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IP addresses %v should contain %s", cert.IPAddresses, expectedIP)
		}
	}

	// Check DNS name
	found := false
	for _, dnsName := range cert.DNSNames {
		if dnsName == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DNS names %v should contain 'example.com'", cert.DNSNames)
	}
}

func TestNewTLSCertificateAltNames_EmptyHosts(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	// Test with empty slice - this should panic due to hosts[1:] access
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling with no hosts, but didn't panic")
		}
	}()

	_, _ = NewTLSCertificateAltNames(priv)
}

func TestNewTLSCertificateAltNames_EmptyStringHost(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	// Test with single empty string - this should work
	certBytes, err := NewTLSCertificateAltNames(priv, "")
	if err != nil {
		t.Fatalf("NewTLSCertificateAltNames() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "" {
		t.Errorf("CommonName = %q, want empty string", cert.Subject.CommonName)
	}
}

func TestKeyStore_ReseederCertificate(t *testing.T) {
	// Create temporary directory structure
	tmpDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test certificate file
	signer := "test@example.com"
	certFileName := SignerFilename(signer)
	reseedDir := filepath.Join(tmpDir, "reseed")
	err = os.MkdirAll(reseedDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create reseed dir: %v", err)
	}

	// Generate a test certificate
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certBytes, err := NewTLSCertificate("test.example.com", priv)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Write certificate to file
	certFile := filepath.Join(reseedDir, certFileName)
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pemBytes := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile(certFile, pemBytes, 0o644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Test KeyStore
	ks := &KeyStore{Path: tmpDir}
	cert, err := ks.ReseederCertificate([]byte(signer))
	if err != nil {
		t.Errorf("ReseederCertificate() error = %v", err)
		return
	}

	if cert == nil {
		t.Error("Expected certificate, got nil")
		return
	}

	// Verify it's the same certificate
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}
}

func TestKeyStore_ReseederCertificate_FileNotFound(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks := &KeyStore{Path: tmpDir}
	signer := "nonexistent@example.com"

	_, err = ks.ReseederCertificate([]byte(signer))
	if err == nil {
		t.Error("Expected error for non-existent certificate, got nil")
	}
}

func TestKeyStore_DirReseederCertificate(t *testing.T) {
	// Create temporary directory structure
	tmpDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create custom directory and test certificate
	customDir := "custom_certs"
	signer := "test@example.com"
	certFileName := SignerFilename(signer)
	certDir := filepath.Join(tmpDir, customDir)
	err = os.MkdirAll(certDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	// Generate and write test certificate
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certBytes, err := NewTLSCertificate("custom.example.com", priv)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	certFile := filepath.Join(certDir, certFileName)
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pemBytes := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile(certFile, pemBytes, 0o644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Test DirReseederCertificate
	ks := &KeyStore{Path: tmpDir}
	cert, err := ks.DirReseederCertificate(customDir, []byte(signer))
	if err != nil {
		t.Errorf("DirReseederCertificate() error = %v", err)
		return
	}

	if cert == nil {
		t.Error("Expected certificate, got nil")
		return
	}

	if cert.Subject.CommonName != "custom.example.com" {
		t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "custom.example.com")
	}
}

func TestKeyStore_ReseederCertificate_InvalidPEM(t *testing.T) {
	// Create temporary directory and invalid certificate file
	tmpDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	signer := "test@example.com"
	certFileName := SignerFilename(signer)
	reseedDir := filepath.Join(tmpDir, "reseed")
	err = os.MkdirAll(reseedDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create reseed dir: %v", err)
	}

	// Write invalid certificate data in valid PEM format but with bad certificate bytes
	// This is valid base64 but invalid certificate data
	invalidPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZGNlcnRpZmljYXRlZGF0YQ==
-----END CERTIFICATE-----`

	certFile := filepath.Join(reseedDir, certFileName)
	err = os.WriteFile(certFile, []byte(invalidPEM), 0o644)
	if err != nil {
		t.Fatalf("Failed to write invalid certificate file: %v", err)
	}

	ks := &KeyStore{Path: tmpDir}
	_, err = ks.ReseederCertificate([]byte(signer))
	if err == nil {
		t.Error("Expected error for invalid certificate, got nil")
	}
}

func TestKeyStore_ReseederCertificate_NonPEMData(t *testing.T) {
	// Create temporary directory and non-PEM file
	tmpDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	signer := "test@example.com"
	certFileName := SignerFilename(signer)
	reseedDir := filepath.Join(tmpDir, "reseed")
	err = os.MkdirAll(reseedDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create reseed dir: %v", err)
	}

	// Write completely invalid data that can't be parsed as PEM
	certFile := filepath.Join(reseedDir, certFileName)
	err = os.WriteFile(certFile, []byte("completely invalid certificate data"), 0o644)
	if err != nil {
		t.Fatalf("Failed to write invalid certificate file: %v", err)
	}

	// After the nil PEM decode fix, the function should return a descriptive error
	// instead of panicking with a nil pointer dereference.
	ks := &KeyStore{Path: tmpDir}
	_, err = ks.ReseederCertificate([]byte(signer))
	if err == nil {
		t.Error("Expected error for non-PEM data, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to decode PEM data") {
		t.Errorf("Expected PEM decode error, got: %v", err)
	}
}

// Benchmark tests for performance validation
func BenchmarkSignerFilename(b *testing.B) {
	signer := "benchmark@example.com"
	for i := 0; i < b.N; i++ {
		_ = SignerFilename(signer)
	}
}

func BenchmarkNewTLSCertificate(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate test private key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewTLSCertificate("benchmark.example.com", priv)
		if err != nil {
			b.Fatalf("NewTLSCertificate failed: %v", err)
		}
	}
}
