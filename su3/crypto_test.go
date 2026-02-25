package su3

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestNewSigningCertificate_ValidInput(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signerID := "test@example.com"

	// Test certificate creation
	certDER, err := NewSigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("NewSigningCertificate failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Certificate should not be empty")
	}

	// Parse the certificate to verify it's valid
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != signerID {
		t.Errorf("Expected CommonName %s, got %s", signerID, cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("Certificate should be marked as CA")
	}

	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be true")
	}

	// Verify organization details
	expectedOrg := []string{"I2P Anonymous Network"}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != expectedOrg[0] {
		t.Errorf("Expected Organization %v, got %v", expectedOrg, cert.Subject.Organization)
	}

	expectedOU := []string{"I2P"}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != expectedOU[0] {
		t.Errorf("Expected OrganizationalUnit %v, got %v", expectedOU, cert.Subject.OrganizationalUnit)
	}

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if cert.KeyUsage != expectedKeyUsage {
		t.Errorf("Expected KeyUsage %d, got %d", expectedKeyUsage, cert.KeyUsage)
	}

	// Verify extended key usage
	expectedExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if len(cert.ExtKeyUsage) != len(expectedExtKeyUsage) {
		t.Errorf("Expected ExtKeyUsage length %d, got %d", len(expectedExtKeyUsage), len(cert.ExtKeyUsage))
	}

	// Verify certificate validity period
	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Error("Certificate NotBefore should be before current time")
	}

	// Should be valid for 10 years
	expectedExpiry := now.AddDate(10, 0, 0)
	if cert.NotAfter.Before(expectedExpiry.AddDate(0, 0, -1)) { // Allow 1 day tolerance
		t.Error("Certificate should be valid for approximately 10 years")
	}
}

func TestNewSigningCertificate_DifferentSignerIDs(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	testCases := []struct {
		name     string
		signerID string
	}{
		{
			name:     "Email format",
			signerID: "user@domain.com",
		},
		{
			name:     "I2P domain",
			signerID: "test@mail.i2p",
		},
		{
			name:     "Simple identifier",
			signerID: "testsigner",
		},
		{
			name:     "With spaces",
			signerID: "Test Signer",
		},
		{
			name:     "Empty string",
			signerID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certDER, err := NewSigningCertificate(tc.signerID, privateKey)
			if err != nil {
				t.Fatalf("NewSigningCertificate failed for %s: %v", tc.signerID, err)
			}

			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate for %s: %v", tc.signerID, err)
			}

			if cert.Subject.CommonName != tc.signerID {
				t.Errorf("Expected CommonName %s, got %s", tc.signerID, cert.Subject.CommonName)
			}

			// Verify SubjectKeyId is set to signerID bytes
			if string(cert.SubjectKeyId) != tc.signerID {
				t.Errorf("Expected SubjectKeyId %s, got %s", tc.signerID, string(cert.SubjectKeyId))
			}
		})
	}
}

func TestNewSigningCertificate_NilPrivateKey(t *testing.T) {
	signerID := "test@example.com"

	// With nil key validation, the function should return a descriptive error
	// instead of panicking inside x509.CreateCertificate.
	_, err := NewSigningCertificate(signerID, nil)
	if err == nil {
		t.Fatal("Expected error when private key is nil")
	}
	if err.Error() != "private key cannot be nil" {
		t.Errorf("Expected 'private key cannot be nil' error, got: %v", err)
	}
}

func TestNewECDSASigningCertificate_NilPrivateKey(t *testing.T) {
	signerID := "test@example.com"

	_, err := NewECDSASigningCertificate(signerID, nil)
	if err == nil {
		t.Fatal("Expected error when ECDSA private key is nil")
	}
	if err.Error() != "ECDSA private key cannot be nil" {
		t.Errorf("Expected 'ECDSA private key cannot be nil' error, got: %v", err)
	}
}

func TestNewEd25519SigningCertificate_NilPrivateKey(t *testing.T) {
	signerID := "test@example.com"

	_, err := NewEd25519SigningCertificate(signerID, nil)
	if err == nil {
		t.Fatal("Expected error when Ed25519 private key is nil")
	}
	if err.Error() != "Ed25519 private key cannot be nil" {
		t.Errorf("Expected 'Ed25519 private key cannot be nil' error, got: %v", err)
	}
}

func TestNewSigningCertificate_SerialNumberUniqueness(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signerID := "test@example.com"

	// Generate multiple certificates
	cert1DER, err := NewSigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("Failed to create first certificate: %v", err)
	}

	cert2DER, err := NewSigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("Failed to create second certificate: %v", err)
	}

	cert1, err := x509.ParseCertificate(cert1DER)
	if err != nil {
		t.Fatalf("Failed to parse first certificate: %v", err)
	}

	cert2, err := x509.ParseCertificate(cert2DER)
	if err != nil {
		t.Fatalf("Failed to parse second certificate: %v", err)
	}

	// Serial numbers should be different
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Error("Serial numbers should be unique across different certificate generations")
	}
}

func TestCheckSignature_RSASignatures(t *testing.T) {
	// Generate test certificate and private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	certDER, err := NewSigningCertificate("test@example.com", privateKey)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	testData := []byte("test data to sign")

	testCases := []struct {
		name      string
		algorithm x509.SignatureAlgorithm
		shouldErr bool
	}{
		{
			name:      "SHA256WithRSA",
			algorithm: x509.SHA256WithRSA,
			shouldErr: false,
		},
		{
			name:      "SHA384WithRSA",
			algorithm: x509.SHA384WithRSA,
			shouldErr: false,
		},
		{
			name:      "SHA512WithRSA",
			algorithm: x509.SHA512WithRSA,
			shouldErr: false,
		},
		{
			name:      "SHA1WithRSA",
			algorithm: x509.SHA1WithRSA,
			shouldErr: false,
		},
		{
			name:      "UnsupportedAlgorithm",
			algorithm: x509.SignatureAlgorithm(999),
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldErr {
				// Test with dummy signature for unsupported algorithm
				err := checkSignature(cert, tc.algorithm, testData, []byte("dummy"))
				if err == nil {
					t.Error("Expected error for unsupported algorithm")
				}
				return
			}

			// Create a proper signature for supported algorithms
			// For this test, we'll create a minimal valid signature
			// In a real scenario, this would be done through proper RSA signing
			signature := make([]byte, 256) // Appropriate size for RSA 2048
			copy(signature, []byte("test signature data"))

			// Note: This will likely fail signature verification, but should not error
			// on algorithm support - we're mainly testing the algorithm dispatch logic
			err := checkSignature(cert, tc.algorithm, testData, signature)
			// We expect a verification failure, not an algorithm error
			// The important thing is that it doesn't return an "unsupported algorithm" error
			if err == x509.ErrUnsupportedAlgorithm {
				t.Errorf("Algorithm %v should be supported", tc.algorithm)
			}
		})
	}
}

func TestCheckSignature_InvalidInputs(t *testing.T) {
	// Generate test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	certDER, err := NewSigningCertificate("test@example.com", privateKey)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	testData := []byte("test data")
	validSignature := make([]byte, 256)

	testCases := []struct {
		name      string
		cert      *x509.Certificate
		algorithm x509.SignatureAlgorithm
		data      []byte
		signature []byte
		expectErr bool
	}{
		{
			name:      "Nil certificate",
			cert:      nil,
			algorithm: x509.SHA256WithRSA,
			data:      testData,
			signature: validSignature,
			expectErr: true,
		},
		{
			name:      "Empty data",
			cert:      cert,
			algorithm: x509.SHA256WithRSA,
			data:      []byte{},
			signature: validSignature,
			expectErr: false, // Empty data should be hashable
		},
		{
			name:      "Empty signature",
			cert:      cert,
			algorithm: x509.SHA256WithRSA,
			data:      testData,
			signature: []byte{},
			expectErr: true,
		},
		{
			name:      "Nil signature",
			cert:      cert,
			algorithm: x509.SHA256WithRSA,
			data:      testData,
			signature: nil,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSignature(tc.cert, tc.algorithm, tc.data, tc.signature)

			if tc.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				// We might get a verification error, but it shouldn't be a panic or unexpected error type
				if err == x509.ErrUnsupportedAlgorithm {
					t.Error("Should not get unsupported algorithm error for valid inputs")
				}
			}
		})
	}
}

func TestDSASignatureStructs(t *testing.T) {
	// Test that the signature structs can be used for ASN.1 operations
	dsaSig := dsaSignature{
		R: big.NewInt(12345),
		S: big.NewInt(67890),
	}

	// Test ASN.1 marshaling
	data, err := asn1.Marshal(dsaSig)
	if err != nil {
		t.Fatalf("Failed to marshal DSA signature: %v", err)
	}

	// Test ASN.1 unmarshaling
	var parsedSig dsaSignature
	_, err = asn1.Unmarshal(data, &parsedSig)
	if err != nil {
		t.Fatalf("Failed to unmarshal DSA signature: %v", err)
	}

	// Verify values
	if dsaSig.R.Cmp(parsedSig.R) != 0 {
		t.Errorf("R value mismatch: expected %s, got %s", dsaSig.R.String(), parsedSig.R.String())
	}

	if dsaSig.S.Cmp(parsedSig.S) != 0 {
		t.Errorf("S value mismatch: expected %s, got %s", dsaSig.S.String(), parsedSig.S.String())
	}
}

func TestECDSASignatureStructs(t *testing.T) {
	// Test that ECDSA signature struct (which is an alias for dsaSignature) works correctly
	ecdsaSig := ecdsaSignature{
		R: big.NewInt(99999),
		S: big.NewInt(11111),
	}

	// Test ASN.1 marshaling
	data, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		t.Fatalf("Failed to marshal ECDSA signature: %v", err)
	}

	// Test ASN.1 unmarshaling
	var parsedSig ecdsaSignature
	_, err = asn1.Unmarshal(data, &parsedSig)
	if err != nil {
		t.Fatalf("Failed to unmarshal ECDSA signature: %v", err)
	}

	// Verify values
	if ecdsaSig.R.Cmp(parsedSig.R) != 0 {
		t.Errorf("R value mismatch: expected %s, got %s", ecdsaSig.R.String(), parsedSig.R.String())
	}

	if ecdsaSig.S.Cmp(parsedSig.S) != 0 {
		t.Errorf("S value mismatch: expected %s, got %s", ecdsaSig.S.String(), parsedSig.S.String())
	}
}

func TestNewSigningCertificate_CertificateFields(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signerID := "detailed-test@example.com"
	certDER, err := NewSigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("NewSigningCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test all subject fields
	expectedSubject := pkix.Name{
		Organization:       []string{"I2P Anonymous Network"},
		OrganizationalUnit: []string{"I2P"},
		Locality:           []string{"XX"},
		StreetAddress:      []string{"XX"},
		Country:            []string{"XX"},
		CommonName:         signerID,
	}

	if cert.Subject.CommonName != expectedSubject.CommonName {
		t.Errorf("CommonName mismatch: expected %s, got %s", expectedSubject.CommonName, cert.Subject.CommonName)
	}

	// Check organization
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != expectedSubject.Organization[0] {
		t.Errorf("Organization mismatch: expected %v, got %v", expectedSubject.Organization, cert.Subject.Organization)
	}

	// Check organizational unit
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != expectedSubject.OrganizationalUnit[0] {
		t.Errorf("OrganizationalUnit mismatch: expected %v, got %v", expectedSubject.OrganizationalUnit, cert.Subject.OrganizationalUnit)
	}

	// Check locality
	if len(cert.Subject.Locality) != 1 || cert.Subject.Locality[0] != expectedSubject.Locality[0] {
		t.Errorf("Locality mismatch: expected %v, got %v", expectedSubject.Locality, cert.Subject.Locality)
	}

	// Check street address
	if len(cert.Subject.StreetAddress) != 1 || cert.Subject.StreetAddress[0] != expectedSubject.StreetAddress[0] {
		t.Errorf("StreetAddress mismatch: expected %v, got %v", expectedSubject.StreetAddress, cert.Subject.StreetAddress)
	}

	// Check country
	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != expectedSubject.Country[0] {
		t.Errorf("Country mismatch: expected %v, got %v", expectedSubject.Country, cert.Subject.Country)
	}

	// Verify the public key matches
	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Certificate public key is not RSA")
	}

	if certPubKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("Certificate public key doesn't match private key")
	}

	if certPubKey.E != privateKey.PublicKey.E {
		t.Error("Certificate public key exponent doesn't match private key")
	}
}

func TestNewECDSASigningCertificate_ValidInput(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	signerID := "test@example.com"
	certDER, err := NewECDSASigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("NewECDSASigningCertificate failed: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("Certificate should not be empty")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	if cert.Subject.CommonName != signerID {
		t.Errorf("Expected CommonName %s, got %s", signerID, cert.Subject.CommonName)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected ECDSA public key, got %T", cert.PublicKey)
	}
}

func TestNewEd25519SigningCertificate_ValidInput(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	signerID := "test@example.com"
	certDER, err := NewEd25519SigningCertificate(signerID, privateKey)
	if err != nil {
		t.Fatalf("NewEd25519SigningCertificate failed: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("Certificate should not be empty")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	if cert.Subject.CommonName != signerID {
		t.Errorf("Expected CommonName %s, got %s", signerID, cert.Subject.CommonName)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("Expected Ed25519 public key, got %T", cert.PublicKey)
	}
}

func TestECDSACurveForSignatureType(t *testing.T) {
	tests := []struct {
		name     string
		sigType  uint16
		expected elliptic.Curve
	}{
		{"ECDSA SHA256 returns P256", SigTypeECDSAWithSHA256, elliptic.P256()},
		{"ECDSA SHA384 returns P384", SigTypeECDSAWithSHA384, elliptic.P384()},
		{"ECDSA SHA512 returns P521", SigTypeECDSAWithSHA512, elliptic.P521()},
		{"RSA type returns nil", SigTypeRSAWithSHA512, nil},
		{"DSA type returns nil", SigTypeDSA, nil},
		{"Ed25519 type returns nil", SigTypeEdDSASHA512Ed25519ph, nil},
		{"Unknown type returns nil", uint16(999), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ECDSACurveForSignatureType(tt.sigType)
			if got != tt.expected {
				t.Errorf("ECDSACurveForSignatureType(%d) = %v, want %v", tt.sigType, got, tt.expected)
			}
		})
	}
}

func TestMapAlgorithmToHashType_Ed25519(t *testing.T) {
	// Verify that PureEd25519 maps to SHA-512 for Ed25519ph compatibility
	hashType, err := mapAlgorithmToHashType(x509.PureEd25519)
	if err != nil {
		t.Fatalf("mapAlgorithmToHashType(PureEd25519) returned error: %v", err)
	}
	if hashType != crypto.SHA512 {
		t.Errorf("mapAlgorithmToHashType(PureEd25519) = %v, want SHA512", hashType)
	}
}

func TestMapAlgorithmToHashType_UnsupportedAlgorithm(t *testing.T) {
	_, err := mapAlgorithmToHashType(x509.SignatureAlgorithm(999))
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm")
	}
}

// Benchmark tests for performance validation
func BenchmarkNewSigningCertificate(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("Failed to generate RSA key: %v", err)
	}

	signerID := "benchmark@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewSigningCertificate(signerID, privateKey)
		if err != nil {
			b.Fatalf("NewSigningCertificate failed: %v", err)
		}
	}
}

func BenchmarkCheckSignature(b *testing.B) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("Failed to generate RSA key: %v", err)
	}

	certDER, err := NewSigningCertificate("benchmark@example.com", privateKey)
	if err != nil {
		b.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatalf("Failed to parse certificate: %v", err)
	}

	testData := []byte("benchmark test data")
	signature := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkSignature(cert, x509.SHA256WithRSA, testData, signature)
	}
}
