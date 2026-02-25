package su3

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-i2p/logger"
)

var lgr = logger.GetGoI2PLogger()

// dsaSignature represents a DSA signature containing R and S components.
// Used for ASN.1 encoding/decoding of DSA signatures in SU3 verification.
type dsaSignature struct {
	R, S *big.Int
}

// ecdsaSignature represents an ECDSA signature, which has the same structure as DSA.
// This named type definition provides semantic clarity when working with ECDSA signatures.
// Note: This is a type definition (not a type alias), so ecdsaSignature has its own method set.
type ecdsaSignature dsaSignature

// checkSignature verifies a digital signature against signed data using the specified certificate.
// It supports RSA, DSA, and ECDSA signature algorithms with various hash functions (SHA1, SHA256, SHA384, SHA512).
// This function extends the standard x509 signature verification to support additional algorithms needed for SU3 files.
func checkSignature(c *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) (err error) {
	if c == nil {
		lgr.Error("Certificate is nil during signature verification")
		return errors.New("x509: certificate is nil")
	}

	hashType, err := mapAlgorithmToHashType(algo)
	if err != nil {
		return err
	}

	digest, err := computeDigest(hashType, signed)
	if err != nil {
		return err
	}

	return verifySignatureByKeyType(c.PublicKey, digest, signature)
}

// mapAlgorithmToHashType maps a signature algorithm to its corresponding hash function.
// It returns the appropriate crypto.Hash type for the given x509.SignatureAlgorithm.
func mapAlgorithmToHashType(algo x509.SignatureAlgorithm) (crypto.Hash, error) {
	var hashType crypto.Hash

	// Map signature algorithm to appropriate hash function
	// Each algorithm specifies both the signature method and hash type
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	case x509.PureEd25519:
		// Ed25519ph is handled separately via verifyEd25519ph() in su3.go.
		// If a caller reaches this via checkSignature with PureEd25519, use SHA-512
		// as the prehash algorithm consistent with Ed25519ph requirements.
		hashType = crypto.SHA512
	default:
		lgr.WithField("algorithm", algo).Error("Unsupported signature algorithm")
		return 0, x509.ErrUnsupportedAlgorithm
	}

	return hashType, nil
}

// computeDigest creates a hash digest of the signed data using the specified hash type.
// It validates hash availability and computes the digest needed for signature verification.
func computeDigest(hashType crypto.Hash, signed []byte) ([]byte, error) {
	if !hashType.Available() {
		lgr.WithField("hash_type", hashType).Error("Hash type not available")
		return nil, x509.ErrUnsupportedAlgorithm
	}

	h := hashType.New()
	h.Write(signed)
	return h.Sum(nil), nil
}

// verifySignatureByKeyType performs signature verification based on the public key algorithm type.
// It handles RSA, DSA, and ECDSA key types with their respective signature formats and verification procedures.
func verifySignatureByKeyType(publicKey crypto.PublicKey, digest, signature []byte) error {
	// Verify signature based on public key algorithm type
	// Each algorithm has different signature formats and verification procedures
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// We pass hash=0 to verify raw PKCS#1 v1.5 signatures without the
		// DigestInfo ASN.1 prefix. This matches the signing mode in su3.go
		// and is required for I2P SU3 format compatibility.
		return rsa.VerifyPKCS1v15(pub, 0, digest, signature)
	case *dsa.PublicKey:
		return verifyDSASignature(pub, digest, signature)
	case *ecdsa.PublicKey:
		return verifyECDSASignature(pub, digest, signature)
	case ed25519.PublicKey:
		// Note: For standard checkSignature path, this verifies a raw Ed25519 signature
		// against a pre-computed digest. Ed25519ph verification is handled separately
		// in verifyEd25519ph() in su3.go.
		if !ed25519.Verify(pub, digest, signature) {
			lgr.Error("Ed25519 signature verification failed")
			return errors.New("ed25519: signature verification failure")
		}
		return nil
	}
	lgr.WithField("public_key_type", fmt.Sprintf("%T", publicKey)).Error("Unsupported public key algorithm")
	return x509.ErrUnsupportedAlgorithm
}

// verifyDSASignature verifies a DSA signature by unmarshaling the ASN.1 encoded signature
// and validating the R and S components before performing cryptographic verification.
func verifyDSASignature(pub *dsa.PublicKey, digest, signature []byte) error {
	dsaSig := new(dsaSignature)
	if _, err := asn1.Unmarshal(signature, dsaSig); err != nil {
		lgr.WithError(err).Error("Failed to unmarshal DSA signature")
		return err
	}
	// Validate DSA signature components are positive integers
	// Zero or negative values indicate malformed or invalid signatures
	if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
		lgr.WithField("r_sign", dsaSig.R.Sign()).WithField("s_sign", dsaSig.S.Sign()).Error("DSA signature contained zero or negative values")
		return errors.New("x509: DSA signature contained zero or negative values")
	}
	if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
		lgr.Error("DSA signature verification failed")
		return errors.New("x509: DSA verification failure")
	}
	return nil
}

// verifyECDSASignature verifies an ECDSA signature by unmarshaling the ASN.1 encoded signature
// and validating the R and S components before performing cryptographic verification.
func verifyECDSASignature(pub *ecdsa.PublicKey, digest, signature []byte) error {
	ecdsaSig := new(ecdsaSignature)
	if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
		lgr.WithError(err).Error("Failed to unmarshal ECDSA signature")
		return err
	}
	// Validate ECDSA signature components are positive integers
	// Similar validation to DSA as both use R,S component pairs
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		lgr.WithField("r_sign", ecdsaSig.R.Sign()).WithField("s_sign", ecdsaSig.S.Sign()).Error("ECDSA signature contained zero or negative values")
		return errors.New("x509: ECDSA signature contained zero or negative values")
	}
	if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
		lgr.Error("ECDSA signature verification failed")
		return errors.New("x509: ECDSA verification failure")
	}
	return nil
}

// NewSigningCertificate creates a self-signed X.509 certificate for SU3 file signing.
// It generates a certificate with the specified signer ID and RSA private key for use in
// I2P reseed operations. The certificate is valid for 10 years and includes proper key usage
// extensions for digital signatures.
func NewSigningCertificate(signerID string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	var subjectKeyId []byte
	isCA := true
	// Configure certificate authority status based on signer ID presence
	// Empty signer IDs create non-CA certificates to prevent auto-generation issues
	if signerID != "" {
		subjectKeyId = []byte(signerID)
	} else {
		// When signerID is empty, create non-CA certificate to prevent auto-generation of SubjectKeyId
		subjectKeyId = []byte("")
		isCA = false
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          subjectKeyId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         signerID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	publicKey := &privateKey.PublicKey

	// Create self-signed certificate using template as both subject and issuer
	// This generates a root certificate suitable for SU3 file signing operations
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// NewECDSASigningCertificate creates a self-signed X.509 certificate for SU3 file signing
// using an ECDSA private key. It generates a certificate with the specified signer ID
// for use in I2P reseed operations. The certificate is valid for 10 years and includes
// proper key usage extensions for digital signatures.
func NewECDSASigningCertificate(signerID string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("ECDSA private key cannot be nil")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	var subjectKeyId []byte
	isCA := true
	if signerID != "" {
		subjectKeyId = []byte(signerID)
	} else {
		subjectKeyId = []byte("")
		isCA = false
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          subjectKeyId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         signerID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	publicKey := &privateKey.PublicKey
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ECDSACurveForSignatureType returns the appropriate elliptic curve for the
// given ECDSA signature type constant. Returns nil for non-ECDSA or
// unrecognized signature types; callers should check for a nil return value.
func ECDSACurveForSignatureType(sigType uint16) elliptic.Curve {
	switch sigType {
	case SigTypeECDSAWithSHA256:
		return elliptic.P256()
	case SigTypeECDSAWithSHA384:
		return elliptic.P384()
	case SigTypeECDSAWithSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// NewEd25519SigningCertificate creates a self-signed X.509 certificate for SU3 file signing
// using an Ed25519 private key. It generates a certificate with the specified signer ID
// for use in I2P reseed operations. The certificate is valid for 10 years and includes
// proper key usage extensions for digital signatures.
func NewEd25519SigningCertificate(signerID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("Ed25519 private key cannot be nil")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	var subjectKeyId []byte
	isCA := true
	if signerID != "" {
		subjectKeyId = []byte(signerID)
	} else {
		subjectKeyId = []byte("")
		isCA = false
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          subjectKeyId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         signerID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	publicKey := privateKey.Public()
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
