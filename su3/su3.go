package su3

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// Constants moved to constants.go

// File represents a complete SU3 file structure for I2P software distribution.
// SU3 files are cryptographically signed containers used to distribute router updates,
// plugins, reseed data, and other I2P network components. Each file contains metadata,
// content, and a digital signature for verification.
type File struct {
	// Format specifies the SU3 file format version for compatibility tracking
	Format uint8

	// SignatureType indicates the cryptographic signature algorithm used
	// Valid values are defined by Sig* constants (RSA, ECDSA, DSA variants)
	SignatureType uint16

	// FileType specifies the format of the contained data
	// Valid values are defined by FileType* constants (ZIP, XML, HTML, etc.)
	FileType uint8

	// ContentType categorizes the purpose of the contained data
	// Valid values are defined by ContentType* constants (Router, Plugin, Reseed, etc.)
	ContentType uint8

	// Version contains version information as bytes, zero-padded to minimum length
	Version []byte

	// SignerID contains the identity of the entity that signed this file
	SignerID []byte

	// Content holds the actual file payload data to be distributed
	Content []byte

	// Signature contains the cryptographic signature for file verification
	Signature []byte

	// SignedBytes stores the signed portion of the file for verification purposes
	SignedBytes []byte
}

// New creates a new SU3 file with default settings and current timestamp.
// The file is initialized with RSA-SHA512 signature type and a Unix timestamp version.
// Additional fields must be set before signing and distribution.
// New creates a new SU3 file with default settings and current timestamp.
// The file is initialized with RSA-SHA512 signature type and a Unix timestamp version.
// Additional fields must be set before signing and distribution.
func New() *File {
	return &File{
		Version:       []byte(strconv.FormatInt(time.Now().Unix(), 10)),
		SignatureType: SigTypeRSAWithSHA512,
	}
}

// Sign cryptographically signs the SU3 file using the provided private key.
// The key must implement crypto.Signer (e.g. *rsa.PrivateKey, *ecdsa.PrivateKey).
// The key type must match the declared SignatureType — RSA keys for RSA signature
// types, ECDSA keys for ECDSA signature types. The signature covers the file
// header and content but not the signature itself.
// Returns an error if the key is nil, the key/type combination is invalid,
// or signature generation fails.
func (s *File) Sign(privkey crypto.Signer) error {
	if privkey == nil {
		lgr.Error("Private key cannot be nil for SU3 signing")
		return fmt.Errorf("private key cannot be nil")
	}

	// Validate that the key type matches the declared SignatureType and
	// select the appropriate hash algorithm.
	var hashType crypto.Hash
	switch s.SignatureType {
	case SigTypeDSA:
		return fmt.Errorf("DSA signing is not supported")
	case SigTypeECDSAWithSHA256:
		if err := validateECDSAKey(privkey, elliptic.P256()); err != nil {
			return err
		}
		hashType = crypto.SHA256
	case SigTypeECDSAWithSHA384:
		if err := validateECDSAKey(privkey, elliptic.P384()); err != nil {
			return err
		}
		hashType = crypto.SHA384
	case SigTypeECDSAWithSHA512:
		if err := validateECDSAKey(privkey, elliptic.P521()); err != nil {
			return err
		}
		hashType = crypto.SHA512
	case SigTypeRSAWithSHA256:
		if err := validateRSAKey(privkey); err != nil {
			return err
		}
		hashType = crypto.SHA256
	case SigTypeRSAWithSHA384:
		if err := validateRSAKey(privkey); err != nil {
			return err
		}
		hashType = crypto.SHA384
	case SigTypeRSAWithSHA512:
		if err := validateRSAKey(privkey); err != nil {
			return err
		}
		hashType = crypto.SHA512
	case SigTypeEdDSASHA512Ed25519ph:
		if err := validateEd25519Key(privkey); err != nil {
			return err
		}
		// Ed25519ph uses SHA-512 prehash: we hash the data ourselves,
		// then pass the 64-byte digest to Ed25519 Sign with Hash option.
		hashType = crypto.SHA512
	default:
		lgr.WithField("signature_type", s.SignatureType).Error("Unknown signature type for SU3 signing")
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	// Pre-calculate signature length so BodyBytes() generates a correct header.
	// For ECDSA, we use a fixed canonical length per curve so the header is
	// deterministic. The actual DER signature will be zero-padded to this length.
	// Ed25519 signatures are always exactly 64 bytes.
	switch key := privkey.(type) {
	case *rsa.PrivateKey:
		s.Signature = make([]byte, key.Size())
	case *ecdsa.PrivateKey:
		s.Signature = make([]byte, ecdsaCanonicalSigLen(key))
	case ed25519.PrivateKey:
		s.Signature = make([]byte, ed25519.SignatureSize) // always 64 bytes
	default:
		return fmt.Errorf("unsupported key type: %T", privkey)
	}

	h := hashType.New()
	h.Write(s.BodyBytes())
	digest := h.Sum(nil)

	// Dispatch signing based on key type
	switch key := privkey.(type) {
	case *rsa.PrivateKey:
		// Generate RSA signature using PKCS#1 v1.5 padding scheme
		// The hash type is already applied, so we pass 0 to indicate pre-hashed data
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, digest)
		if err != nil {
			lgr.WithError(err).Error("Failed to generate RSA signature for SU3 file")
			return err
		}
		s.Signature = sig
	case *ecdsa.PrivateKey:
		// Generate ECDSA signature as ASN.1 DER-encoded (R, S) pair
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			lgr.WithError(err).Error("Failed to generate ECDSA signature for SU3 file")
			return err
		}
		// Pad the DER-encoded signature to the canonical length so the
		// signatureLength header field is consistent between signing and
		// verification. asn1.Unmarshal will correctly parse the DER prefix
		// and ignore trailing zero-padding.
		canonLen := ecdsaCanonicalSigLen(key)
		if len(sig) > canonLen {
			return fmt.Errorf("ECDSA signature length %d exceeds canonical max %d", len(sig), canonLen)
		}
		padded := make([]byte, canonLen)
		copy(padded, sig)
		s.Signature = padded
	case ed25519.PrivateKey:
		// Ed25519ph (prehash): the digest is the SHA-512 hash of the body.
		// We pass it to Sign with Options{Hash: SHA512} to indicate prehash mode.
		// Per RFC 8032 and I2P spec, Ed25519ph signatures are always 64 bytes.
		sig, err := key.Sign(rand.Reader, digest, &ed25519.Options{Hash: crypto.SHA512})
		if err != nil {
			lgr.WithError(err).Error("Failed to generate Ed25519ph signature for SU3 file")
			return err
		}
		s.Signature = sig
	default:
		return fmt.Errorf("unsupported key type for signing: %T", privkey)
	}

	return nil
}

// validateRSAKey checks that privkey is an *rsa.PrivateKey.
func validateRSAKey(privkey crypto.Signer) error {
	if _, ok := privkey.(*rsa.PrivateKey); !ok {
		return fmt.Errorf("RSA signature type requires *rsa.PrivateKey, got %T", privkey)
	}
	return nil
}

// validateECDSAKey checks that privkey is an *ecdsa.PrivateKey on the expected curve.
func validateECDSAKey(privkey crypto.Signer, expectedCurve elliptic.Curve) error {
	ecKey, ok := privkey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("ECDSA signature type requires *ecdsa.PrivateKey, got %T", privkey)
	}
	if ecKey.Curve != expectedCurve {
		return fmt.Errorf("ECDSA key curve mismatch: expected %s, got %s",
			expectedCurve.Params().Name, ecKey.Curve.Params().Name)
	}
	return nil
}

// validateEd25519Key checks that privkey is an ed25519.PrivateKey.
func validateEd25519Key(privkey crypto.Signer) error {
	if _, ok := privkey.(ed25519.PrivateKey); !ok {
		return fmt.Errorf("EdDSA signature type requires ed25519.PrivateKey, got %T", privkey)
	}
	return nil
}

// ecdsaCanonicalSigLen returns the fixed canonical signature length for the
// given ECDSA key's curve. ECDSA DER signatures are variable-length, but
// we use a fixed maximum per curve so the SU3 header signatureLength field
// is deterministic. Actual signatures are zero-padded to this length.
func ecdsaCanonicalSigLen(key *ecdsa.PrivateKey) int {
	// DER encoding: SEQUENCE { INTEGER r, INTEGER s }
	// Each integer: at most (orderLen + 1) bytes (sign padding) + 2 bytes tag+length
	// Sequence overhead: 2 bytes if content ≤ 127, 3 bytes otherwise
	orderLen := (key.Curve.Params().BitSize + 7) / 8
	contentLen := 2*(orderLen+1) + 4 // two integers with tag+length
	if contentLen > 127 {
		return 3 + contentLen // long-form SEQUENCE length
	}
	return 2 + contentLen // short-form SEQUENCE length
}

// BodyBytes generates the binary representation of the SU3 file without the signature.
// This includes the magic header, metadata fields, and content data in the proper SU3 format.
// The signature field length is calculated but the actual signature bytes are not included.
// This data is used for signature generation and verification operations.
func (s *File) BodyBytes() []byte {
	var (
		buf = new(bytes.Buffer)

		skip    [1]byte
		bigSkip [12]byte

		versionLength   = uint8(len(s.Version))
		signatureLength = uint16(512)
		signerIDLength  = uint8(len(s.SignerID))
		contentLength   = uint64(len(s.Content))
	)

	// Calculate signature length based on algorithm and available signature data.
	// For RSA, signature length is fixed by key size. For ECDSA, we use
	// canonical fixed lengths per curve (actual DER signatures are zero-padded).
	// When s.Signature is already populated (e.g. after Sign or UnmarshalBinary),
	// use its actual length to ensure header consistency.
	switch s.SignatureType {
	case SigTypeDSA:
		signatureLength = uint16(40)
	case SigTypeECDSAWithSHA256:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(72) // Canonical max for P-256 DER
		}
	case SigTypeECDSAWithSHA384:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(104) // Canonical max for P-384 DER
		}
	case SigTypeECDSAWithSHA512:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(141) // Canonical max for P-521 DER
		}
	case SigTypeRSAWithSHA256:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(256) // Default for 2048-bit RSA key
		}
	case SigTypeRSAWithSHA384:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(384) // Default for 3072-bit RSA key
		}
	case SigTypeRSAWithSHA512:
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(256) // Default for 2048-bit RSA key
		}
	case SigTypeEdDSASHA512Ed25519ph:
		// Ed25519 signatures are always exactly 64 bytes per I2P spec and RFC 8032.
		// No variable-length padding needed.
		signatureLength = uint16(ed25519.SignatureSize)
	}

	// Ensure version field meets minimum length requirement by zero-padding
	// SU3 specification requires version fields to be at least minVersionLength bytes
	if len(s.Version) < minVersionLength {
		minBytes := make([]byte, minVersionLength)
		copy(minBytes, s.Version)
		s.Version = minBytes
		versionLength = uint8(len(s.Version))
	}

	// Write SU3 file header in big-endian binary format following specification
	// Each field is written in the exact order and size required by the SU3 format
	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.Format)
	binary.Write(buf, binary.BigEndian, s.SignatureType)
	binary.Write(buf, binary.BigEndian, signatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, versionLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, signerIDLength)
	binary.Write(buf, binary.BigEndian, contentLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.FileType)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.ContentType)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, s.Version)
	binary.Write(buf, binary.BigEndian, s.SignerID)
	binary.Write(buf, binary.BigEndian, s.Content)

	return buf.Bytes()
}

// MarshalBinary serializes the complete SU3 file including signature to binary format.
// This produces the final SU3 file data that can be written to disk or transmitted.
// The signature must be set before calling this method for a valid SU3 file.
func (s *File) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(s.BodyBytes())

	// Append signature to complete the SU3 file format
	// The signature is always the last component of a valid SU3 file
	binary.Write(buf, binary.BigEndian, s.Signature)

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes binary data into a SU3 file structure.
// This parses the SU3 file format and populates all fields including header metadata,
// content, and signature. No validation is performed on the parsed data.
func (s *File) UnmarshalBinary(data []byte) error {
	var (
		r = bytes.NewReader(data)

		magic   = []byte(magicBytes)
		skip    [1]byte
		bigSkip [12]byte

		signatureLength uint16
		versionLength   uint8
		signerIDLength  uint8
		contentLength   uint64
	)

	// Read SU3 file header fields in big-endian format
	// Each binary.Read operation should be checked for errors in production code
	binary.Read(r, binary.BigEndian, &magic)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.Format)
	binary.Read(r, binary.BigEndian, &s.SignatureType)
	binary.Read(r, binary.BigEndian, &signatureLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &versionLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &signerIDLength)
	binary.Read(r, binary.BigEndian, &contentLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.FileType)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.ContentType)
	binary.Read(r, binary.BigEndian, &bigSkip)

	// Allocate byte slices based on header length fields
	// These lengths determine how much data to read for each variable-length field
	s.Version = make([]byte, versionLength)
	s.SignerID = make([]byte, signerIDLength)
	s.Content = make([]byte, contentLength)
	s.Signature = make([]byte, signatureLength)

	// Read variable-length data fields in the order specified by SU3 format
	// Version, SignerID, Content, and Signature follow the fixed header fields
	binary.Read(r, binary.BigEndian, &s.Version)
	binary.Read(r, binary.BigEndian, &s.SignerID)
	binary.Read(r, binary.BigEndian, &s.Content)
	binary.Read(r, binary.BigEndian, &s.Signature)

	return nil
}

// VerifySignature validates the SU3 file signature using the provided certificate.
// This checks that the signature was created by the private key corresponding to the
// certificate's public key. The signature algorithm is determined by the SignatureType field.
// Returns an error if verification fails or the signature type is unsupported.
func (s *File) VerifySignature(cert *x509.Certificate) error {
	var sigAlg x509.SignatureAlgorithm
	// Map SU3 signature types to standard x509 signature algorithms
	// Each SU3 signature type corresponds to a specific combination of algorithm and hash
	switch s.SignatureType {
	case SigTypeDSA:
		sigAlg = x509.DSAWithSHA1
	case SigTypeECDSAWithSHA256:
		sigAlg = x509.ECDSAWithSHA256
	case SigTypeECDSAWithSHA384:
		sigAlg = x509.ECDSAWithSHA384
	case SigTypeECDSAWithSHA512:
		sigAlg = x509.ECDSAWithSHA512
	case SigTypeRSAWithSHA256:
		sigAlg = x509.SHA256WithRSA
	case SigTypeRSAWithSHA384:
		sigAlg = x509.SHA384WithRSA
	case SigTypeRSAWithSHA512:
		sigAlg = x509.SHA512WithRSA
	case SigTypeEdDSASHA512Ed25519ph:
		// Ed25519ph doesn't map to a standard x509.SignatureAlgorithm.
		// Go's x509.PureEd25519 is for pure Ed25519, not Ed25519ph (prehash).
		// We handle verification directly using crypto/ed25519.
		return s.verifyEd25519ph(cert)
	default:
		lgr.WithField("signature_type", s.SignatureType).Error("Unknown signature type for SU3 verification")
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	err := checkSignature(cert, sigAlg, s.BodyBytes(), s.Signature)
	if err != nil {
		lgr.WithError(err).WithField("signature_type", s.SignatureType).Error("SU3 signature verification failed")
		return err
	}

	return nil
}

// verifyEd25519ph verifies an Ed25519ph (prehash) signature using the certificate's
// public key. Ed25519ph is not a standard x509.SignatureAlgorithm in Go, so we
// extract the Ed25519 public key from the certificate and verify directly.
// Per I2P spec, Ed25519ph hashes the data with SHA-512 first, then verifies
// the 64-byte signature against that digest.
func (s *File) verifyEd25519ph(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("Ed25519ph verification requires ed25519.PublicKey, got %T", cert.PublicKey)
	}

	// Ed25519ph: hash the body with SHA-512, then verify against the digest
	h := crypto.SHA512.New()
	h.Write(s.BodyBytes())
	digest := h.Sum(nil)

	if err := ed25519.VerifyWithOptions(pubKey, digest, s.Signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		lgr.WithError(err).Error("Ed25519ph signature verification failed")
		return fmt.Errorf("Ed25519ph verification failure: %w", err)
	}

	return nil
}

// String returns a human-readable representation of the SU3 file metadata.
// This includes format information, signature type, file type, content type, version,
// and signer ID in a formatted display suitable for debugging and verification.
func (s *File) String() string {
	var b bytes.Buffer

	// Format SU3 file metadata in a readable table structure
	// Display key fields with proper formatting and null-byte trimming
	fmt.Fprintln(&b, "---------------------------")
	fmt.Fprintf(&b, "Format: %q\n", s.Format)
	fmt.Fprintf(&b, "SignatureType: %q\n", s.SignatureType)
	fmt.Fprintf(&b, "FileType: %q\n", s.FileType)
	fmt.Fprintf(&b, "ContentType: %q\n", s.ContentType)
	fmt.Fprintf(&b, "Version: %q\n", bytes.Trim(s.Version, "\x00"))
	fmt.Fprintf(&b, "SignerId: %q\n", s.SignerID)
	fmt.Fprintf(&b, "---------------------------")

	// Content and signature data are commented out to avoid large output
	// Uncomment these lines for debugging when full content inspection is needed
	// fmt.Fprintf(&b, "Content: %q\n", s.Content)
	// fmt.Fprintf(&b, "Signature: %q\n", s.Signature)
	// fmt.Fprintln(&b, "---------------------------")

	return b.String()
}
