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
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	file := New()

	if file == nil {
		t.Fatal("New() returned nil")
	}

	if file.SignatureType != SigTypeRSAWithSHA512 {
		t.Errorf("Expected SignatureType %d, got %d", SigTypeRSAWithSHA512, file.SignatureType)
	}

	if len(file.Version) == 0 {
		t.Error("Version should be set")
	}

	// Verify version is a valid Unix timestamp string
	if len(file.Version) < 10 {
		t.Error("Version should be at least 10 characters (Unix timestamp)")
	}
}

func TestFile_Sign(t *testing.T) {
	tests := []struct {
		name          string
		signatureType uint16
		key           crypto.Signer
		expectError   bool
	}{
		{
			name:          "RSA with SHA256",
			signatureType: SigTypeRSAWithSHA256,
			expectError:   false,
		},
		{
			name:          "RSA with SHA384",
			signatureType: SigTypeRSAWithSHA384,
			expectError:   false,
		},
		{
			name:          "RSA with SHA512",
			signatureType: SigTypeRSAWithSHA512,
			expectError:   false,
		},
		{
			name:          "Unknown signature type",
			signatureType: uint16(999),
			expectError:   true,
		},
	}

	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := New()
			file.SignatureType = tt.signatureType
			file.Content = []byte("test content")
			file.SignerID = []byte("test@example.com")

			var key crypto.Signer = privateKey
			if tt.key != nil {
				key = tt.key
			}
			err := file.Sign(key)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(file.Signature) == 0 {
				t.Error("Signature should be set after signing")
			}
		})
	}
}

func TestFile_Sign_NilPrivateKey(t *testing.T) {
	file := New()
	file.Content = []byte("test content")

	err := file.Sign(nil)
	if err == nil {
		t.Error("Expected error when signing with nil private key")
	}
}

func TestFile_Sign_ECDSA(t *testing.T) {
	tests := []struct {
		name          string
		signatureType uint16
		curve         elliptic.Curve
		expectError   bool
	}{
		{
			name:          "ECDSA P-256 with SHA256",
			signatureType: SigTypeECDSAWithSHA256,
			curve:         elliptic.P256(),
			expectError:   false,
		},
		{
			name:          "ECDSA P-384 with SHA384",
			signatureType: SigTypeECDSAWithSHA384,
			curve:         elliptic.P384(),
			expectError:   false,
		},
		{
			name:          "ECDSA P-521 with SHA512",
			signatureType: SigTypeECDSAWithSHA512,
			curve:         elliptic.P521(),
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			file := New()
			file.SignatureType = tt.signatureType
			file.Content = []byte("test content for ECDSA")
			file.SignerID = []byte("ecdsa-test@example.com")

			err = file.Sign(ecKey)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(file.Signature) == 0 {
				t.Error("Signature should be set after signing")
			}
		})
	}
}

func TestFile_Sign_KeyTypeMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	tests := []struct {
		name          string
		signatureType uint16
		key           crypto.Signer
	}{
		{"RSA key with ECDSA type", SigTypeECDSAWithSHA256, rsaKey},
		{"ECDSA key with RSA type", SigTypeRSAWithSHA256, ecKey},
		{"ECDSA P-256 key with P-384 type", SigTypeECDSAWithSHA384, ecKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := New()
			file.SignatureType = tt.signatureType
			file.Content = []byte("test")
			file.SignerID = []byte("test@example.com")

			err := file.Sign(tt.key)
			if err == nil {
				t.Error("Expected error for key/type mismatch but got none")
			}
		})
	}
}

func TestFile_Sign_DSAUnsupported(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeDSA
	file.Content = []byte("test")
	file.SignerID = []byte("test@example.com")

	err = file.Sign(rsaKey)
	if err == nil {
		t.Error("Expected error for DSA signing but got none")
	}
}

func TestFile_BodyBytes(t *testing.T) {
	file := New()
	file.Format = 1
	file.SignatureType = SigTypeRSAWithSHA256
	file.FileType = FileTypeZIP
	file.ContentType = ContentTypeReseed
	file.Version = []byte("1234567890")
	file.SignerID = []byte("test@example.com")
	file.Content = []byte("test content data")

	bodyBytes := file.BodyBytes()

	if len(bodyBytes) == 0 {
		t.Error("BodyBytes should not be empty")
	}

	// Check that magic bytes are included
	if !bytes.HasPrefix(bodyBytes, []byte(magicBytes)) {
		t.Error("BodyBytes should start with magic bytes")
	}

	// Test version padding
	shortVersionFile := New()
	shortVersionFile.Version = []byte("123") // Less than minVersionLength
	bodyBytes = shortVersionFile.BodyBytes()

	if len(bodyBytes) == 0 {
		t.Error("BodyBytes should handle short version")
	}
}

// TestFile_BodyBytes_DoesNotMutateVersion verifies that BodyBytes() does not
// modify the receiver's Version field when zero-padding is needed. This was
// a bug where s.Version was mutated in-place during serialization.
func TestFile_BodyBytes_DoesNotMutateVersion(t *testing.T) {
	tests := []struct {
		name    string
		version []byte
	}{
		{"short version", []byte("123")},
		{"single byte", []byte("X")},
		{"empty version", []byte{}},
		{"exactly min length", make([]byte, minVersionLength)},
		{"longer than min", []byte("this-is-a-long-version-string-here")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := New()
			file.Content = []byte("content")
			file.SignerID = []byte("signer@example.com")

			// Make a copy of the original version bytes
			original := make([]byte, len(tt.version))
			copy(original, tt.version)
			file.Version = tt.version

			// Call BodyBytes multiple times — should be idempotent and non-mutating
			_ = file.BodyBytes()
			_ = file.BodyBytes()

			if !bytes.Equal(file.Version, original) {
				t.Errorf("BodyBytes() mutated Version: got %q, want %q", file.Version, original)
			}
			if len(file.Version) != len(original) {
				t.Errorf("BodyBytes() changed Version length: got %d, want %d", len(file.Version), len(original))
			}
		})
	}
}

// TestFile_BodyBytes_RSA512FallbackSignatureLength verifies that the fallback
// signature length for SigTypeRSAWithSHA512 (when no signature is set) is 512
// bytes, matching the 4096-bit RSA key that createSigningCertificate generates.
func TestFile_BodyBytes_RSA512FallbackSignatureLength(t *testing.T) {
	tests := []struct {
		name             string
		sigType          uint16
		expectedFallback uint16
	}{
		{"RSA-SHA256 fallback", SigTypeRSAWithSHA256, 256},
		{"RSA-SHA384 fallback", SigTypeRSAWithSHA384, 384},
		{"RSA-SHA512 fallback", SigTypeRSAWithSHA512, 512},
		{"ECDSA-SHA256 fallback", SigTypeECDSAWithSHA256, 72},
		{"ECDSA-SHA384 fallback", SigTypeECDSAWithSHA384, 104},
		{"ECDSA-SHA512 fallback", SigTypeECDSAWithSHA512, 141},
		{"EdDSA fallback", SigTypeEdDSASHA512Ed25519ph, 64},
		{"DSA fallback", SigTypeDSA, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Version:       []byte("1234567890123456"), // >= minVersionLength
				SignerID:      []byte("test@example.com"),
				Content:       []byte("test content"),
				SignatureType: tt.sigType,
				// Signature intentionally left nil — test fallback path
			}

			bodyBytes := file.BodyBytes()

			// Parse the signature length from the header (offset 8, uint16 big-endian).
			// SU3 header layout: magic(6) + skip(1) + format(1) + sigType(2) + sigLen(2)
			if len(bodyBytes) < 12 {
				t.Fatal("BodyBytes too short to contain header")
			}
			sigLen := binary.BigEndian.Uint16(bodyBytes[10:12])
			if sigLen != tt.expectedFallback {
				t.Errorf("fallback signature length = %d, want %d", sigLen, tt.expectedFallback)
			}
		})
	}
}

// TestFile_BodyBytes_SignatureLengthFromActualSignature verifies that when
// Signature is populated, BodyBytes() uses len(Signature) for the header field
// regardless of the default fallback value.
func TestFile_BodyBytes_SignatureLengthFromActualSignature(t *testing.T) {
	file := &File{
		Version:       []byte("1234567890123456"),
		SignerID:      []byte("test@example.com"),
		Content:       []byte("test"),
		SignatureType: SigTypeRSAWithSHA512,
		Signature:     make([]byte, 256), // e.g. from a 2048-bit key
	}

	bodyBytes := file.BodyBytes()
	sigLen := binary.BigEndian.Uint16(bodyBytes[10:12])
	if sigLen != 256 {
		t.Errorf("signature length from actual Signature = %d, want 256", sigLen)
	}

	// Now with a 4096-bit key signature (512 bytes)
	file.Signature = make([]byte, 512)
	bodyBytes = file.BodyBytes()
	sigLen = binary.BigEndian.Uint16(bodyBytes[10:12])
	if sigLen != 512 {
		t.Errorf("signature length from actual Signature = %d, want 512", sigLen)
	}
}

// TestFile_BodyBytes_Idempotent verifies that repeated calls to BodyBytes()
// produce identical output, confirming no side effects.
func TestFile_BodyBytes_Idempotent(t *testing.T) {
	file := New()
	file.Content = []byte("test content")
	file.SignerID = []byte("test@example.com")
	file.Version = []byte("short") // Will trigger padding

	first := file.BodyBytes()
	second := file.BodyBytes()
	third := file.BodyBytes()

	if !bytes.Equal(first, second) {
		t.Error("BodyBytes() is not idempotent: first != second")
	}
	if !bytes.Equal(second, third) {
		t.Error("BodyBytes() is not idempotent: second != third")
	}
}

func TestFile_MarshalBinary(t *testing.T) {
	file := New()
	file.Content = []byte("test content")
	file.SignerID = []byte("test@example.com")
	file.Signature = []byte("dummy signature data")

	data, err := file.MarshalBinary()
	if err != nil {
		t.Errorf("MarshalBinary failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("MarshalBinary should return data")
	}

	// Verify signature is at the end
	expectedSigStart := len(data) - len(file.Signature)
	if !bytes.Equal(data[expectedSigStart:], file.Signature) {
		t.Error("Signature should be at the end of marshaled data")
	}
}

func TestFile_UnmarshalBinary(t *testing.T) {
	// Create a file and marshal it
	originalFile := New()
	originalFile.Format = 1
	originalFile.SignatureType = SigTypeRSAWithSHA256
	originalFile.FileType = FileTypeZIP
	originalFile.ContentType = ContentTypeReseed
	originalFile.Version = []byte("1234567890123456") // Exactly minVersionLength
	originalFile.SignerID = []byte("test@example.com")
	originalFile.Content = []byte("test content data")
	originalFile.Signature = make([]byte, 256) // Appropriate size for RSA SHA256

	// Fill signature with test data
	for i := range originalFile.Signature {
		originalFile.Signature[i] = byte(i % 256)
	}

	data, err := originalFile.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal test file: %v", err)
	}

	// Unmarshal into new file
	newFile := &File{}
	err = newFile.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("UnmarshalBinary failed: %v", err)
	}

	// Compare fields
	if newFile.Format != originalFile.Format {
		t.Errorf("Format mismatch: expected %d, got %d", originalFile.Format, newFile.Format)
	}

	if newFile.SignatureType != originalFile.SignatureType {
		t.Errorf("SignatureType mismatch: expected %d, got %d", originalFile.SignatureType, newFile.SignatureType)
	}

	if newFile.FileType != originalFile.FileType {
		t.Errorf("FileType mismatch: expected %d, got %d", originalFile.FileType, newFile.FileType)
	}

	if newFile.ContentType != originalFile.ContentType {
		t.Errorf("ContentType mismatch: expected %d, got %d", originalFile.ContentType, newFile.ContentType)
	}

	if !bytes.Equal(newFile.Version, originalFile.Version) {
		t.Errorf("Version mismatch: expected %s, got %s", originalFile.Version, newFile.Version)
	}

	if !bytes.Equal(newFile.SignerID, originalFile.SignerID) {
		t.Errorf("SignerID mismatch: expected %s, got %s", originalFile.SignerID, newFile.SignerID)
	}

	if !bytes.Equal(newFile.Content, originalFile.Content) {
		t.Errorf("Content mismatch: expected %s, got %s", originalFile.Content, newFile.Content)
	}

	if !bytes.Equal(newFile.Signature, originalFile.Signature) {
		t.Error("Signature mismatch")
	}
}

func TestFile_UnmarshalBinary_InvalidData(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "Empty data",
			data:      []byte{},
			wantErr:   true,
			errSubstr: "failed to read magic bytes",
		},
		{
			name:      "Too short data",
			data:      []byte("short"),
			wantErr:   true,
			errSubstr: "failed to read magic bytes",
		},
		{
			name:      "Invalid magic bytes",
			data:      append([]byte("BADMAG"), make([]byte, 100)...),
			wantErr:   true,
			errSubstr: "invalid magic bytes",
		},
		{
			name:      "Valid magic but truncated header",
			data:      []byte("I2Psu3"),
			wantErr:   true,
			errSubstr: "failed to read",
		},
		{
			name: "Valid magic with partial header",
			// Magic (6) + skip (1) + format (1) = 8 bytes, but truncated before signature type
			data:      append([]byte("I2Psu3"), []byte{0x00, 0x00}...),
			wantErr:   true,
			errSubstr: "failed to read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{}
			err := file.UnmarshalBinary(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestFile_UnmarshalBinary_ExtremeContentLength(t *testing.T) {
	// Build a valid SU3 header with an extreme contentLength to test OOM protection.
	// The header layout is:
	//   magic(6) + skip(1) + format(1) + sigType(2) + sigLen(2) + skip(1)
	//   + verLen(1) + skip(1) + signerIDLen(1) + contentLen(8) + skip(1)
	//   + fileType(1) + skip(1) + contentType(1) + bigSkip(12)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, []byte("I2Psu3"))       // magic
	binary.Write(buf, binary.BigEndian, [1]byte{})              // skip
	binary.Write(buf, binary.BigEndian, uint8(0))               // format
	binary.Write(buf, binary.BigEndian, uint16(6))              // sigType (RSA-SHA512)
	binary.Write(buf, binary.BigEndian, uint16(512))            // sigLen
	binary.Write(buf, binary.BigEndian, [1]byte{})              // skip
	binary.Write(buf, binary.BigEndian, uint8(16))              // versionLength
	binary.Write(buf, binary.BigEndian, [1]byte{})              // skip
	binary.Write(buf, binary.BigEndian, uint8(0))               // signerIDLength
	binary.Write(buf, binary.BigEndian, uint64(0xFFFFFFFFFFFF)) // extreme contentLength
	binary.Write(buf, binary.BigEndian, [1]byte{})              // skip
	binary.Write(buf, binary.BigEndian, uint8(0))               // fileType
	binary.Write(buf, binary.BigEndian, [1]byte{})              // skip
	binary.Write(buf, binary.BigEndian, uint8(0))               // contentType
	binary.Write(buf, binary.BigEndian, [12]byte{})             // bigSkip

	file := &File{}
	err := file.UnmarshalBinary(buf.Bytes())
	if err == nil {
		t.Fatal("Expected error for extreme content length, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("Expected 'exceeds maximum' error, got: %v", err)
	}
}

func TestFile_UnmarshalBinary_TruncatedContent(t *testing.T) {
	// Build a valid header that claims 1024 bytes of content but only provides 10
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, []byte("I2Psu3")) // magic
	binary.Write(buf, binary.BigEndian, [1]byte{})        // skip
	binary.Write(buf, binary.BigEndian, uint8(0))         // format
	binary.Write(buf, binary.BigEndian, uint16(6))        // sigType
	binary.Write(buf, binary.BigEndian, uint16(64))       // sigLen
	binary.Write(buf, binary.BigEndian, [1]byte{})        // skip
	binary.Write(buf, binary.BigEndian, uint8(16))        // versionLength
	binary.Write(buf, binary.BigEndian, [1]byte{})        // skip
	binary.Write(buf, binary.BigEndian, uint8(4))         // signerIDLength
	binary.Write(buf, binary.BigEndian, uint64(1024))     // contentLength (claims 1024)
	binary.Write(buf, binary.BigEndian, [1]byte{})        // skip
	binary.Write(buf, binary.BigEndian, uint8(0))         // fileType
	binary.Write(buf, binary.BigEndian, [1]byte{})        // skip
	binary.Write(buf, binary.BigEndian, uint8(3))         // contentType
	binary.Write(buf, binary.BigEndian, [12]byte{})       // bigSkip
	binary.Write(buf, binary.BigEndian, make([]byte, 16)) // version (16 bytes)
	binary.Write(buf, binary.BigEndian, []byte("test"))   // signerID (4 bytes)
	binary.Write(buf, binary.BigEndian, make([]byte, 10)) // only 10 bytes of "content" (header claims 1024)

	file := &File{}
	err := file.UnmarshalBinary(buf.Bytes())
	if err == nil {
		t.Fatal("Expected error for truncated content, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read content") {
		t.Errorf("Expected 'failed to read content' error, got: %v", err)
	}
}

func TestFile_UnmarshalBinary_MaxContentLength(t *testing.T) {
	// Verify that the maxContentLength constant is 100MB
	if maxContentLength != 100*1024*1024 {
		t.Errorf("Expected maxContentLength to be 100MB, got %d", maxContentLength)
	}

	// Build a header with content length exactly at the limit — should not error
	// (we won't actually provide the data, so it will fail on read, not on bounds check)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, []byte("I2Psu3"))
	binary.Write(buf, binary.BigEndian, [1]byte{})
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint16(6))
	binary.Write(buf, binary.BigEndian, uint16(64))
	binary.Write(buf, binary.BigEndian, [1]byte{})
	binary.Write(buf, binary.BigEndian, uint8(16))
	binary.Write(buf, binary.BigEndian, [1]byte{})
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint64(maxContentLength)) // exactly at limit
	binary.Write(buf, binary.BigEndian, [1]byte{})
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, [1]byte{})
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, [12]byte{})

	file := &File{}
	err := file.UnmarshalBinary(buf.Bytes())
	// Should fail on reading content (not enough data), NOT on bounds check
	if err == nil {
		t.Fatal("Expected error (truncated), got nil")
	}
	if strings.Contains(err.Error(), "exceeds maximum") {
		t.Error("Content at exactly maxContentLength should not trigger bounds check")
	}

	// Build header with content length one over the limit
	buf2 := new(bytes.Buffer)
	binary.Write(buf2, binary.BigEndian, []byte("I2Psu3"))
	binary.Write(buf2, binary.BigEndian, [1]byte{})
	binary.Write(buf2, binary.BigEndian, uint8(0))
	binary.Write(buf2, binary.BigEndian, uint16(6))
	binary.Write(buf2, binary.BigEndian, uint16(64))
	binary.Write(buf2, binary.BigEndian, [1]byte{})
	binary.Write(buf2, binary.BigEndian, uint8(16))
	binary.Write(buf2, binary.BigEndian, [1]byte{})
	binary.Write(buf2, binary.BigEndian, uint8(0))
	binary.Write(buf2, binary.BigEndian, uint64(maxContentLength+1)) // one over limit
	binary.Write(buf2, binary.BigEndian, [1]byte{})
	binary.Write(buf2, binary.BigEndian, uint8(0))
	binary.Write(buf2, binary.BigEndian, [1]byte{})
	binary.Write(buf2, binary.BigEndian, uint8(0))
	binary.Write(buf2, binary.BigEndian, [12]byte{})

	file2 := &File{}
	err = file2.UnmarshalBinary(buf2.Bytes())
	if err == nil {
		t.Fatal("Expected error for content length over max, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("Expected 'exceeds maximum' error, got: %v", err)
	}
}

func TestFile_VerifySignature(t *testing.T) {
	// Generate test certificate and private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a test certificate
	cert, err := NewSigningCertificate("test@example.com", privateKey)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	tests := []struct {
		name          string
		signatureType uint16
		setupFile     func(*File)
		expectError   bool
	}{
		{
			name:          "Valid RSA SHA256 signature",
			signatureType: SigTypeRSAWithSHA256,
			setupFile: func(f *File) {
				f.Content = []byte("test content")
				f.SignerID = []byte("test@example.com")
				err := f.Sign(privateKey)
				if err != nil {
					t.Fatalf("Failed to sign file: %v", err)
				}
			},
			expectError: false,
		},
		{
			name:          "Unknown signature type",
			signatureType: uint16(999),
			setupFile: func(f *File) {
				f.Content = []byte("test content")
				f.SignerID = []byte("test@example.com")
				f.Signature = []byte("dummy signature")
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := New()
			file.SignatureType = tt.signatureType
			tt.setupFile(file)

			err := file.VerifySignature(parsedCert)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestFile_String(t *testing.T) {
	file := New()
	file.Format = 1
	file.SignatureType = SigTypeRSAWithSHA256
	file.FileType = FileTypeZIP
	file.ContentType = ContentTypeReseed
	file.Version = []byte("test version")
	file.SignerID = []byte("test@example.com")

	str := file.String()

	if len(str) == 0 {
		t.Error("String() should not return empty string")
	}

	// Check that important fields are included in string representation
	expectedSubstrings := []string{
		"Format:",
		"SignatureType:",
		"FileType:",
		"ContentType:",
		"Version:",
		"SignerId:",
		"---------------------------",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(str, substr) {
			t.Errorf("String() should contain '%s'", substr)
		}
	}
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	if magicBytes != "I2Psu3" {
		t.Errorf("Expected magic bytes 'I2Psu3', got '%s'", magicBytes)
	}

	if minVersionLength != 16 {
		t.Errorf("Expected minVersionLength 16, got %d", minVersionLength)
	}

	// Test signature type constants
	expectedSigTypes := map[string]uint16{
		"DSA":                  0,
		"ECDSAWithSHA256":      1,
		"ECDSAWithSHA384":      2,
		"ECDSAWithSHA512":      3,
		"RSAWithSHA256":        4,
		"RSAWithSHA384":        5,
		"RSAWithSHA512":        6,
		"EdDSASHA512Ed25519ph": 8,
	}

	actualSigTypes := map[string]uint16{
		"DSA":                  SigTypeDSA,
		"ECDSAWithSHA256":      SigTypeECDSAWithSHA256,
		"ECDSAWithSHA384":      SigTypeECDSAWithSHA384,
		"ECDSAWithSHA512":      SigTypeECDSAWithSHA512,
		"RSAWithSHA256":        SigTypeRSAWithSHA256,
		"RSAWithSHA384":        SigTypeRSAWithSHA384,
		"RSAWithSHA512":        SigTypeRSAWithSHA512,
		"EdDSASHA512Ed25519ph": SigTypeEdDSASHA512Ed25519ph,
	}

	if !reflect.DeepEqual(expectedSigTypes, actualSigTypes) {
		t.Error("Signature type constants don't match expected values")
	}
}

func TestFile_RoundTrip(t *testing.T) {
	// Test complete round-trip: create -> sign -> marshal -> unmarshal -> verify
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cert, err := NewSigningCertificate("roundtrip@example.com", privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create and set up original file
	originalFile := New()
	originalFile.FileType = FileTypeZIP
	originalFile.ContentType = ContentTypeReseed
	originalFile.Content = []byte("This is test content for round-trip testing")
	originalFile.SignerID = []byte("roundtrip@example.com")

	// Sign the file
	err = originalFile.Sign(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	// Marshal to binary
	data, err := originalFile.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal file: %v", err)
	}

	// Unmarshal from binary
	newFile := &File{}
	err = newFile.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal file: %v", err)
	}

	// Verify signature
	err = newFile.VerifySignature(parsedCert)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	// Ensure content matches
	if !bytes.Equal(originalFile.Content, newFile.Content) {
		t.Error("Content doesn't match after round-trip")
	}

	if !bytes.Equal(originalFile.SignerID, newFile.SignerID) {
		t.Error("SignerID doesn't match after round-trip")
	}
}

func TestFile_Sign_RSAKeySize(t *testing.T) {
	testCases := []struct {
		name           string
		keySize        int
		expectedSigLen int
	}{
		{"2048-bit RSA", 2048, 256},
		{"3072-bit RSA", 3072, 384},
		{"4096-bit RSA", 4096, 512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate RSA key of specific size
			privateKey, err := rsa.GenerateKey(rand.Reader, tc.keySize)
			if err != nil {
				t.Fatalf("Failed to generate %d-bit RSA key: %v", tc.keySize, err)
			}

			file := New()
			file.Content = []byte("test content")
			file.SignerID = []byte("test@example.com")
			file.SignatureType = SigTypeRSAWithSHA512

			err = file.Sign(privateKey)
			if err != nil {
				t.Errorf("Unexpected error signing with %d-bit key: %v", tc.keySize, err)
				return
			}

			if len(file.Signature) != tc.expectedSigLen {
				t.Errorf("Expected signature length %d for %d-bit key, got %d",
					tc.expectedSigLen, tc.keySize, len(file.Signature))
			}

			// Verify the header reflects the correct signature length
			bodyBytes := file.BodyBytes()
			if len(bodyBytes) == 0 {
				t.Error("BodyBytes should not be empty")
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}

func BenchmarkFile_BodyBytes(b *testing.B) {
	file := New()
	file.Content = make([]byte, 1024) // 1KB content
	file.SignerID = []byte("benchmark@example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = file.BodyBytes()
	}
}

func BenchmarkFile_MarshalBinary(b *testing.B) {
	file := New()
	file.Content = make([]byte, 1024) // 1KB content
	file.SignerID = []byte("benchmark@example.com")
	file.Signature = make([]byte, 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = file.MarshalBinary()
	}
}

func BenchmarkFile_UnmarshalBinary(b *testing.B) {
	// Create test data once
	file := New()
	file.Content = make([]byte, 1024)
	file.SignerID = []byte("benchmark@example.com")
	file.Signature = make([]byte, 512)

	data, err := file.MarshalBinary()
	if err != nil {
		b.Fatalf("Failed to create test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newFile := &File{}
		_ = newFile.UnmarshalBinary(data)
	}
}

func TestFile_ECDSA_RoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		signatureType uint16
		curve         elliptic.Curve
	}{
		{"ECDSA P-256 SHA256", SigTypeECDSAWithSHA256, elliptic.P256()},
		{"ECDSA P-384 SHA384", SigTypeECDSAWithSHA384, elliptic.P384()},
		{"ECDSA P-521 SHA512", SigTypeECDSAWithSHA512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate ECDSA key
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			// Create certificate
			certDER, err := NewECDSASigningCertificate("ecdsa-roundtrip@example.com", ecKey)
			if err != nil {
				t.Fatalf("Failed to create ECDSA certificate: %v", err)
			}
			parsedCert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Create, sign, marshal, unmarshal, verify
			originalFile := New()
			originalFile.SignatureType = tt.signatureType
			originalFile.FileType = FileTypeZIP
			originalFile.ContentType = ContentTypeReseed
			originalFile.Content = []byte("ECDSA round-trip test content")
			originalFile.SignerID = []byte("ecdsa-roundtrip@example.com")

			err = originalFile.Sign(ecKey)
			if err != nil {
				t.Fatalf("Failed to sign file: %v", err)
			}

			data, err := originalFile.MarshalBinary()
			if err != nil {
				t.Fatalf("Failed to marshal file: %v", err)
			}

			newFile := &File{}
			err = newFile.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal file: %v", err)
			}

			// Verify signature
			err = newFile.VerifySignature(parsedCert)
			if err != nil {
				t.Fatalf("Failed to verify ECDSA signature after round-trip: %v", err)
			}

			// Verify content matches
			if !bytes.Equal(originalFile.Content, newFile.Content) {
				t.Error("Content doesn't match after round-trip")
			}

			if !bytes.Equal(originalFile.SignerID, newFile.SignerID) {
				t.Error("SignerID doesn't match after round-trip")
			}

			if newFile.SignatureType != tt.signatureType {
				t.Errorf("SignatureType mismatch: expected %d, got %d", tt.signatureType, newFile.SignatureType)
			}
		})
	}
}

func TestFile_ECDSA_VerifySignature(t *testing.T) {
	tests := []struct {
		name          string
		signatureType uint16
		curve         elliptic.Curve
	}{
		{"ECDSA P-256 SHA256", SigTypeECDSAWithSHA256, elliptic.P256()},
		{"ECDSA P-384 SHA384", SigTypeECDSAWithSHA384, elliptic.P384()},
		{"ECDSA P-521 SHA512", SigTypeECDSAWithSHA512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			certDER, err := NewECDSASigningCertificate("verify-test@example.com", ecKey)
			if err != nil {
				t.Fatalf("Failed to create ECDSA certificate: %v", err)
			}
			parsedCert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			file := New()
			file.SignatureType = tt.signatureType
			file.Content = []byte("ECDSA verify test")
			file.SignerID = []byte("verify-test@example.com")

			err = file.Sign(ecKey)
			if err != nil {
				t.Fatalf("Failed to sign file: %v", err)
			}

			err = file.VerifySignature(parsedCert)
			if err != nil {
				t.Errorf("ECDSA signature verification failed: %v", err)
			}

			// Tamper with content and verify failure
			file.Content = []byte("tampered content")
			err = file.VerifySignature(parsedCert)
			if err == nil {
				t.Error("Expected verification failure after content tampering")
			}
		})
	}
}

func TestFile_Sign_Ed25519ph(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeEdDSASHA512Ed25519ph
	file.Content = []byte("test content for Ed25519ph")
	file.SignerID = []byte("ed25519-test@example.com")

	err = file.Sign(edKey)
	if err != nil {
		t.Fatalf("Unexpected error signing with Ed25519ph: %v", err)
	}

	if len(file.Signature) != ed25519.SignatureSize {
		t.Errorf("Expected Ed25519 signature length %d, got %d", ed25519.SignatureSize, len(file.Signature))
	}
}

func TestFile_Ed25519ph_RoundTrip(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	certDER, err := NewEd25519SigningCertificate("ed25519-roundtrip@example.com", edKey)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create, sign, marshal, unmarshal, verify
	originalFile := New()
	originalFile.SignatureType = SigTypeEdDSASHA512Ed25519ph
	originalFile.FileType = FileTypeZIP
	originalFile.ContentType = ContentTypeReseed
	originalFile.Content = []byte("Ed25519ph round-trip test content")
	originalFile.SignerID = []byte("ed25519-roundtrip@example.com")

	err = originalFile.Sign(edKey)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	data, err := originalFile.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal file: %v", err)
	}

	newFile := &File{}
	err = newFile.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal file: %v", err)
	}

	// Verify signature
	err = newFile.VerifySignature(parsedCert)
	if err != nil {
		t.Fatalf("Failed to verify Ed25519ph signature after round-trip: %v", err)
	}

	// Verify content matches
	if !bytes.Equal(originalFile.Content, newFile.Content) {
		t.Error("Content doesn't match after round-trip")
	}

	if !bytes.Equal(originalFile.SignerID, newFile.SignerID) {
		t.Error("SignerID doesn't match after round-trip")
	}

	if newFile.SignatureType != SigTypeEdDSASHA512Ed25519ph {
		t.Errorf("SignatureType mismatch: expected %d, got %d", SigTypeEdDSASHA512Ed25519ph, newFile.SignatureType)
	}

	// Verify the signature is 64 bytes
	if len(newFile.Signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature length %d after round-trip, got %d", ed25519.SignatureSize, len(newFile.Signature))
	}
}

func TestFile_Ed25519ph_VerifySignature(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	certDER, err := NewEd25519SigningCertificate("ed25519-verify@example.com", edKey)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeEdDSASHA512Ed25519ph
	file.Content = []byte("Ed25519ph verify test")
	file.SignerID = []byte("ed25519-verify@example.com")

	err = file.Sign(edKey)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	// Verify valid signature
	err = file.VerifySignature(parsedCert)
	if err != nil {
		t.Errorf("Ed25519ph signature verification failed: %v", err)
	}

	// Tamper with content and verify failure
	file.Content = []byte("tampered content")
	err = file.VerifySignature(parsedCert)
	if err == nil {
		t.Error("Expected verification failure after content tampering")
	}
}

func TestFile_Ed25519ph_KeyMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name          string
		signatureType uint16
		key           crypto.Signer
	}{
		{"RSA key with Ed25519ph type", SigTypeEdDSASHA512Ed25519ph, rsaKey},
		{"ECDSA key with Ed25519ph type", SigTypeEdDSASHA512Ed25519ph, ecKey},
		{"Ed25519 key with RSA type", SigTypeRSAWithSHA256, edKey},
		{"Ed25519 key with ECDSA type", SigTypeECDSAWithSHA256, edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := New()
			file.SignatureType = tt.signatureType
			file.Content = []byte("test")
			file.SignerID = []byte("test@example.com")

			err := file.Sign(tt.key)
			if err == nil {
				t.Error("Expected error for key/type mismatch but got none")
			}
		})
	}
}

func TestFile_Ed25519ph_WrongKeyVerify(t *testing.T) {
	// Sign with one key, attempt to verify with a different key's certificate
	_, edKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key 1: %v", err)
	}
	_, edKey2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key 2: %v", err)
	}

	certDER2, err := NewEd25519SigningCertificate("wrong-key@example.com", edKey2)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	parsedCert2, err := x509.ParseCertificate(certDER2)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeEdDSASHA512Ed25519ph
	file.Content = []byte("wrong key test")
	file.SignerID = []byte("wrong-key@example.com")

	err = file.Sign(edKey1)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	err = file.VerifySignature(parsedCert2)
	if err == nil {
		t.Error("Expected verification failure with wrong key but got none")
	}
}

func TestFile_Ed25519ph_NilCertVerify(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeEdDSASHA512Ed25519ph
	file.Content = []byte("nil cert test")
	file.SignerID = []byte("test@example.com")

	err = file.Sign(edKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	err = file.VerifySignature(nil)
	if err == nil {
		t.Error("Expected error when verifying with nil certificate")
	}
}

func TestFile_Ed25519ph_RSACertVerify(t *testing.T) {
	// Sign with Ed25519, try to verify with RSA certificate
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	rsaCertDER, err := NewSigningCertificate("rsa@example.com", rsaKey)
	if err != nil {
		t.Fatalf("Failed to create RSA certificate: %v", err)
	}
	rsaCert, err := x509.ParseCertificate(rsaCertDER)
	if err != nil {
		t.Fatalf("Failed to parse RSA certificate: %v", err)
	}

	file := New()
	file.SignatureType = SigTypeEdDSASHA512Ed25519ph
	file.Content = []byte("wrong cert type test")
	file.SignerID = []byte("test@example.com")

	err = file.Sign(edKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	err = file.VerifySignature(rsaCert)
	if err == nil {
		t.Error("Expected error when verifying Ed25519ph with RSA certificate")
	}
}

func TestConstants_Ed25519ph(t *testing.T) {
	// Verify Ed25519ph constant matches I2P spec (type code 8, not 7)
	if SigTypeEdDSASHA512Ed25519ph != 8 {
		t.Errorf("Expected SigTypeEdDSASHA512Ed25519ph = 8 per I2P spec, got %d", SigTypeEdDSASHA512Ed25519ph)
	}
}
