package cmd

import (
	"os"
	"testing"

	"i2pgit.org/go-i2p/reseed-tools/su3"
)

func TestExtractSU3Content_WritesContentNotBodyBytes(t *testing.T) {
	// Create an SU3 file with known content payload
	su3File := su3.New()
	expectedContent := []byte("this is the raw ZIP payload content")
	su3File.Content = expectedContent
	su3File.SignerID = []byte("test@example.com")
	su3File.FileType = su3.FileTypeZIP
	su3File.ContentType = su3.ContentTypeReseed

	// Change to temp directory so we don't pollute the working directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir, err := os.MkdirTemp("", "verify_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	// Extract should write only the Content field, not the full SU3 binary
	if err := extractSU3Content(su3File); err != nil {
		t.Fatalf("extractSU3Content() returned error: %v", err)
	}

	// Read back the extracted file
	extracted, err := os.ReadFile("extracted.zip")
	if err != nil {
		t.Fatalf("failed to read extracted.zip: %v", err)
	}

	// The extracted data must match the Content field exactly
	if string(extracted) != string(expectedContent) {
		t.Errorf("extracted content mismatch:\n  got:  %q\n  want: %q", extracted, expectedContent)
	}

	// Verify we did NOT get the full BodyBytes (which includes SU3 header + content)
	bodyBytes := su3File.BodyBytes()
	if string(extracted) == string(bodyBytes) {
		t.Error("extracted content matches BodyBytes() — should only contain Content, not the full SU3 binary")
	}
}

func TestExtractSU3Content_EmptyContent(t *testing.T) {
	su3File := su3.New()
	su3File.Content = []byte{}
	su3File.SignerID = []byte("test@example.com")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir, err := os.MkdirTemp("", "verify_test_empty")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	if err := extractSU3Content(su3File); err != nil {
		t.Fatalf("extractSU3Content() returned error: %v", err)
	}

	extracted, err := os.ReadFile("extracted.zip")
	if err != nil {
		t.Fatalf("failed to read extracted.zip: %v", err)
	}

	if len(extracted) != 0 {
		t.Errorf("expected empty extraction, got %d bytes", len(extracted))
	}
}

func TestExtractSU3Content_FilePermissions(t *testing.T) {
	su3File := su3.New()
	su3File.Content = []byte("test content")
	su3File.SignerID = []byte("test@example.com")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir, err := os.MkdirTemp("", "verify_test_perms")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	if err := extractSU3Content(su3File); err != nil {
		t.Fatalf("extractSU3Content() returned error: %v", err)
	}

	info, err := os.Stat("extracted.zip")
	if err != nil {
		t.Fatalf("failed to stat extracted.zip: %v", err)
	}

	// File should be created with 0644 permissions (not 0755)
	perm := info.Mode().Perm()
	if perm&0o111 != 0 {
		t.Errorf("extracted.zip should not be executable, got permissions %o", perm)
	}
}
