package cmd

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNewShareCommand(t *testing.T) {
	cmd := NewShareCommand()
	if cmd == nil {
		t.Fatal("NewShareCommand() returned nil")
	}

	if cmd.Name != "share" {
		t.Errorf("Expected command name 'share', got %s", cmd.Name)
	}

	if cmd.Action == nil {
		t.Error("Command action should not be nil")
	}
}

func TestSharer(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file in the netdb directory
	testFile := filepath.Join(tempDir, "routerInfo-test.dat")
	err = os.WriteFile(testFile, []byte("test router info data"), 0o644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	password := "testpassword"
	sharer := Sharer(tempDir, password)

	if sharer == nil {
		t.Fatal("Sharer() returned nil")
	}

	// Test that it implements http.Handler
	var _ http.Handler = sharer
}

func TestSharer_ServeHTTP(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	password := "testpassword"
	sharer := Sharer(tempDir, password)

	// This test verifies the sharer can be created without panicking
	// Full HTTP testing would require setting up SAM/I2P which is complex
	if sharer.Password != password {
		t.Errorf("Expected password %s, got %s", password, sharer.Password)
	}

	if sharer.Path != tempDir {
		t.Errorf("Expected path %s, got %s", tempDir, sharer.Path)
	}
}

func TestWalker(t *testing.T) {
	// Create temporary directory with test files
	tempDir, err := os.MkdirTemp("", "netdb_walker_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFile1 := filepath.Join(tempDir, "routerInfo-test1.dat")
	testFile2 := filepath.Join(tempDir, "routerInfo-test2.dat")

	testContent1 := []byte("test router info 1")
	testContent2 := []byte("test router info 2")

	err = os.WriteFile(testFile1, testContent1, 0o644)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}

	err = os.WriteFile(testFile2, testContent2, 0o644)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Test walker function
	result, err := walker(tempDir)
	if err != nil {
		t.Fatalf("walker() failed: %v", err)
	}

	if result == nil {
		t.Fatal("walker() returned nil buffer")
	}

	if result.Len() == 0 {
		t.Error("walker() returned empty buffer")
	}

	// Verify the tar archive is valid and properly finalized by reading it back
	tr := tar.NewReader(bytes.NewReader(result.Bytes()))
	filesFound := make(map[string][]byte)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // Properly terminated archive
		}
		if err != nil {
			t.Fatalf("tar.Reader.Next() failed — archive may be malformed (missing tw.Close): %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("failed to read tar entry %s: %v", header.Name, err)
		}
		filesFound[header.Name] = content
	}

	if len(filesFound) != 2 {
		t.Errorf("expected 2 files in archive, got %d", len(filesFound))
	}
}

func TestWalker_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_walker_empty")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	result, err := walker(tempDir)
	if err != nil {
		t.Fatalf("walker() failed on empty dir: %v", err)
	}

	// Even an empty archive should be valid (just the end-of-archive markers)
	tr := tar.NewReader(bytes.NewReader(result.Bytes()))
	_, err = tr.Next()
	if err != io.EOF {
		t.Errorf("expected EOF for empty archive, got: %v", err)
	}
}

func TestWalker_NonexistentDirectory(t *testing.T) {
	_, err := walker("/nonexistent/path/to/nowhere")
	if err == nil {
		t.Error("walker() should return error for nonexistent directory")
	}
}

// TestShareActionResourceCleanup verifies that resources are properly cleaned up
// This is a basic test that can't fully test the I2P functionality but ensures
// the command structure is correct
func TestShareActionResourceCleanup(t *testing.T) {
	// This test verifies the function signature and basic setup
	// Full testing would require a mock SAM interface

	// Skip if running in CI or without I2P SAM available
	t.Skip("Skipping integration test - requires I2P SAM interface")

	// If we had a mock SAM interface, we would test:
	// 1. That defer statements are called in correct order
	// 2. That resources are properly released on error paths
	// 3. That the server can start and stop cleanly
}
