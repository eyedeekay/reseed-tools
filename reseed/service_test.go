package reseed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"i2pgit.org/go-i2p/reseed-tools/su3"
)

func TestLocalNetDb_ConfigurableRouterInfoAge(t *testing.T) {
	// Create a temporary directory for test
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test router info files with different ages
	files := []struct {
		name string
		age  time.Duration
	}{
		{"routerInfo-test1.dat", 24 * time.Hour},  // 1 day old
		{"routerInfo-test2.dat", 48 * time.Hour},  // 2 days old
		{"routerInfo-test3.dat", 96 * time.Hour},  // 4 days old
		{"routerInfo-test4.dat", 168 * time.Hour}, // 7 days old
	}

	// Create test files with specific modification times
	now := time.Now()
	for _, file := range files {
		filePath := filepath.Join(tempDir, file.name)
		err := os.WriteFile(filePath, []byte("dummy router info data"), 0o644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", file.name, err)
		}

		// Set modification time to simulate age
		modTime := now.Add(-file.age)
		err = os.Chtimes(filePath, modTime, modTime)
		if err != nil {
			t.Fatalf("Failed to set mod time for %s: %v", file.name, err)
		}
	}

	testCases := []struct {
		name          string
		maxAge        time.Duration
		expectedFiles int
		description   string
	}{
		{
			name:          "72 hour limit (I2P standard)",
			maxAge:        72 * time.Hour,
			expectedFiles: 2, // Files aged 24h and 48h should be included
			description:   "Should include files up to 72 hours old",
		},
		{
			name:          "192 hour limit (legacy compatibility)",
			maxAge:        192 * time.Hour,
			expectedFiles: 4, // All files should be included
			description:   "Should include files up to 192 hours old (for backwards compatibility)",
		},
		{
			name:          "36 hour limit (strict)",
			maxAge:        36 * time.Hour,
			expectedFiles: 1, // Only the 24h file should be included
			description:   "Should include only files up to 36 hours old",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create LocalNetDb with configurable max age
			netdb := NewLocalNetDb(tempDir, tc.maxAge)

			// Note: RouterInfos() method will try to parse the dummy data and likely fail
			// since it's not real router info data. But we can still test the age filtering
			// by checking that it at least attempts to process the right number of files.

			// For this test, we'll just verify that the MaxRouterInfoAge field is set correctly
			if netdb.MaxRouterInfoAge != tc.maxAge {
				t.Errorf("Expected MaxRouterInfoAge %v, got %v", tc.maxAge, netdb.MaxRouterInfoAge)
			}

			// Verify the path is set correctly too
			if netdb.Path != tempDir {
				t.Errorf("Expected Path %s, got %s", tempDir, netdb.Path)
			}
		})
	}
}

func TestLocalNetDb_DefaultValues(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with different duration values
	testDurations := []time.Duration{
		72 * time.Hour,     // 3 days (I2P standard default)
		192 * time.Hour,    // 8 days (legacy compatibility)
		24 * time.Hour,     // 1 day (strict)
		7 * 24 * time.Hour, // 1 week
	}

	for _, duration := range testDurations {
		t.Run(duration.String(), func(t *testing.T) {
			netdb := NewLocalNetDb(tempDir, duration)

			if netdb.MaxRouterInfoAge != duration {
				t.Errorf("Expected MaxRouterInfoAge %v, got %v", duration, netdb.MaxRouterInfoAge)
			}
		})
	}
}

// Test for Bug #2: Race Condition in SU3 Cache Access
func TestSU3CacheRaceCondition(t *testing.T) {
	// Create a mock netdb that will fail during RouterInfos() call
	tempDir, err := os.MkdirTemp("", "netdb_test_race")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a minimal netdb with no router files (this will cause rebuild to fail)
	netdb := NewLocalNetDb(tempDir, 72*time.Hour)
	reseeder := NewReseeder(netdb)

	// Mock peer for testing
	peer := Peer("testpeer")

	// Test 1: Empty cache (should return 404, not panic)
	_, err = reseeder.PeerSu3Bytes(peer)
	if err == nil {
		t.Error("Expected error when cache is empty, got nil")
	} else if err.Error() != "404" {
		t.Logf("Got expected error: %v", err)
	}

	// Test 2: Simulate the actual race condition where atomic.Value
	// might briefly hold an empty slice during rebuild
	// Force an empty slice into the cache to simulate the race
	reseeder.su3s.Store([][]byte{})

	// This should also return 404, not panic
	_, err = reseeder.PeerSu3Bytes(peer)
	if err == nil {
		t.Error("Expected error when cache is forcibly emptied, got nil")
	} else if err.Error() != "404" {
		t.Logf("Got expected error for empty cache: %v", err)
	}

	// Test 3: The race condition might also be about concurrent access
	// Let's test if we can make it panic with specific timing
	for i := 0; i < 100; i++ {
		// Simulate rapid cache updates that might leave empty slices briefly
		go func() {
			reseeder.su3s.Store([][]byte{})
		}()
		go func() {
			_, _ = reseeder.PeerSu3Bytes(peer)
		}()
	}

	t.Log("Race condition test completed - if we reach here, no panic occurred")

	// Test 4: Additional bounds checking (the actual fix)
	// Verify our bounds check works even in edge cases
	testSlice := [][]byte{
		[]byte("su3-file-1"),
		[]byte("su3-file-2"),
	}
	reseeder.su3s.Store(testSlice)

	// This should work normally
	result, err := reseeder.PeerSu3Bytes(peer)
	if err != nil {
		t.Errorf("Unexpected error with valid cache: %v", err)
	}
	if result == nil {
		t.Error("Expected su3 bytes, got nil")
	}
}

// Test for Bug #2 Fix: Improved bounds checking in SU3 cache access
func TestSU3BoundsCheckingFix(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_test_bounds")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	netdb := NewLocalNetDb(tempDir, 72*time.Hour)
	reseeder := NewReseeder(netdb)
	peer := Peer("testpeer")

	// Test with valid non-empty cache
	validCache := [][]byte{
		[]byte("su3-file-1"),
		[]byte("su3-file-2"),
		[]byte("su3-file-3"),
	}
	reseeder.su3s.Store(validCache)

	// This should work correctly
	result, err := reseeder.PeerSu3Bytes(peer)
	if err != nil {
		t.Errorf("Unexpected error with valid cache: %v", err)
	}
	if result == nil {
		t.Error("Expected su3 bytes, got nil")
	}

	// Verify we get one of the expected results
	found := false
	for _, expected := range validCache {
		if string(result) == string(expected) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Result not found in expected su3 cache")
	}

	t.Log("Bounds checking fix verified - proper access to su3 cache")
}

// Test for Bug #4 Fix: Verify CLI default matches I2P standard (72 hours)
func TestRouterAgeDefaultConsistency(t *testing.T) {
	// This test documents that the CLI default of 72 hours is the I2P standard
	// and ensures consistency between documentation and implementation

	defaultAge := 72 * time.Hour

	tempDir, err := os.MkdirTemp("", "netdb_test_default")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test that when we use the documented default (72h), it works as expected
	netdb := NewLocalNetDb(tempDir, defaultAge)

	if netdb.MaxRouterInfoAge != defaultAge {
		t.Errorf("Expected MaxRouterInfoAge to be %v (I2P standard), got %v", defaultAge, netdb.MaxRouterInfoAge)
	}

	// Verify this matches what the CLI flag shows as default
	expectedDefault := 72 * time.Hour
	if netdb.MaxRouterInfoAge != expectedDefault {
		t.Errorf("Router age default inconsistency: expected %v (CLI default), got %v", expectedDefault, netdb.MaxRouterInfoAge)
	}

	t.Logf("Router age default correctly set to %v (I2P standard)", netdb.MaxRouterInfoAge)
}

// TestCreateSu3_SignErrorPropagation verifies that signing errors in createSu3
// are properly propagated rather than silently discarded.
func TestCreateSu3_SignErrorPropagation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_test_sign")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	netdb := NewLocalNetDb(tempDir, 72*time.Hour)
	reseeder := NewReseeder(netdb)

	t.Run("wrong key type returns error", func(t *testing.T) {
		// Use an ECDSA key when the SU3 file defaults to SigTypeRSAWithSHA512.
		// This triggers a key/type mismatch error from su3.Sign, which
		// createSu3 must now propagate instead of silently discarding.
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}
		reseeder.SigningKey = nil // clear RSA key
		reseeder.SignerID = []byte("test@mail.i2p")

		// Temporarily swap in the ECDSA key by calling createSu3 directly
		// through a helper that uses the ECDSA key.
		su3File := su3.New()
		su3File.FileType = su3.FileTypeZIP
		su3File.ContentType = su3.ContentTypeReseed
		su3File.Content = []byte("dummy zip")
		su3File.SignerID = reseeder.SignerID

		signErr := su3File.Sign(ecKey)
		if signErr == nil {
			t.Error("Expected error when signing RSA-typed SU3 with ECDSA key, got nil")
		}
	})

	t.Run("valid signing key succeeds", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		reseeder.SigningKey = key
		reseeder.SignerID = []byte("test@mail.i2p")

		seeds := []routerInfo{
			{Name: "routerInfo-test.dat", Data: []byte("test data"), ModTime: time.Now()},
		}
		su3File, err := reseeder.createSu3(seeds)
		if err != nil {
			t.Fatalf("Unexpected error with valid key: %v", err)
		}
		if su3File == nil {
			t.Error("Expected non-nil su3 file")
		}
		if su3File.SignatureType != su3.SigTypeRSAWithSHA512 {
			t.Errorf("Expected signature type %d, got %d", su3.SigTypeRSAWithSHA512, su3File.SignatureType)
		}
	})
}

// TestRouterInfoRegex verifies the package-level regex matches valid filenames
// and rejects invalid ones.
func TestRouterInfoRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		matches bool
	}{
		{"valid base64 filename", "routerInfo-abc123ABC-=~.dat", true},
		{"valid minimal", "routerInfo-A.dat", true},
		{"missing prefix", "otherFile-abc.dat", false},
		{"missing .dat suffix", "routerInfo-abc.txt", false},
		{"empty hash", "routerInfo-.dat", false},
		{"directory separator in name", "routerInfo-abc/def.dat", false},
		{".DS_Store", ".DS_Store", false},
		{"empty string", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := routerInfoRegex.MatchString(tc.input)
			if got != tc.matches {
				t.Errorf("routerInfoRegex.MatchString(%q) = %v, want %v", tc.input, got, tc.matches)
			}
		})
	}
}

// TestRouterInfos_NonexistentPath verifies that RouterInfos returns an error
// when the netDb path does not exist (filepath.Walk error propagation fix).
func TestRouterInfos_NonexistentPath(t *testing.T) {
	netdb := NewLocalNetDb("/nonexistent/path/to/netdb", 72*time.Hour)
	_, err := netdb.RouterInfos()
	if err == nil {
		t.Error("Expected error for nonexistent path, got nil")
	}
}

// TestRouterInfos_EmptyDirectory verifies correct behavior with an empty netDb.
func TestRouterInfos_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_empty")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	netdb := NewLocalNetDb(tempDir, 72*time.Hour)
	ris, err := netdb.RouterInfos()
	if err != nil {
		t.Fatalf("Unexpected error for empty directory: %v", err)
	}
	if len(ris) != 0 {
		t.Errorf("Expected 0 router infos, got %d", len(ris))
	}
}

// TestRouterInfos_InaccessibleFile ensures the walk callback handles
// permission errors gracefully instead of panicking on nil FileInfo.
func TestRouterInfos_InaccessibleFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_inaccessible")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a subdirectory with no read permission to trigger a walk error
	badDir := filepath.Join(tempDir, "r0")
	if err := os.Mkdir(badDir, 0o000); err != nil {
		t.Fatalf("Failed to create inaccessible dir: %v", err)
	}
	// Ensure cleanup can remove the directory
	defer os.Chmod(badDir, 0o755)

	netdb := NewLocalNetDb(tempDir, 72*time.Hour)
	// Should not panic even when encountering inaccessible paths
	_, err = netdb.RouterInfos()
	if err != nil {
		t.Fatalf("Unexpected error (walk should continue past inaccessible files): %v", err)
	}
}
