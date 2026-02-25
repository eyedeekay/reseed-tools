package reseed

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPingClient_HasTimeout verifies that the dedicated ping HTTP client
// has a non-zero timeout to prevent goroutine leaks from unresponsive servers.
func TestPingClient_HasTimeout(t *testing.T) {
	if pingClient.Timeout == 0 {
		t.Fatal("pingClient.Timeout must be non-zero to prevent goroutine leaks")
	}
	if pingClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", pingClient.Timeout)
	}
}

// TestPing_SuccessfulServer tests Ping against a mock server returning HTTP 200.
func TestPing_SuccessfulServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != I2pUserAgent {
			t.Errorf("expected User-Agent %q, got %q", I2pUserAgent, r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alive, err := Ping(server.URL + "/i2pseeds.su3")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !alive {
		t.Error("expected alive=true for 200 response")
	}
}

// TestPing_AppendsSU3Suffix verifies that Ping appends "i2pseeds.su3" when missing.
func TestPing_AppendsSU3Suffix(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// URL with trailing slash so the suffix appends correctly
	_, err := Ping(server.URL + "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(receivedPath, "i2pseeds.su3") {
		t.Errorf("expected path to end with i2pseeds.su3, got %q", receivedPath)
	}
}

// TestPing_DoesNotAppendSU3SuffixWhenPresent verifies no double-append.
func TestPing_DoesNotAppendSU3SuffixWhenPresent(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := Ping(server.URL + "/i2pseeds.su3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(receivedPath, "i2pseeds.su3") != 1 {
		t.Errorf("expected exactly one i2pseeds.su3 in path, got %q", receivedPath)
	}
}

// TestPing_NonOKStatus tests Ping with non-200 HTTP responses.
func TestPing_NonOKStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"403 Forbidden", http.StatusForbidden},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			alive, err := Ping(server.URL + "/i2pseeds.su3")
			if alive {
				t.Error("expected alive=false for non-200 response")
			}
			if err == nil {
				t.Error("expected error for non-200 response")
			}
		})
	}
}

// TestPing_InvalidURL tests Ping with an invalid URL that fails request creation.
func TestPing_InvalidURL(t *testing.T) {
	alive, err := Ping("://invalid-url")
	if alive {
		t.Error("expected alive=false for invalid URL")
	}
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// TestPing_UsesI2PUserAgent verifies the correct User-Agent header is sent.
func TestPing_UsesI2PUserAgent(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	Ping(server.URL + "/i2pseeds.su3")
	if receivedUA != I2pUserAgent {
		t.Errorf("expected User-Agent %q, got %q", I2pUserAgent, receivedUA)
	}
}

// TestTrimPath verifies protocol and path stripping for filename generation.
func TestTrimPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"HTTPS URL", "https://example.com/path", "example.compath"},
		{"HTTP URL", "http://example.com/path", "example.compath"},
		{"No protocol", "example.com/path", "example.compath"},
		{"Multiple slashes", "https://example.com/a/b/c", "example.comabc"},
		{"No slashes", "example.com", "example.com"},
		{"Empty string", "", ""},
		{"Only protocol", "https://", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimPath(tt.input)
			if got != tt.expected {
				t.Errorf("trimPath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestYday verifies that yday returns a time approximately 24 hours ago.
func TestYday(t *testing.T) {
	before := time.Now().Add(-24*time.Hour - time.Second)
	result := yday()
	after := time.Now().Add(-24*time.Hour + time.Second)

	if result.Before(before) {
		t.Errorf("yday() %v is before expected range starting %v", result, before)
	}
	if result.After(after) {
		t.Errorf("yday() %v is after expected range ending %v", result, after)
	}
}

// TestPingEverybody_RateLimiting verifies that consecutive PingEverybody calls
// are rate-limited (second call returns nil immediately).
func TestPingEverybody_RateLimiting(t *testing.T) {
	// Set lastPing to now (simulating a recent ping) to test rate limiting
	pingMu.Lock()
	lastPing = time.Now()
	pingMu.Unlock()

	// Call should be rate-limited and return nil immediately
	result := PingEverybody()
	if result != nil {
		t.Errorf("expected nil from rate-limited PingEverybody, got %d results", len(result))
	}
}

// TestPingEverybody_ConcurrentSafety verifies that concurrent calls to
// PingEverybody do not trigger a data race on lastPing.
// Run with: go test -race -run TestPingEverybody_ConcurrentSafety
func TestPingEverybody_ConcurrentSafety(t *testing.T) {
	var wg sync.WaitGroup
	const numGoroutines = 10

	// Set to now so all calls are rate-limited (fast, no network)
	pingMu.Lock()
	lastPing = time.Now()
	pingMu.Unlock()

	// Launch concurrent calls — the race detector will flag unsynchronized access
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			PingEverybody()
		}()
	}
	wg.Wait()
	// If no race is detected by -race flag, the test passes
}

// TestPingWriteContent_InvalidURL tests PingWriteContent with a malformed URL.
func TestPingWriteContent_InvalidURL(t *testing.T) {
	err := PingWriteContent("://bad-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "PingWriteContent:") {
		t.Errorf("expected error prefixed with PingWriteContent:, got: %v", err)
	}
}

// TestPingWriteContent_WritesFile tests that PingWriteContent creates a .ping file.
func TestPingWriteContent_WritesFile(t *testing.T) {
	// Create a mock server that returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create temp directory for content output
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// Use URL with trailing slash so i2pseeds.su3 suffix is appended correctly
	err = PingWriteContent(server.URL + "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify a .ping file was created in the content directory
	date := time.Now().Format("2006-01-02")
	BaseContentPath, _ := StableContentPath()
	found := false
	filepath.Walk(BaseContentPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".ping") && strings.Contains(path, date) {
			found = true
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("failed to read ping file: %v", readErr)
			}
			if !strings.Contains(string(content), "Alive") {
				t.Errorf("expected ping file to contain 'Alive', got: %s", content)
			}
		}
		return nil
	})
	if !found {
		t.Error("no .ping file was created")
	}
}

// TestPingWriteContent_SkipsExistingFile tests that existing .ping files are not overwritten.
func TestPingWriteContent_SkipsExistingFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// First call creates the file
	err = PingWriteContent(server.URL + "/")
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Second call should skip (file exists)
	err = PingWriteContent(server.URL + "/")
	if err != nil {
		t.Fatalf("second call should succeed silently: %v", err)
	}
}

// TestPingWriteContent_FailedPing tests that a failed ping writes "Dead:" content.
func TestPingWriteContent_FailedPing(t *testing.T) {
	// Server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// Use trailing slash for valid URL formation
	err = PingWriteContent(server.URL + "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify .ping file contains "Dead:"
	date := time.Now().Format("2006-01-02")
	BaseContentPath, _ := StableContentPath()
	found := false
	filepath.Walk(BaseContentPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".ping") && strings.Contains(path, date) {
			found = true
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("failed to read ping file: %v", readErr)
			}
			if !strings.Contains(string(content), "Dead:") {
				t.Errorf("expected ping file to contain 'Dead:', got: %s", content)
			}
		}
		return nil
	})
	if !found {
		t.Error("no .ping file was created for failed ping")
	}
}

// TestGetPingFiles_NoPingFiles tests GetPingFiles when no .ping files exist.
func TestGetPingFiles_NoPingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	files, err := GetPingFiles()
	if err == nil {
		t.Error("expected error when no ping files found")
	}
	if files != nil {
		t.Errorf("expected nil files, got %d", len(files))
	}
	if !strings.Contains(err.Error(), "no ping files found") {
		t.Errorf("expected 'no ping files found' error, got: %v", err)
	}
}

// TestGetPingFiles_FindsTodaysPingFiles tests that GetPingFiles returns
// only files matching today's date.
func TestGetPingFiles_FindsTodaysPingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// Ensure content path exists via extraction
	BaseContentPath, err := StableContentPath()
	if err != nil {
		t.Fatalf("StableContentPath: %v", err)
	}

	date := time.Now().Format("2006-01-02")

	// Create today's ping file
	todayFile := filepath.Join(BaseContentPath, "example.com-"+date+".ping")
	if err := os.WriteFile(todayFile, []byte("Alive"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Create yesterday's ping file (should not be returned)
	yesterday := time.Now().Add(-24 * time.Hour).Format("2006-01-02")
	oldFile := filepath.Join(BaseContentPath, "example.com-"+yesterday+".ping")
	if err := os.WriteFile(oldFile, []byte("Dead"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetPingFiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Check that today's file is in the results
	foundToday := false
	foundOld := false
	for _, f := range files {
		if strings.Contains(f, "example.com-"+date+".ping") {
			foundToday = true
		}
		if strings.Contains(f, "example.com-"+yesterday+".ping") {
			foundOld = true
		}
	}
	if !foundToday {
		t.Errorf("expected today's ping file in results, got: %v", files)
	}
	if foundOld {
		t.Errorf("yesterday's ping file should not be in results")
	}
}

// TestReadOut_WithPingFiles tests ReadOut generates proper HTML with escaped content.
func TestReadOut_WithPingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	BaseContentPath, err := StableContentPath()
	if err != nil {
		t.Fatalf("StableContentPath: %v", err)
	}

	date := time.Now().Format("2006-01-02")

	// Create a ping file with content that needs HTML escaping
	pingFile := filepath.Join(BaseContentPath, "test-server-"+date+".ping")
	if err := os.WriteFile(pingFile, []byte("Alive: <script>alert('xss')</script>"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	ReadOut(w)

	body := w.Body.String()
	if !strings.Contains(body, "Reseed Server Statuses") {
		t.Error("expected HTML header in output")
	}
	// Verify content is HTML-escaped — the <script> tag should not appear raw
	if strings.Contains(body, "<script>") {
		t.Error("ReadOut did not HTML-escape ping content, XSS vector present")
	}
	escaped := html.EscapeString("<script>alert('xss')</script>")
	if !strings.Contains(body, escaped) {
		t.Errorf("expected escaped content %q in output, got: %s", escaped, body)
	}
}

// TestReadOut_NoPingFiles tests ReadOut when no ping files are available.
func TestReadOut_NoPingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	ReadOut(w)

	body := w.Body.String()
	if !strings.Contains(body, "No ping files found") {
		t.Errorf("expected 'No ping files found' message, got: %s", body)
	}
}

// TestReadOut_HTMLEscapesHostnames verifies that hostnames derived from filenames
// are HTML-escaped to prevent injection.
func TestReadOut_HTMLEscapesHostnames(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	BaseContentPath, err := StableContentPath()
	if err != nil {
		t.Fatalf("StableContentPath: %v", err)
	}

	date := time.Now().Format("2006-01-02")

	// Create a ping file with a "malicious" hostname component
	// Use & which needs escaping but is safe in filenames
	hostPart := "bad&host"
	pingFile := filepath.Join(BaseContentPath, fmt.Sprintf("%s-%s.ping", hostPart, date))
	if err := os.WriteFile(pingFile, []byte("Alive: OK"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	ReadOut(w)

	body := w.Body.String()
	// The raw & should be escaped to &amp; in the HTML output
	if strings.Contains(body, "<strong>bad&host") && !strings.Contains(body, "&amp;") {
		t.Error("hostname not HTML-escaped: found raw & without escaping in output")
	}
}

// TestPingMutex_ProtectsLastPing verifies the mutex is properly used
// by checking that concurrent resets and reads don't panic.
func TestPingMutex_ProtectsLastPing(t *testing.T) {
	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Simulate concurrent rate-limit checks
			pingMu.Lock()
			lastPing = time.Now()
			pingMu.Unlock()

			pingMu.Lock()
			_ = lastPing.After(yday())
			pingMu.Unlock()
		}()
	}
	wg.Wait()
}
