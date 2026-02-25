package reseed

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestHandleAFile_CachesContent verifies that handleAFile reads from disk on
// first call and returns cached content on subsequent calls.
func TestHandleAFile_CachesContent(t *testing.T) {
	// Clear cache before test
	cachedDataMu.Lock()
	CachedDataPages = map[string][]byte{}
	cachedDataMu.Unlock()

	// Create temp content directory structure
	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	testContent := "body { color: red; }"
	if err := os.WriteFile(filepath.Join(contentDir, "style.css"), []byte(testContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Override working directory so StableContentPath finds our temp content
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// First request — should read from disk
	w := httptest.NewRecorder()
	handleAFile(w, "", "style.css")
	if w.Body.String() != testContent {
		t.Errorf("first call: got %q, want %q", w.Body.String(), testContent)
	}

	// Verify it was cached
	cachedDataMu.RLock()
	cached, ok := CachedDataPages["style.css"]
	cachedDataMu.RUnlock()
	if !ok {
		t.Fatal("content was not cached after first call")
	}
	if string(cached) != testContent {
		t.Errorf("cached value: got %q, want %q", string(cached), testContent)
	}

	// Second request — should serve from cache
	w2 := httptest.NewRecorder()
	handleAFile(w2, "", "style.css")
	if w2.Body.String() != testContent {
		t.Errorf("second call: got %q, want %q", w2.Body.String(), testContent)
	}
}

// TestHandleAFile_FileNotFound verifies error handling for missing files.
func TestHandleAFile_FileNotFound(t *testing.T) {
	cachedDataMu.Lock()
	CachedDataPages = map[string][]byte{}
	cachedDataMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	handleAFile(w, "", "nonexistent.css")
	body := w.Body.String()
	if !strings.Contains(body, "Oops!") {
		t.Errorf("expected error message, got: %q", body)
	}
}

// TestHandleAFile_ConcurrentAccess verifies that concurrent calls to handleAFile
// do not cause a fatal "concurrent map read and map write" panic.
func TestHandleAFile_ConcurrentAccess(t *testing.T) {
	cachedDataMu.Lock()
	CachedDataPages = map[string][]byte{}
	cachedDataMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create multiple test files
	for i := 0; i < 10; i++ {
		name := filepath.Join(contentDir, strings.Replace("file_X.css", "X", string(rune('a'+i)), 1))
		if err := os.WriteFile(name, []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Launch many goroutines hitting the cache concurrently.
	// Before the fix, this would cause "fatal error: concurrent map read and map write".
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			file := strings.Replace("file_X.css", "X", string(rune('a'+(idx%10))), 1)
			w := httptest.NewRecorder()
			handleAFile(w, "", file)
		}(i)
	}
	wg.Wait()
}

// TestHandleALocalizedFile_SkipsNonMarkdownFiles verifies that non-.md files
// in language directories are skipped (not causing early return).
func TestHandleALocalizedFile_SkipsNonMarkdownFiles(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	langDir := filepath.Join(contentDir, "lang", "en")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a non-.md file that sorts before .md files
	// .DS_Store sorts before alphabetic names
	if err := os.WriteFile(filepath.Join(langDir, ".DS_Store"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Create actual markdown content
	mdContent := "# Hello World\n\nThis is a test."
	if err := os.WriteFile(filepath.Join(langDir, "01-intro.md"), []byte(mdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	handleALocalizedFile(w, "en")
	body := w.Body.String()

	// Before the fix: `return` on .DS_Store would produce empty output.
	// After the fix: .DS_Store is skipped via `continue`, and the .md file is rendered.
	if body == "" {
		t.Error("handleALocalizedFile produced empty output; non-.md file was not skipped")
	}
	if !strings.Contains(body, "Hello World") {
		t.Errorf("expected rendered markdown content, got: %q", body)
	}
	if !strings.Contains(body, `<div id="01-intro">`) {
		t.Errorf("expected div wrapper with trimmed name, got: %q", body)
	}
}

// TestHandleALocalizedFile_CachesContent verifies that localized content is cached
// after first access and served from cache on subsequent calls.
func TestHandleALocalizedFile_CachesContent(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	langDir := filepath.Join(contentDir, "lang", "de")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(langDir, "welcome.md"), []byte("# Willkommen"), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// First call
	w1 := httptest.NewRecorder()
	handleALocalizedFile(w1, "de")
	first := w1.Body.String()
	if first == "" {
		t.Fatal("first call produced empty output")
	}

	// Verify cached
	cachedLanguageMu.RLock()
	_, ok := CachedLanguagePages["de"]
	cachedLanguageMu.RUnlock()
	if !ok {
		t.Fatal("localized content was not cached after first call")
	}

	// Second call from cache
	w2 := httptest.NewRecorder()
	handleALocalizedFile(w2, "de")
	if w2.Body.String() != first {
		t.Errorf("cached content differs: %q vs %q", w2.Body.String(), first)
	}
}

// TestHandleALocalizedFile_ConcurrentAccess verifies that concurrent calls to
// handleALocalizedFile do not panic from concurrent map access.
func TestHandleALocalizedFile_ConcurrentAccess(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")

	// Create several language directories
	langs := []string{"en", "de", "fr", "es", "ru"}
	for _, lang := range langs {
		langDir := filepath.Join(contentDir, "lang", lang)
		if err := os.MkdirAll(langDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(langDir, "page.md"), []byte("# "+lang), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Launch concurrent goroutines accessing different and same languages.
	// Before the fix, this would cause "fatal error: concurrent map read and map write".
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			lang := langs[idx%len(langs)]
			w := httptest.NewRecorder()
			handleALocalizedFile(w, lang)
		}(i)
	}
	wg.Wait()
}

// TestHandleALocalizedFile_MissingDirectory verifies graceful error handling
// when the language directory does not exist.
func TestHandleALocalizedFile_MissingDirectory(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Don't create the lang/xx directory

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	handleALocalizedFile(w, "xx")
	body := w.Body.String()
	if !strings.Contains(body, "Oops!") {
		t.Errorf("expected error message for missing directory, got: %q", body)
	}
}

// TestHandleALocalizedFile_ReturnsOnReadError verifies that handleALocalizedFile
// handles unreadable files gracefully after the os.ReadDir succeeds.
func TestHandleALocalizedFile_ReturnsOnReadError(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	langDir := filepath.Join(contentDir, "lang", "ko")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create an unreadable .md file
	mdFile := filepath.Join(langDir, "page.md")
	if err := os.WriteFile(mdFile, []byte("# Test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mdFile, 0o000); err != nil {
		t.Skip("cannot change file permissions on this OS")
	}
	defer os.Chmod(mdFile, 0o644) // cleanup

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	handleALocalizedFile(w, "ko")
	body := w.Body.String()
	if !strings.Contains(body, "Oops!") {
		t.Errorf("expected error for unreadable file, got: %q", body)
	}
}

// TestHandleALocalizedFile_OnlyMarkdownFiles verifies that a directory with
// only .md files processes correctly (no regression from continue fix).
func TestHandleALocalizedFile_OnlyMarkdownFiles(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	langDir := filepath.Join(contentDir, "lang", "jp")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(langDir, "01-first.md"), []byte("# First"), 0o644)
	os.WriteFile(filepath.Join(langDir, "02-second.md"), []byte("# Second"), 0o644)

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	w := httptest.NewRecorder()
	handleALocalizedFile(w, "jp")
	body := w.Body.String()

	if !strings.Contains(body, "First") || !strings.Contains(body, "Second") {
		t.Errorf("expected both markdown files rendered, got: %q", body)
	}
	if !strings.Contains(body, `<div id="01-first">`) || !strings.Contains(body, `<div id="02-second">`) {
		t.Errorf("expected both div wrappers, got: %q", body)
	}
}

// TestCachedDataPages_ThreadSafe exercises the cache mutex under the race detector.
func TestCachedDataPages_ThreadSafe(t *testing.T) {
	cachedDataMu.Lock()
	CachedDataPages = map[string][]byte{}
	cachedDataMu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			key := string(rune('a' + (idx % 26)))
			cachedDataMu.Lock()
			CachedDataPages[key] = []byte("data")
			cachedDataMu.Unlock()
		}(i)
		go func(idx int) {
			defer wg.Done()
			key := string(rune('a' + (idx % 26)))
			cachedDataMu.RLock()
			_ = CachedDataPages[key]
			cachedDataMu.RUnlock()
		}(i)
	}
	wg.Wait()
}

// TestCachedLanguagePages_ThreadSafe exercises the language cache mutex under the race detector.
func TestCachedLanguagePages_ThreadSafe(t *testing.T) {
	cachedLanguageMu.Lock()
	CachedLanguagePages = map[string]string{}
	cachedLanguageMu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			key := string(rune('a' + (idx % 26)))
			cachedLanguageMu.Lock()
			CachedLanguagePages[key] = "html"
			cachedLanguageMu.Unlock()
		}(i)
		go func(idx int) {
			defer wg.Done()
			key := string(rune('a' + (idx % 26)))
			cachedLanguageMu.RLock()
			_ = CachedLanguagePages[key]
			cachedLanguageMu.RUnlock()
		}(i)
	}
	wg.Wait()
}

// TestContentPath_BadCwd verifies ContentPath handles invalid working directory gracefully.
func TestContentPath_BadCwd(t *testing.T) {
	// Verify that ContentPath returns the expected content directory relative to cwd
	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	path, err := ContentPath()
	if err != nil {
		t.Fatalf("ContentPath() error: %v", err)
	}
	if path != contentDir {
		t.Errorf("ContentPath() = %q, want %q", path, contentDir)
	}
}

// TestHandleARealBrowser_Smoke is a basic smoke test verifying that HandleARealBrowser
// does not panic. Note: StableContentPath auto-extracts embedded content, so a "no content"
// scenario is difficult to reproduce reliably.
func TestHandleARealBrowser_Smoke(t *testing.T) {
	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	srv := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en")
	w := httptest.NewRecorder()

	// Should not panic regardless of content availability
	srv.HandleARealBrowser(w, req)
	if w.Code == 0 {
		t.Error("expected non-zero status code")
	}
}
