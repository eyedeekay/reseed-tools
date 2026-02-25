package reseed

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/eyedeekay/unembed"
	"gitlab.com/golang-commonmark/markdown"
	"golang.org/x/text/language"
)

// f contains the embedded static content files for the reseed server web interface.
// This includes HTML templates, CSS stylesheets, JavaScript files, and localized content
// for serving the homepage and user interface to reseed service clients.
//
//go:embed content
var f embed.FS

// SupportedLanguages defines all languages available for the reseed server homepage.
// These language tags are used for content localization and browser language matching
// to provide multilingual support for users accessing the reseed service web interface.
var SupportedLanguages = []language.Tag{
	language.English,
	language.Russian,
	language.SimplifiedChinese,
	language.Arabic,
	language.Portuguese,
	language.German,
	language.French,
	language.Spanish,
	language.Indonesian,
	language.Hindi,
	language.Japanese,
	language.Korean,
	language.Bengali,
}

var (
	// cachedLanguageMu protects CachedLanguagePages from concurrent map access.
	cachedLanguageMu sync.RWMutex
	// CachedLanguagePages stores pre-processed language-specific content pages for performance.
	// Keys are language directory paths and values are rendered HTML content to avoid
	// repeated markdown processing on each request for better response times.
	CachedLanguagePages = map[string]string{}
	// cachedDataMu protects CachedDataPages from concurrent map access.
	cachedDataMu sync.RWMutex
	// CachedDataPages stores static file content in memory for faster serving.
	// Keys are file paths and values are raw file content bytes to reduce filesystem I/O
	// and improve performance for frequently accessed static resources.
	CachedDataPages = map[string][]byte{}
)

// StableContentPath returns the path to static content files for the reseed server homepage.
// It automatically extracts embedded content to the filesystem if not already present and
// ensures the content directory structure is available for serving web requests.
func StableContentPath() (string, error) {
	// Attempt to get the base content path from the system
	BaseContentPath, ContentPathError := ContentPath()
	// Extract embedded content if directory doesn't exist
	if _, err := os.Stat(BaseContentPath); os.IsNotExist(err) {
		if err := unembed.Unembed(f, BaseContentPath); err != nil {
			return "", err
		} else {
			return BaseContentPath, nil
		}
	}
	return BaseContentPath, ContentPathError
}

// matcher provides language matching functionality for reseed server internationalization.
// It uses the SupportedLanguages list to match client browser language preferences
// with available localized content for optimal user experience.
var matcher = language.NewMatcher(SupportedLanguages)

// header contains the standard HTML document header for reseed server web pages.
// This template includes essential meta tags, CSS stylesheet links, and JavaScript
// imports needed for consistent styling and functionality across all served pages.
var header = []byte(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>This is an I2P Reseed Server</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>`)

// footer contains the closing HTML tags for reseed server web pages.
// This template ensures proper document structure termination for all served content
// and maintains valid HTML5 compliance across the web interface.
var footer = []byte(`  </body>
</html>`)

// md provides configured markdown processor for reseed server content rendering.
// It supports XHTML output and embedded HTML for converting markdown files to
// properly formatted web content with security and standards compliance.
var md = markdown.New(markdown.XHTMLOutput(true), markdown.HTML(true))

// ContentPath determines the filesystem path where reseed server content should be stored.
// It checks the current working directory and creates a content subdirectory for serving
// static files like HTML, CSS, and localized content to reseed service users.
func ContentPath() (string, error) {
	exPath, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// exPath := filepath.Dir(ex)
	if _, err := os.Stat(filepath.Join(exPath, "content")); err != nil {
		return "", err
	}
	return filepath.Join(exPath, "content"), nil
}

// HandleARealBrowser processes HTTP requests from web browsers and serves appropriate content.
// This function routes browser requests to the correct content handlers based on URL path
// and provides language localization support for the reseed server's web interface.
func (srv *Server) HandleARealBrowser(w http.ResponseWriter, r *http.Request) {
	if err := srv.validateContentPath(); err != nil {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Determine client's preferred language from headers and cookies
	baseLanguage := srv.determineClientLanguage(r)

	// Route request to appropriate handler based on URL path
	srv.routeRequest(w, r, baseLanguage)
}

// validateContentPath ensures the content directory exists and is accessible.
// Returns an error if content cannot be served.
func (srv *Server) validateContentPath() error {
	_, ContentPathError := StableContentPath()
	return ContentPathError
}

// determineClientLanguage extracts and processes language preferences from the HTTP request.
// It uses both cookie values and Accept-Language headers to determine the best language match.
func (srv *Server) determineClientLanguage(r *http.Request) string {
	lang, _ := r.Cookie("lang")
	accept := r.Header.Get("Accept-Language")

	lgr.WithField("lang", lang).WithField("accept", accept).Debug("Processing language preferences")
	srv.logRequestHeaders(r)

	tag, _ := language.MatchStrings(matcher, lang.String(), accept)
	lgr.WithField("tag", tag).Debug("Matched language tag")

	base, _ := tag.Base()
	lgr.WithField("base", base).Debug("Base language")

	return base.String()
}

// logRequestHeaders logs all HTTP request headers for debugging purposes.
func (srv *Server) logRequestHeaders(r *http.Request) {
	for name, values := range r.Header {
		for _, value := range values {
			lgr.WithField("header_name", name).WithField("header_value", value).Debug("Request header")
		}
	}
}

// routeRequest dispatches HTTP requests to the appropriate content handler based on URL path.
// Supports CSS files, JavaScript files, images, ping functionality, readout pages, and localized content.
func (srv *Server) routeRequest(w http.ResponseWriter, r *http.Request, baseLanguage string) {
	if strings.HasSuffix(r.URL.Path, "style.css") {
		srv.handleCSSRequest(w)
	} else if strings.HasSuffix(r.URL.Path, "script.js") {
		srv.handleJavaScriptRequest(w)
	} else {
		srv.handleDynamicRequest(w, r, baseLanguage)
	}
}

// handleCSSRequest serves CSS stylesheet files with appropriate content type headers.
func (srv *Server) handleCSSRequest(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/css")
	handleAFile(w, "", "style.css")
}

// handleJavaScriptRequest serves JavaScript files with appropriate content type headers.
func (srv *Server) handleJavaScriptRequest(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/javascript")
	handleAFile(w, "", "script.js")
}

// handleDynamicRequest processes requests for images, special functions, and localized content.
// Routes to appropriate handlers for images, ping operations, readout pages, and main homepage.
func (srv *Server) handleDynamicRequest(w http.ResponseWriter, r *http.Request, baseLanguage string) {
	image := strings.Replace(r.URL.Path, "/", "", -1)

	if strings.HasPrefix(image, "images") {
		srv.handleImageRequest(w, r)
	} else if strings.HasPrefix(image, "ping") {
		srv.handlePingRequest(w, r)
	} else if strings.HasPrefix(image, "readout") {
		srv.handleReadoutRequest(w)
	} else {
		srv.handleHomepageRequest(w, baseLanguage)
	}
}

// handleImageRequest serves image files with PNG content type headers.
func (srv *Server) handleImageRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	imagePath := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/"), "images")
	handleAFile(w, "images", imagePath)
}

// handlePingRequest processes ping functionality and redirects to homepage.
func (srv *Server) handlePingRequest(w http.ResponseWriter, r *http.Request) {
	PingEverybody()
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleReadoutRequest serves the readout page with status information.
func (srv *Server) handleReadoutRequest(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(header))
	ReadOut(w)
	w.Write([]byte(footer))
}

// handleHomepageRequest serves the main homepage with localized content and reseed functionality.
func (srv *Server) handleHomepageRequest(w http.ResponseWriter, baseLanguage string) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(header))
	handleALocalizedFile(w, baseLanguage)

	// Add reseed form with one-time token
	reseedForm := `<ul><li><form method="post" action="/i2pseeds" class="inline">
		<input type="hidden" name="onetime" value="` + srv.Acceptable() + `">
		<button type="submit" name="submit_param" value="submit_value" class="link-button">
		Reseed
		</button>
		</form></li></ul>`
	w.Write([]byte(reseedForm))

	ReadOut(w)
	w.Write([]byte(footer))
}

// handleAFile serves static files from the reseed server content directory with caching.
// It loads files from the filesystem on first access and caches them in memory for
// improved performance on subsequent requests, supporting CSS, JavaScript, and image files.
func handleAFile(w http.ResponseWriter, dirPath, file string) {
	BaseContentPath, _ := StableContentPath()
	file = filepath.Join(dirPath, file)

	cachedDataMu.RLock()
	cached, prs := CachedDataPages[file]
	cachedDataMu.RUnlock()

	if !prs {
		path := filepath.Join(BaseContentPath, file)
		f, err := os.ReadFile(path)
		if err != nil {
			w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
			return
		}

		cachedDataMu.Lock()
		CachedDataPages[file] = f
		cachedDataMu.Unlock()

		w.Write(f)
	} else {
		w.Write(cached)
	}
}

// handleALocalizedFile processes and serves language-specific content with markdown rendering.
// It reads markdown files from language subdirectories, converts them to HTML, and caches
// the results for efficient serving of multilingual reseed server interface content.
func handleALocalizedFile(w http.ResponseWriter, dirPath string) {
	cachedLanguageMu.RLock()
	cached, prs := CachedLanguagePages[dirPath]
	cachedLanguageMu.RUnlock()

	if !prs {
		BaseContentPath, _ := StableContentPath()
		dir := filepath.Join(BaseContentPath, "lang", dirPath)
		files, err := os.ReadDir(dir)
		if err != nil {
			w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
			return
		}
		var f []byte
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".md") {
				continue
			}
			trimmedName := strings.TrimSuffix(file.Name(), ".md")
			path := filepath.Join(dir, file.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
				return
			}
			f = append(f, []byte(`<div id="`+trimmedName+`">`)...)
			f = append(f, []byte(md.RenderToString(b))...)
			f = append(f, []byte(`</div>`)...)
		}

		cachedLanguageMu.Lock()
		CachedLanguagePages[dirPath] = string(f)
		cachedLanguageMu.Unlock()

		w.Write(f)
	} else {
		w.Write([]byte(cached))
	}
}
