package reseed

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// pingClient is a dedicated HTTP client for ping operations with a reasonable timeout.
// Using http.DefaultClient has no timeout and can cause goroutine leaks when servers
// are unresponsive. A 30-second timeout balances reliability with resource safety.
var pingClient = &http.Client{
	Timeout: 30 * time.Second,
}

// Ping tests the availability of a reseed server by requesting an SU3 file.
// It appends "i2pseeds.su3" to the URL if not present and validates the server response.
// Returns true if the server responds with HTTP 200, false and error details otherwise.
// Example usage: alive, err := Ping("https://reseed.example.com/")
func Ping(urlInput string) (bool, error) {
	// Ensure URL targets the standard reseed SU3 file endpoint
	if !strings.HasSuffix(urlInput, "i2pseeds.su3") {
		urlInput = fmt.Sprintf("%s%s", urlInput, "i2pseeds.su3")
	}
	lgr.WithField("url", urlInput).Debug("Pinging reseed server")
	// Create HTTP request with proper User-Agent for I2P compatibility
	req, err := http.NewRequest("GET", urlInput, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", I2pUserAgent)

	// Execute request using dedicated client with timeout to prevent goroutine leaks
	resp, err := pingClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("%s", resp.Status)
	}
	return true, nil
}

func trimPath(s string) string {
	// Remove protocol and path components to create clean filename
	tmp := strings.ReplaceAll(s, "https://", "")
	tmp = strings.ReplaceAll(tmp, "http://", "")
	tmp = strings.ReplaceAll(tmp, "/", "")
	return tmp
}

// PingWriteContent performs a ping test and writes the result to a timestamped file.
// Creates daily ping status files in the content directory for status tracking and
// web interface display. Files are named with host and date to prevent conflicts.
func PingWriteContent(urlInput string) error {
	lgr.WithField("url", urlInput).Debug("Calling PWC")
	// Generate date stamp for daily ping file organization
	date := time.Now().Format("2006-01-02")
	u, err := url.Parse(urlInput)
	if err != nil {
		lgr.WithError(err).WithField("url", urlInput).Error("PWC URL parsing error")
		return fmt.Errorf("PingWriteContent:%s", err)
	}
	// Create clean filename from host and date for ping result storage
	path := trimPath(u.Host)
	lgr.WithField("path", path).Debug("Calling PWC path")
	BaseContentPath, _ := StableContentPath()
	path = filepath.Join(BaseContentPath, path+"-"+date+".ping")
	// Only ping if daily result file doesn't exist to prevent spam
	if _, err := os.Stat(path); err != nil {
		result, err := Ping(urlInput)
		if result {
			lgr.WithField("url", urlInput).Debug("Ping: OK")
			err := os.WriteFile(path, []byte("Alive: Status OK"), 0o644)
			return err
		} else {
			lgr.WithField("url", urlInput).WithError(err).Error("Ping: failed")
			err := os.WriteFile(path, []byte("Dead: "+err.Error()), 0o644)
			return err
		}
	}
	return nil
}

// AllReseeds moved to shared_utils.go

func yday() time.Time {
	// Calculate yesterday's date for rate limiting ping operations
	today := time.Now()
	yesterday := today.Add(-24 * time.Hour)
	return yesterday
}

// pingMu protects lastPing from concurrent read/write access.
// Without synchronization, concurrent HTTP requests triggering PingEverybody()
// can race on the time.Time value, bypassing rate limiting or corrupting timestamps.
var pingMu sync.Mutex

// lastPing tracks the timestamp of the last successful ping operation for rate limiting.
// This prevents excessive server polling by ensuring ping operations only occur once
// per 24-hour period, respecting reseed server resources and network bandwidth.
// Access must be protected by pingMu.
var lastPing = yday()

// PingEverybody tests all known reseed servers and returns their status results.
// Implements rate limiting to prevent excessive pinging (once per 24 hours) and
// returns a slice of status strings indicating success or failure for each server.
// Thread-safe: uses pingMu to synchronize access to lastPing.
func PingEverybody() []string {
	pingMu.Lock()
	// Enforce rate limiting to prevent server abuse
	if lastPing.After(yday()) {
		pingMu.Unlock()
		lgr.Debug("Your ping was rate-limited")
		return nil
	}
	lastPing = time.Now()
	pingMu.Unlock()

	var nonerrs []string
	// Test each reseed server and collect results for display
	for _, urlInput := range AllReseeds {
		err := PingWriteContent(urlInput)
		if err == nil {
			nonerrs = append(nonerrs, urlInput)
		} else {
			nonerrs = append(nonerrs, err.Error()+"-"+urlInput)
		}
	}
	return nonerrs
}

// GetPingFiles retrieves all ping result files from today for status display.
// Searches the content directory for .ping files containing today's date and
// returns their paths for processing by the web interface status page.
func GetPingFiles() ([]string, error) {
	var files []string
	date := time.Now().Format("2006-01-02")
	BaseContentPath, _ := StableContentPath()
	// Walk content directory to find today's ping files
	err := filepath.Walk(BaseContentPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".ping") && strings.Contains(path, date) {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil, fmt.Errorf("no ping files found")
	}
	return files, err
}

// ReadOut writes HTML-formatted ping status information to the HTTP response.
// Displays the current status of all known reseed servers in a user-friendly format
// for the web interface, including warnings about experimental nature of the feature.
// All dynamic content is HTML-escaped to prevent injection from ping result data.
func ReadOut(w http.ResponseWriter) {
	pinglist, err := GetPingFiles()
	if err == nil {
		// Generate HTML status display with ping results
		fmt.Fprintf(w, "<h3>Reseed Server Statuses</h3>")
		fmt.Fprintf(w, "<div class=\"pingtest\">This feature is experimental and may not always provide accurate results.</div>")
		fmt.Fprintf(w, "<div class=\"homepage\"><p><ul>")
		for _, file := range pinglist {
			ping, err := os.ReadFile(file)
			host := strings.Replace(file, ".ping", "", 1)
			host = filepath.Base(host)
			if err == nil {
				fmt.Fprintf(w, "<li><strong>%s</strong> - %s</li>\n", html.EscapeString(host), html.EscapeString(string(ping)))
			} else {
				fmt.Fprintf(w, "<li><strong>%s</strong> - No ping file found</li>\n", html.EscapeString(host))
			}
		}
		fmt.Fprintf(w, "</ul></p></div>")
	} else {
		fmt.Fprintf(w, "<h4>No ping files found, check back later for reseed stats</h4>")
	}
}
