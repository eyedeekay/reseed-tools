package reseed

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/go-i2p/onramp"
	"github.com/gorilla/handlers"
	"github.com/justinas/alice"
	throttled "github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store"
)

// Constants moved to constants.go

// Server represents a complete reseed server instance with multi-protocol support.
// It provides HTTP/HTTPS reseed services over clearnet, I2P, and Tor networks with
// rate limiting, blacklisting, and comprehensive security features for distributing
// router information to bootstrap new I2P nodes joining the network.
type Server struct {
	*http.Server

	// Reseeder handles the core reseed functionality and SU3 file generation
	Reseeder *ReseederImpl
	// Blacklist manages IP-based access control for security
	Blacklist *Blacklist

	// ServerListener handles standard HTTP/HTTPS connections
	ServerListener net.Listener

	// I2P Listener configuration for serving over I2P network
	Garlic      *onramp.Garlic
	I2PListener net.Listener

	// Tor Listener configuration for serving over Tor network
	OnionListener net.Listener
	Onion         *onramp.Onion

	// Rate limiting configuration for request throttling
	RequestRateLimit int
	WebRateLimit     int
	// Thread-safe tracking of acceptable client connection timing
	acceptables      map[string]time.Time
	acceptablesMutex sync.RWMutex
}

// NewServer creates a new reseed server instance with secure TLS configuration.
// It sets up TLS 1.3-only connections, proper cipher suites, and middleware chain for
// request processing. The prefix parameter customizes URL paths and trustProxy enables
// reverse proxy support for deployment behind load balancers or CDNs.
func NewServer(prefix string, trustProxy bool) *Server {
	config := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP384, tls.CurveP521}, // default CurveP256 removed
	}
	h := &http.Server{TLSConfig: config}
	server := Server{Server: h, Reseeder: nil}

	throttleSu3Handler := throttled.RateLimit(throttled.PerHour(4), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(200000))
	throttleWebHandler := throttled.RateLimit(throttled.PerHour(30), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(200000))

	middlewareChain := alice.New()
	if trustProxy {
		middlewareChain = middlewareChain.Append(proxiedMiddleware)
	}

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write(nil); nil != err {
			lgr.WithError(err).Error("Error writing HTTP response")
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware, throttleWebHandler.RateLimit, server.browsingMiddleware).Then(errorHandler))
	mux.Handle(prefix+"/i2pseeds.su3", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware, verifyMiddleware, throttleSu3Handler.RateLimit).Then(http.HandlerFunc(server.reseedHandler)))
	server.Handler = mux

	return &server
}

// See use of crypto/rand on:
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
// Constants moved to constants.go

// SecureRandomAlphaString generates a cryptographically secure random alphabetic string.
// Returns a 16-character string using only letters for use in tokens, session IDs, and
// other security-sensitive contexts. Uses crypto/rand for entropy source.
func SecureRandomAlphaString() string {
	// Fixed 16-character length for consistent token generation
	length := 16
	result := make([]byte, length)
	// Buffer size calculation for efficient random byte usage
	bufferSize := int(float64(length) * 1.3)
	for i, j, randomBytes := 0, 0, []byte{}; i < length; j++ {
		// Refresh random bytes buffer when needed for efficiency
		if j%bufferSize == 0 {
			randomBytes = SecureRandomBytes(bufferSize)
		}
		// Filter random bytes to only include valid letter indices
		if idx := int(randomBytes[j%length] & letterIdxMask); idx < len(letterBytes) {
			result[i] = letterBytes[idx]
			i++
		}
	}
	return string(result)
}

// SecureRandomBytes generates cryptographically secure random bytes of specified length.
// Uses crypto/rand for high-quality entropy suitable for cryptographic operations, tokens,
// and security-sensitive random data generation. Panics on randomness failure for security.
func SecureRandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	// Use crypto/rand for cryptographically secure random generation
	_, err := rand.Read(randomBytes)
	if err != nil {
		lgr.WithError(err).Fatal("Unable to generate random bytes")
	}
	return randomBytes
}

//

func (srv *Server) Address() string {
	addrs := make(map[string]string)
	if srv.I2PListener != nil {
		addrs["i2p"] = srv.I2PListener.Addr().String()
	}
	if srv.OnionListener != nil {
		addrs["onion"] = srv.OnionListener.Addr().String()
	}
	if srv.Server != nil {
		addrs["tcp"] = srv.Server.Addr
	}
	return fmt.Sprintf("%v", addrs)
}

func (srv *Server) Acceptable() string {
	srv.acceptablesMutex.Lock()
	defer srv.acceptablesMutex.Unlock()

	if srv.acceptables == nil {
		srv.acceptables = make(map[string]time.Time)
	}

	// Clean up expired entries first
	srv.cleanupExpiredTokensUnsafe()

	// If still too many entries, remove oldest ones
	if len(srv.acceptables) > 50 {
		srv.evictOldestTokensUnsafe(50)
	}

	acceptme := SecureRandomAlphaString()
	srv.acceptables[acceptme] = time.Now()
	return acceptme
}

func (srv *Server) CheckAcceptable(val string) bool {
	srv.acceptablesMutex.Lock()
	defer srv.acceptablesMutex.Unlock()

	if srv.acceptables == nil {
		srv.acceptables = make(map[string]time.Time)
	}
	if timeout, ok := srv.acceptables[val]; ok {
		checktime := time.Since(timeout)
		if checktime > (4 * time.Minute) {
			delete(srv.acceptables, val)
			return false
		}
		delete(srv.acceptables, val)
		return true
	}
	return false
}

// checkAcceptableUnsafe performs acceptable checking without acquiring the mutex.
// This should only be called when the mutex is already held.
func (srv *Server) checkAcceptableUnsafe(val string) bool {
	if timeout, ok := srv.acceptables[val]; ok {
		checktime := time.Since(timeout)
		if checktime > (4 * time.Minute) {
			delete(srv.acceptables, val)
			return false
		}
		// Don't delete here since we're just cleaning up expired entries
		return true
	}
	return false
}

func (srv *Server) reseedHandler(w http.ResponseWriter, r *http.Request) {
	var peer Peer
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = Peer(ip)
	} else {
		peer = Peer(r.RemoteAddr)
	}

	su3Bytes, err := srv.Reseeder.PeerSu3Bytes(peer)
	if nil != err {
		lgr.WithError(err).WithField("peer", peer).Errorf("Error serving su3 %s", err)
		http.Error(w, "500 Unable to serve su3", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=i2pseeds.su3")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(su3Bytes)), 10))

	io.Copy(w, bytes.NewReader(su3Bytes))
}

func disableKeepAliveMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Version", Version)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func (srv *Server) browsingMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if srv.CheckAcceptable(r.FormValue("onetime")) {
			srv.reseedHandler(w, r)
			return
		}
		if I2pUserAgent != r.UserAgent() {
			srv.HandleARealBrowser(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func verifyMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if I2pUserAgent != r.UserAgent() {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func proxiedMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			r.RemoteAddr = prior[0]
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// cleanupExpiredTokensUnsafe removes expired tokens from the acceptables map.
// This should only be called when the mutex is already held.
func (srv *Server) cleanupExpiredTokensUnsafe() {
	now := time.Now()
	for token, timestamp := range srv.acceptables {
		if now.Sub(timestamp) > (4 * time.Minute) {
			delete(srv.acceptables, token)
		}
	}
}

// evictOldestTokensUnsafe removes the oldest tokens to keep the map size at the target.
// This should only be called when the mutex is already held.
func (srv *Server) evictOldestTokensUnsafe(targetSize int) {
	if len(srv.acceptables) <= targetSize {
		return
	}

	// Convert to slice and sort by timestamp
	type tokenTime struct {
		token string
		time  time.Time
	}

	tokens := make([]tokenTime, 0, len(srv.acceptables))
	for token, timestamp := range srv.acceptables {
		tokens = append(tokens, tokenTime{token, timestamp})
	}

	// Sort by timestamp (oldest first)
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].time.Before(tokens[j].time)
	})

	// Delete oldest tokens until we reach target size
	toDelete := len(srv.acceptables) - targetSize
	for i := 0; i < toDelete && i < len(tokens); i++ {
		delete(srv.acceptables, tokens[i].token)
	}
}
