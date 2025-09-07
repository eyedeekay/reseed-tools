package cmd

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	//"flag"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	"github.com/cretz/bine/torutil/ed25519"
	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/onramp"
	"github.com/go-i2p/sam3"
	"github.com/otiai10/copy"
	"github.com/rglonek/untar"
	"github.com/urfave/cli/v3"
	"i2pgit.org/go-i2p/reseed-tools/reseed"

	"github.com/go-i2p/checki2cp/getmeanetdb"
)

var lgr = logger.GetGoI2PLogger()

func getDefaultSigner() string {
	intentionalsigner := os.Getenv("RESEED_EMAIL")
	if intentionalsigner == "" {
		adminsigner := os.Getenv("MAILTO")
		if adminsigner != "" {
			return strings.Replace(adminsigner, "\n", "", -1)
		}
		return ""
	}
	return strings.Replace(intentionalsigner, "\n", "", -1)
}

func getHostName() string {
	hostname := os.Getenv("RESEED_HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return strings.Replace(hostname, "\n", "", -1)
}

func providedReseeds(c *cli.Context) []string {
	reseedArg := c.StringSlice("friends")
	reseed.AllReseeds = reseedArg
	return reseed.AllReseeds
}

// NewReseedCommand creates a new CLI command for starting a reseed server.
// A reseed server provides bootstrap router information to help new I2P nodes join the network.
// The server supports multiple protocols (HTTP, HTTPS, I2P, Tor) and provides signed SU3 files
// containing router information for network bootstrapping.
func NewReseedCommand() *cli.Command {
	ndb, err := getmeanetdb.WhereIstheNetDB()
	if err != nil {
		lgr.WithError(err).Fatal("Failed to locate NetDB")
	}
	return &cli.Command{
		Name:   "reseed",
		Usage:  "Start a reseed server",
		Action: reseedAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "signer",
				Value: getDefaultSigner(),
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			&cli.StringFlag{
				Name:  "tlsHost",
				Value: getHostName(),
				Usage: "The public hostname used on your TLS certificate",
			},
			&cli.BoolFlag{
				Name:  "onion",
				Usage: "Present an onionv3 address",
			},
			&cli.BoolFlag{
				Name:  "singleOnion",
				Usage: "Use a faster, but non-anonymous single-hop onion",
			},
			&cli.StringFlag{
				Name:  "onionKey",
				Value: "onion.key",
				Usage: "Specify a path to an ed25519 private key for onion",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "Path to your su3 signing private key",
			},
			&cli.StringFlag{
				Name:  "netdb",
				Value: ndb,
				Usage: "Path to NetDB directory containing routerInfos",
			},
			&cli.DurationFlag{
				Name:  "routerInfoAge",
				Value: 72 * time.Hour,
				Usage: "Maximum age of router infos to include in reseed files (ex. 72h, 8d)",
			},
			&cli.StringFlag{
				Name:  "tlsCert",
				Usage: "Path to a TLS certificate",
			},
			&cli.StringFlag{
				Name:  "tlsKey",
				Usage: "Path to a TLS private key",
			},
			&cli.StringFlag{
				Name:  "ip",
				Value: "0.0.0.0",
				Usage: "IP address to listen on",
			},
			&cli.StringFlag{
				Name:  "port",
				Value: "8443",
				Usage: "Port to listen on",
			},
			&cli.IntFlag{
				Name:  "numRi",
				Value: 61,
				Usage: "Number of routerInfos to include in each su3 file",
			},
			&cli.IntFlag{
				Name:  "numSu3",
				Value: 50,
				Usage: "Number of su3 files to build (0 = automatic based on size of netdb)",
			},
			&cli.StringFlag{
				Name:  "interval",
				Value: "90h",
				Usage: "Duration between SU3 cache rebuilds (ex. 12h, 15m)",
			},
			&cli.StringFlag{
				Name:  "prefix",
				Value: "",
				Usage: "Prefix path for the HTTP(S) server. (ex. /netdb)",
			},
			&cli.BoolFlag{
				Name:  "trustProxy",
				Usage: "If provided, we will trust the 'X-Forwarded-For' header in requests (ex. behind cloudflare)",
			},
			&cli.StringFlag{
				Name:  "blacklist",
				Value: "",
				Usage: "Path to a txt file containing a list of IPs to deny connections from.",
			},
			&cli.DurationFlag{
				Name:  "stats",
				Value: 0,
				Usage: "Periodically print memory stats.",
			},
			&cli.BoolFlag{
				Name:  "i2p",
				Usage: "Listen for reseed request inside the I2P network",
			},
			&cli.BoolFlag{
				Name:  "yes",
				Usage: "Automatically answer 'yes' to self-signed SSL generation",
			},
			&cli.StringFlag{
				Name:  "samaddr",
				Value: "127.0.0.1:7656",
				Usage: "Use this SAM address to set up I2P connections for in-network reseed",
			},
			&cli.StringSliceFlag{
				Name:  "friends",
				Value: cli.NewStringSlice(reseed.AllReseeds...),
				Usage: "Ping other reseed servers and display the result on the homepage to provide information about reseed uptime.",
			},
			&cli.StringFlag{
				Name:  "share-peer",
				Value: "",
				Usage: "Download the shared netDb content of another I2P router, over I2P",
			},
			&cli.StringFlag{
				Name:  "share-password",
				Value: "",
				Usage: "Password for downloading netDb content from another router. Required for share-peer to work.",
			},
			&cli.BoolFlag{
				Name:  "acme",
				Usage: "Automatically generate a TLS certificate with the ACME protocol, defaults to Let's Encrypt",
			},
			&cli.StringFlag{
				Name:  "acmeserver",
				Value: "https://acme-staging-v02.api.letsencrypt.org/directory",
				Usage: "Use this server to issue a certificate with the ACME protocol",
			},
			&cli.IntFlag{
				Name:  "ratelimit",
				Value: 4,
				Usage: "Maximum number of reseed bundle requests per-IP address, per-hour.",
			},
			&cli.IntFlag{
				Name:  "ratelimitweb",
				Value: 40,
				Usage: "Maxiumum number of web-visits per-IP address, per-hour",
			},
		},
	}
}

// CreateEepServiceKey generates new I2P keys for eepSite (hidden service) operation.
// It connects to the I2P SAM interface and creates a fresh key pair for hosting services
// on the I2P network. Returns the generated keys or an error if SAM connection fails.
func CreateEepServiceKey(c *cli.Context) (i2pkeys.I2PKeys, error) {
	// Connect to I2P SAM interface for key generation
	sam, err := sam3.NewSAM(c.String("samaddr"))
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	defer sam.Close()
	// Generate new I2P destination keys
	k, err := sam.NewKeys()
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	return k, err
}

// LoadKeys loads existing I2P keys from file or creates new ones if the file doesn't exist.
// This function handles the key management lifecycle for I2P services, automatically
// generating keys when needed and persisting them for reuse across restarts.
func LoadKeys(keysPath string, c *cli.Context) (i2pkeys.I2PKeys, error) {
	// Check if keys file exists, create new keys if not found
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		return createAndStoreNewKeys(keysPath, c)
	} else if err == nil {
		return loadExistingKeys(keysPath)
	} else {
		return i2pkeys.I2PKeys{}, err
	}
}

// createAndStoreNewKeys generates new I2P keys and saves them to the specified file path.
func createAndStoreNewKeys(keysPath string, c *cli.Context) (i2pkeys.I2PKeys, error) {
	keys, err := CreateEepServiceKey(c)
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}

	err = persistKeysToFile(keys, keysPath)
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}

	return keys, nil
}

// loadExistingKeys reads and parses I2P keys from an existing file.
func loadExistingKeys(keysPath string) (i2pkeys.I2PKeys, error) {
	file, err := os.Open(keysPath)
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	defer file.Close()

	keys, err := i2pkeys.LoadKeysIncompat(file)
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}

	return keys, nil
}

// persistKeysToFile writes I2P keys to the specified file path using the incompatible format.
func persistKeysToFile(keys i2pkeys.I2PKeys, keysPath string) error {
	file, err := os.Create(keysPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return i2pkeys.StoreKeysIncompat(keys, file)
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// reseedAction is the main entry point for the reseed command.
// It orchestrates the configuration and startup of the reseed server.
func reseedAction(c *cli.Context) error {
	// Validate required configuration parameters
	netdbDir, signerID, err := validateRequiredConfig(c)
	if err != nil {
		return err
	}

	// Setup remote NetDB sharing if configured
	if err := setupRemoteNetDBSharing(c); err != nil {
		return err
	}

	// Configure TLS certificates for all protocols
	tlsConfig, err := configureTLSCertificates(c)
	if err != nil {
		return err
	}

	// Setup I2P keys if I2P protocol is enabled
	i2pkey, err := setupI2PKeys(c, tlsConfig)
	if err != nil {
		return err
	}

	// Setup Onion keys if Onion protocol is enabled
	if err := setupOnionKeys(c, tlsConfig); err != nil {
		return err
	}

	// Parse configuration and setup signing keys
	reloadIntvl, privKey, err := setupSigningConfiguration(c, signerID)
	if err != nil {
		return err
	}

	// Initialize reseeder with configured parameters
	reseeder, err := initializeReseeder(c, netdbDir, signerID, privKey, reloadIntvl)
	if err != nil {
		return err
	}

	// Start all configured servers
	startConfiguredServers(c, tlsConfig, i2pkey, reseeder)
	return nil
}

// validateRequiredConfig validates and returns the required netdb and signer configuration.
func validateRequiredConfig(c *cli.Context) (string, string, error) {
	providedReseeds(c)

	netdbDir := c.String("netdb")
	if netdbDir == "" {
		fmt.Println("--netdb is required")
		return "", "", fmt.Errorf("--netdb is required")
	}

	signerID := c.String("signer")
	if signerID == "" || signerID == "you@mail.i2p" {
		fmt.Println("--signer is required")
		return "", "", fmt.Errorf("--signer is required")
	}

	if !strings.Contains(signerID, "@") {
		if !fileExists(signerID) {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return "", "", fmt.Errorf("--signer must be an email address or a file containing an email address.")
		}
		bytes, err := ioutil.ReadFile(signerID)
		if err != nil {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return "", "", fmt.Errorf("--signer must be an email address or a file containing an email address.")
		}
		signerID = string(bytes)
	}

	return netdbDir, signerID, nil
}

// setupRemoteNetDBSharing configures and starts remote NetDB downloading if share-peer is specified.
func setupRemoteNetDBSharing(c *cli.Context) error {
	if c.String("share-peer") != "" {
		count := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		for i := range count {
			err := downloadRemoteNetDB(c.String("share-peer"), c.String("share-password"), c.String("netdb"), c.String("samaddr"))
			if err != nil {
				lgr.WithError(err).WithField("attempt", i).WithField("attempts_remaining", 10-i).Warn("Error downloading remote netDb, retrying in 10 seconds")
				time.Sleep(time.Second * 10)
			} else {
				break
			}
		}
		go getSupplementalNetDb(c.String("share-peer"), c.String("share-password"), c.String("netdb"), c.String("samaddr"))
	}
	return nil
}

// tlsConfiguration holds TLS certificate configuration for different protocols.
type tlsConfiguration struct {
	tlsCert, tlsKey           string
	tlsHost                   string
	onionTlsCert, onionTlsKey string
	onionTlsHost              string
	i2pTlsCert, i2pTlsKey     string
	i2pTlsHost                string
}

// configureTLSCertificates sets up TLS certificates and keys for HTTP/HTTPS protocol.
func configureTLSCertificates(c *cli.Context) (*tlsConfiguration, error) {
	config := &tlsConfiguration{
		tlsHost: c.String("tlsHost"),
	}

	if config.tlsHost != "" {
		setupTLSHostConfiguration(config)
		setupTLSKeyPaths(c, config)
		setupTLSCertPaths(c, config)

		ignore := c.Bool("trustProxy")
		if !ignore {
			err := validateAndProvisionCertificates(c, config)
			if err != nil {
				return nil, err
			}
		}
	}

	return config, nil
}

// setupTLSHostConfiguration configures host settings for all TLS protocols.
func setupTLSHostConfiguration(config *tlsConfiguration) {
	config.onionTlsHost = config.tlsHost
	config.i2pTlsHost = config.tlsHost
}

// setupTLSKeyPaths configures TLS key file paths with defaults if not specified.
func setupTLSKeyPaths(c *cli.Context, config *tlsConfiguration) {
	config.tlsKey = c.String("tlsKey")
	if config.tlsKey == "" {
		defaultKeyPath := config.tlsHost + ".pem"
		config.tlsKey = defaultKeyPath
		config.onionTlsKey = defaultKeyPath
		config.i2pTlsKey = defaultKeyPath
	}
}

// setupTLSCertPaths configures TLS certificate file paths with defaults if not specified.
func setupTLSCertPaths(c *cli.Context, config *tlsConfiguration) {
	config.tlsCert = c.String("tlsCert")
	if config.tlsCert == "" {
		defaultCertPath := config.tlsHost + ".crt"
		config.tlsCert = defaultCertPath
		config.onionTlsCert = defaultCertPath
		config.i2pTlsCert = defaultCertPath
	}
}

// validateAndProvisionCertificates handles certificate validation and generation based on configuration.
func validateAndProvisionCertificates(c *cli.Context, config *tlsConfiguration) error {
	auto := c.Bool("yes")
	acme := c.Bool("acme")

	if acme {
		acmeserver := c.String("acmeserver")
		err := checkUseAcmeCert(config.tlsHost, "", acmeserver, &config.tlsCert, &config.tlsKey, auto)
		if err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}
	} else {
		err := checkOrNewTLSCert(config.tlsHost, &config.tlsCert, &config.tlsKey, auto)
		if err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}
	}
	return nil
}

// setupI2PKeys configures I2P keys and TLS certificates if I2P protocol is enabled.
func setupI2PKeys(c *cli.Context, tlsConfig *tlsConfiguration) (i2pkeys.I2PKeys, error) {
	var i2pkey i2pkeys.I2PKeys

	if !c.Bool("i2p") {
		return i2pkey, nil
	}

	var err error
	i2pkey, err = LoadKeys("reseed.i2pkeys", c)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	configureI2PTLSSettings(tlsConfig, i2pkey)

	if err := setupI2PTLSCertificate(c, tlsConfig); err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	return i2pkey, nil
}

// configureI2PTLSSettings configures TLS host and certificate paths for I2P connections.
// It sets default values based on the I2P key's base32 address if not already specified.
func configureI2PTLSSettings(tlsConfig *tlsConfiguration, i2pkey i2pkeys.I2PKeys) {
	if tlsConfig.i2pTlsHost == "" {
		tlsConfig.i2pTlsHost = i2pkey.Addr().Base32()
	}

	if tlsConfig.i2pTlsHost != "" {
		if tlsConfig.i2pTlsKey == "" {
			tlsConfig.i2pTlsKey = tlsConfig.i2pTlsHost + ".pem"
		}

		if tlsConfig.i2pTlsCert == "" {
			tlsConfig.i2pTlsCert = tlsConfig.i2pTlsHost + ".crt"
		}
	}
}

// setupI2PTLSCertificate ensures I2P TLS certificates are available if not using a trusted proxy.
// It checks or creates new TLS certificates based on the configuration settings.
func setupI2PTLSCertificate(c *cli.Context, tlsConfig *tlsConfiguration) error {
	if tlsConfig.i2pTlsHost == "" {
		return nil
	}

	auto := c.Bool("yes")
	ignore := c.Bool("trustProxy")
	if ignore {
		return nil
	}

	return checkOrNewTLSCert(tlsConfig.i2pTlsHost, &tlsConfig.i2pTlsCert, &tlsConfig.i2pTlsKey, auto)
}

// loadOrGenerateOnionKey loads an existing onion key from file or generates a new one.
func loadOrGenerateOnionKey(keyPath string) ([]byte, error) {
	if _, err := os.Stat(keyPath); err == nil {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return []byte(key.PrivateKey()), nil
}

// configureOnionTlsHost sets up the onion TLS hostname if not already configured.
func configureOnionTlsHost(tlsConfig *tlsConfiguration, onionKey []byte) {
	if tlsConfig.onionTlsHost == "" {
		tlsConfig.onionTlsHost = torutil.OnionServiceIDFromPrivateKey(ed25519.PrivateKey(onionKey)) + ".onion"
	}
}

// configureOnionTlsPaths sets up default paths for TLS key and certificate files.
func configureOnionTlsPaths(tlsConfig *tlsConfiguration) {
	if tlsConfig.onionTlsKey == "" {
		tlsConfig.onionTlsKey = tlsConfig.onionTlsHost + ".pem"
	}

	if tlsConfig.onionTlsCert == "" {
		tlsConfig.onionTlsCert = tlsConfig.onionTlsHost + ".crt"
	}
}

// setupOnionTlsCertificate creates or validates TLS certificates for onion services.
func setupOnionTlsCertificate(c *cli.Context, tlsConfig *tlsConfiguration) error {
	if tlsConfig.onionTlsHost == "" {
		return nil
	}

	auto := c.Bool("yes")
	ignore := c.Bool("trustProxy")
	if !ignore {
		return checkOrNewTLSCert(tlsConfig.onionTlsHost, &tlsConfig.onionTlsCert, &tlsConfig.onionTlsKey, auto)
	}
	return nil
}

// setupOnionKeys configures Onion service keys and TLS certificates if Onion protocol is enabled.
func setupOnionKeys(c *cli.Context, tlsConfig *tlsConfiguration) error {
	if !c.Bool("onion") {
		return nil
	}

	onionKey, err := loadOrGenerateOnionKey(c.String("onionKey"))
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	configureOnionTlsHost(tlsConfig, onionKey)

	err = ioutil.WriteFile(c.String("onionKey"), onionKey, 0o644)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	configureOnionTlsPaths(tlsConfig)

	err = setupOnionTlsCertificate(c, tlsConfig)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	return nil
}

// setupSigningConfiguration parses duration and sets up signing certificates.
func setupSigningConfiguration(c *cli.Context, signerID string) (time.Duration, *rsa.PrivateKey, error) {
	reloadIntvl, err := time.ParseDuration(c.String("interval"))
	if err != nil {
		fmt.Printf("'%s' is not a valid time interval.\n", reloadIntvl)
		return 0, nil, fmt.Errorf("'%s' is not a valid time interval.\n", reloadIntvl)
	}

	signerKey := c.String("key")
	if signerKey == "" {
		signerKey = signerFile(signerID) + ".pem"
	}

	auto := c.Bool("yes")
	privKey, err := getOrNewSigningCert(&signerKey, signerID, auto)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	return reloadIntvl, privKey, nil
}

// initializeReseeder creates and configures a new reseeder instance.
func initializeReseeder(c *cli.Context, netdbDir, signerID string, privKey *rsa.PrivateKey, reloadIntvl time.Duration) (*reseed.ReseederImpl, error) {
	routerInfoAge := c.Duration("routerInfoAge")
	netdb := reseed.NewLocalNetDb(netdbDir, routerInfoAge)

	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerID = []byte(signerID)
	reseeder.NumRi = c.Int("numRi")
	reseeder.NumSu3 = c.Int("numSu3")
	reseeder.RebuildInterval = reloadIntvl
	reseeder.Start()

	return reseeder, nil
}

// Context-aware server functions that return errors instead of calling Fatal
func reseedHTTPSWithContext(ctx context.Context, c *cli.Context, tlsCert, tlsKey string, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	lgr.WithField("address", server.Addr).Debug("HTTPS server started")
	return server.ListenAndServeTLS(tlsCert, tlsKey)
}

func reseedHTTPWithContext(ctx context.Context, c *cli.Context, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	lgr.WithField("address", server.Addr).Debug("HTTP server started")
	return server.ListenAndServe()
}

// setupOnionServer configures a new reseed server instance with blacklist support.
func setupOnionServer(c *cli.Context, reseeder *reseed.ReseederImpl) *reseed.Server {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	return server
}

// startStatsMonitoring begins memory statistics monitoring in a separate goroutine.
func startStatsMonitoring(ctx context.Context, c *cli.Context) {
	if c.Duration("stats") == 0 {
		return
	}

	go func() {
		var mem runtime.MemStats
		ticker := time.NewTicker(c.Duration("stats"))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}
	}()
}

// calculateOnionPort parses the port from context and increments it for onion service.
func calculateOnionPort(c *cli.Context) (int, error) {
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	return port + 1, nil
}

// createTorListenConf creates a Tor listen configuration with the specified parameters.
func createTorListenConf(port int, key ed25519.PrivateKey, remotePorts []int, singleOnion bool) *tor.ListenConf {
	return &tor.ListenConf{
		LocalPort:    port,
		Key:          key,
		RemotePorts:  remotePorts,
		Version3:     true,
		NonAnonymous: singleOnion,
		DiscardKey:   false,
	}
}

// handleOnionKeyBasedService manages onion service startup based on existing key file.
func handleOnionKeyBasedService(server *reseed.Server, c *cli.Context, port int, onionTlsCert, onionTlsKey string) error {
	ok, err := ioutil.ReadFile(c.String("onionKey"))
	if err != nil {
		return fmt.Errorf("failed to read onion key: %w", err)
	}

	singleOnion := c.Bool("singleOnion")
	if onionTlsCert != "" && onionTlsKey != "" {
		tlc := createTorListenConf(port, ed25519.PrivateKey(ok), []int{443}, singleOnion)
		return server.ListenAndServeOnionTLS(nil, tlc, onionTlsCert, onionTlsKey)
	} else {
		tlc := createTorListenConf(port, ed25519.PrivateKey(ok), []int{80}, singleOnion)
		return server.ListenAndServeOnion(nil, tlc)
	}
}

func reseedOnionWithContext(ctx context.Context, c *cli.Context, onionTlsCert, onionTlsKey string, reseeder *reseed.ReseederImpl) error {
	server := setupOnionServer(c, reseeder)
	startStatsMonitoring(ctx, c)

	port, err := calculateOnionPort(c)
	if err != nil {
		return err
	}

	if _, err := os.Stat(c.String("onionKey")); err == nil {
		return handleOnionKeyBasedService(server, c, port, onionTlsCert, onionTlsKey)
	} else if os.IsNotExist(err) {
		tlc := createTorListenConf(port, nil, []int{80}, c.Bool("singleOnion"))
		return server.ListenAndServeOnion(nil, tlc)
	}

	return fmt.Errorf("onion key file error: %w", err)
}

// reseedI2PWithContext starts an I2P reseed server using the SAM interface for network connectivity.
// It configures the server with rate limiting, blacklist filtering, and optional TLS support.
func reseedI2PWithContext(ctx context.Context, c *cli.Context, i2pTlsCert, i2pTlsKey string, i2pIdentKey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) error {
	server := configureI2PReseederServer(c, reseeder)

	configureServerBlacklist(server, c)

	startI2PStatsMonitoring(ctx, c)

	return startI2PServerListener(server, c, i2pTlsCert, i2pTlsKey, i2pIdentKey)
}

// configureI2PReseederServer creates and configures a new reseed server for I2P networking.
// It sets up rate limiting, network address, and basic server configuration.
func configureI2PReseederServer(c *cli.Context, reseeder *reseed.ReseederImpl) *reseed.Server {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))
	return server
}

// configureServerBlacklist sets up IP blacklist filtering for the server based on configuration.
// It loads blacklist entries from a file if specified in the configuration.
func configureServerBlacklist(server *reseed.Server, c *cli.Context) {
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if blacklistFile != "" {
		blacklist.LoadFile(blacklistFile)
	}
}

// startI2PStatsMonitoring launches a background goroutine to periodically log memory statistics for I2P.
// It respects the context cancellation and runs at the interval specified in configuration.
func startI2PStatsMonitoring(ctx context.Context, c *cli.Context) {
	if c.Duration("stats") == 0 {
		return
	}

	go func() {
		var mem runtime.MemStats
		ticker := time.NewTicker(c.Duration("stats"))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}
	}()
}

// startI2PServerListener starts the I2P server with optional TLS configuration.
// It chooses between TLS and non-TLS server variants based on certificate availability.
func startI2PServerListener(server *reseed.Server, c *cli.Context, i2pTlsCert, i2pTlsKey string, i2pIdentKey i2pkeys.I2PKeys) error {
	if i2pTlsCert != "" && i2pTlsKey != "" {
		return server.ListenAndServeI2PTLS(c.String("samaddr"), i2pIdentKey, i2pTlsCert, i2pTlsKey)
	} else {
		return server.ListenAndServeI2P(c.String("samaddr"), i2pIdentKey)
	}
}

// startOnionServer launches the onion server in a goroutine if enabled.
func startOnionServer(ctx context.Context, c *cli.Context, tlsConfig *tlsConfiguration, reseeder *reseed.ReseederImpl, wg *sync.WaitGroup, errChan chan<- error) {
	if !c.Bool("onion") {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		lgr.WithField("service", "onion").Debug("Onion server starting")
		if err := reseedOnionWithContext(ctx, c, tlsConfig.onionTlsCert, tlsConfig.onionTlsKey, reseeder); err != nil {
			select {
			case errChan <- fmt.Errorf("onion server error: %w", err):
			default:
			}
		}
	}()
}

// startI2PServer launches the I2P server in a goroutine if enabled.
func startI2PServer(ctx context.Context, c *cli.Context, tlsConfig *tlsConfiguration, i2pkey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl, wg *sync.WaitGroup, errChan chan<- error) {
	if !c.Bool("i2p") {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		lgr.WithField("service", "i2p").Debug("I2P server starting")
		if err := reseedI2PWithContext(ctx, c, tlsConfig.i2pTlsCert, tlsConfig.i2pTlsKey, i2pkey, reseeder); err != nil {
			select {
			case errChan <- fmt.Errorf("i2p server error: %w", err):
			default:
			}
		}
	}()
}

// startHTTPServer launches the appropriate HTTP/HTTPS server in a goroutine.
func startHTTPServer(ctx context.Context, c *cli.Context, tlsConfig *tlsConfiguration, reseeder *reseed.ReseederImpl, wg *sync.WaitGroup, errChan chan<- error) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runHTTPServerBasedOnConfig(ctx, c, tlsConfig, reseeder)
		if err != nil {
			sendErrorToChannel(errChan, err)
		}
	}()
}

// runHTTPServerBasedOnConfig determines whether to run HTTP or HTTPS server based on the trustProxy configuration.
// It starts the appropriate server type and returns any errors that occur during startup or operation.
func runHTTPServerBasedOnConfig(ctx context.Context, c *cli.Context, tlsConfig *tlsConfiguration, reseeder *reseed.ReseederImpl) error {
	if !c.Bool("trustProxy") {
		lgr.WithField("service", "https").Debug("HTTPS server starting")
		return reseedHTTPSWithContext(ctx, c, tlsConfig.tlsCert, tlsConfig.tlsKey, reseeder)
	} else {
		lgr.WithField("service", "http").Debug("HTTP server starting")
		return reseedHTTPWithContext(ctx, c, reseeder)
	}
}

// sendErrorToChannel safely sends an error to the error channel without blocking.
// It uses a select statement to prevent blocking if the channel is full.
func sendErrorToChannel(errChan chan<- error, err error) {
	formattedErr := fmt.Errorf("server error: %w", err)
	select {
	case errChan <- formattedErr:
	default:
	}
}

// setupServerContext initializes the context and error handling infrastructure for server coordination.
func setupServerContext() (context.Context, context.CancelFunc, *sync.WaitGroup, chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	errChan := make(chan error, 3) // Buffer for up to 3 server errors
	return ctx, cancel, &wg, errChan
}

// waitForServerCompletion coordinates server completion and error handling.
func waitForServerCompletion(wg *sync.WaitGroup, errChan chan error) {
	// Wait for first error or all servers to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Handle the first error that occurs
	if err := <-errChan; err != nil {
		lgr.WithError(err).Fatal("Fatal server error", err)
	}
}

// startConfiguredServers starts all enabled server protocols (Onion, I2P, HTTP/HTTPS) with proper coordination.
func startConfiguredServers(c *cli.Context, tlsConfig *tlsConfiguration, i2pkey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) {
	ctx, cancel, wg, errChan := setupServerContext()
	defer cancel()

	startOnionServer(ctx, c, tlsConfig, reseeder, wg, errChan)
	startI2PServer(ctx, c, tlsConfig, i2pkey, reseeder, wg, errChan)
	startHTTPServer(ctx, c, tlsConfig, reseeder, wg, errChan)

	waitForServerCompletion(wg, errChan)
}

func getSupplementalNetDb(remote, password, path, samaddr string) {
	log.Println("Remote NetDB Update Loop")
	for {
		if err := downloadRemoteNetDB(remote, password, path, samaddr); err != nil {
			log.Println("Error downloading remote netDb", err)
			time.Sleep(time.Second * 30)
		} else {
			log.Println("Success downloading remote netDb", err)
			time.Sleep(time.Minute * 30)
		}
	}
}

// normalizeRemoteURL ensures the remote URL has proper HTTP protocol and netDb.tar.gz suffix.
func normalizeRemoteURL(remote string) (string, error) {
	var hremote string
	if !strings.HasPrefix(remote, "http://") && !strings.HasPrefix(remote, "https://") {
		hremote = "http://" + remote
	} else {
		hremote = remote
	}
	if !strings.HasSuffix(hremote, ".tar.gz") {
		hremote += "/netDb.tar.gz"
	}
	return hremote, nil
}

// createGarlicHTTPClient creates an HTTP client configured to use I2P's SAM interface.
func createGarlicHTTPClient(samaddr, password string) (*http.Client, *onramp.Garlic, error) {
	garlic, err := onramp.NewGarlic("reseed-client", samaddr, onramp.OPT_WIDE)
	if err != nil {
		return nil, nil, err
	}

	transport := http.Transport{
		Dial: garlic.Dial,
	}
	client := http.Client{
		Transport: &transport,
	}
	return &client, garlic, nil
}

// downloadAndSaveNetDB downloads the netDb archive from the remote URL and saves it locally.
func downloadAndSaveNetDB(client *http.Client, url *url.URL, password string) error {
	httpRequest := http.Request{
		URL:    url,
		Header: http.Header{},
	}
	httpRequest.Header.Add(http.CanonicalHeaderKey("reseed-password"), password)
	httpRequest.Header.Add(http.CanonicalHeaderKey("x-user-agent"), reseed.I2pUserAgent)

	resp, err := client.Do(&httpRequest)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return ioutil.WriteFile("netDb.tar.gz", bodyBytes, 0o644)
}

// extractAndCopyNetDB extracts the netDb archive and copies it to the target directory.
func extractAndCopyNetDB(path string) error {
	dbPath := filepath.Join(path, "reseed-netDb")
	if err := untar.UntarFile("netDb.tar.gz", dbPath); err != nil {
		return err
	}

	opt := copy.Options{
		Skip: func(info os.FileInfo, src, dest string) (bool, error) {
			srcBase := filepath.Base(src)
			dstBase := filepath.Base(dest)
			if info.IsDir() {
				return false, nil
			}
			if srcBase == dstBase {
				log.Println("Ignoring existing RI", srcBase, dstBase)
				return true, nil
			}
			return false, nil
		},
	}

	if err := copy.Copy(dbPath, path, opt); err != nil {
		return err
	}

	// Clean up temporary files
	if err := os.RemoveAll(dbPath); err != nil {
		return err
	}
	return os.RemoveAll("netDb.tar.gz")
}

func downloadRemoteNetDB(remote, password, path, samaddr string) error {
	hremote, err := normalizeRemoteURL(remote)
	if err != nil {
		return err
	}

	url, err := url.Parse(hremote)
	if err != nil {
		return err
	}

	client, garlic, err := createGarlicHTTPClient(samaddr, password)
	if err != nil {
		return err
	}
	defer garlic.Close()

	if err := downloadAndSaveNetDB(client, url, password); err != nil {
		return err
	}

	return extractAndCopyNetDB(path)
}
