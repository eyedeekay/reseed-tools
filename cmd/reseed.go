package cmd

import (
	"context"
	"strings"

	//"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	"github.com/cretz/bine/torutil/ed25519"
	"github.com/eyedeekay/sam3"
	"github.com/eyedeekay/sam3/i2pkeys"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/urfave/cli"
	"i2pgit.org/idk/reseed-tools/reseed"

	"github.com/eyedeekay/checki2cp/getmeanetdb"
)

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

func NewReseedCommand() cli.Command {
	ndb, err := getmeanetdb.WhereIstheNetDB()
	if err != nil {
		log.Fatal(err)
	}
	return cli.Command{
		Name:   "reseed",
		Usage:  "Start a reseed server",
		Action: reseedAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "signer",
				Value: getDefaultSigner(),
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			cli.StringFlag{
				Name:  "tlsHost",
				Value: getHostName(),
				Usage: "The public hostname used on your TLS certificate",
			},
			cli.BoolFlag{
				Name:  "onion",
				Usage: "Present an onionv3 address",
			},
			cli.BoolFlag{
				Name:  "singleOnion",
				Usage: "Use a faster, but non-anonymous single-hop onion",
			},
			cli.StringFlag{
				Name:  "onionKey",
				Value: "onion.key",
				Usage: "Specify a path to an ed25519 private key for onion",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "Path to your su3 signing private key",
			},
			cli.StringFlag{
				Name:  "netdb",
				Value: ndb,
				Usage: "Path to NetDB directory containing routerInfos",
			},
			cli.StringFlag{
				Name:  "tlsCert",
				Usage: "Path to a TLS certificate",
			},
			cli.StringFlag{
				Name:  "tlsKey",
				Usage: "Path to a TLS private key",
			},
			cli.StringFlag{
				Name:  "ip",
				Value: "0.0.0.0",
				Usage: "IP address to listen on",
			},
			cli.StringFlag{
				Name:  "port",
				Value: "8443",
				Usage: "Port to listen on",
			},
			cli.IntFlag{
				Name:  "numRi",
				Value: 77,
				Usage: "Number of routerInfos to include in each su3 file",
			},
			cli.IntFlag{
				Name:  "numSu3",
				Value: 50,
				Usage: "Number of su3 files to build (0 = automatic based on size of netdb)",
			},
			cli.StringFlag{
				Name:  "interval",
				Value: "90h",
				Usage: "Duration between SU3 cache rebuilds (ex. 12h, 15m)",
			},
			cli.StringFlag{
				Name:  "prefix",
				Value: "",
				Usage: "Prefix path for the HTTP(S) server. (ex. /netdb)",
			},
			cli.BoolFlag{
				Name:  "trustProxy",
				Usage: "If provided, we will trust the 'X-Forwarded-For' header in requests (ex. behind cloudflare)",
			},
			cli.StringFlag{
				Name:  "blacklist",
				Value: "",
				Usage: "Path to a txt file containing a list of IPs to deny connections from.",
			},
			cli.DurationFlag{
				Name:  "stats",
				Value: 0,
				Usage: "Periodically print memory stats.",
			},
			cli.BoolFlag{
				Name:  "p2p",
				Usage: "Listen for reseed request via libp2p",
			},
			cli.BoolFlag{
				Name:  "i2p",
				Usage: "Listen for reseed request inside the I2P network",
			},
			cli.BoolFlag{
				Name:  "yes",
				Usage: "Automatically answer 'yes' to self-signed SSL generation",
			},
			cli.StringFlag{
				Name:  "samaddr",
				Value: "127.0.0.1:7656",
				Usage: "Use this SAM address to set up I2P connections for in-network reseed",
			},
			cli.BoolFlag{
				Name:  "acme",
				Usage: "Automatically generate a TLS certificate with the ACME protocol, defaults to Let's Encrypt",
			},
			cli.StringFlag{
				Name:  "acmeserver",
				Value: "https://acme-staging-v02.api.letsencrypt.org/directory",
				Usage: "Use this server to issue a certificate with the ACME protocol",
			},
			cli.BoolFlag{
				Name:  "yggdrasil",
				Usage: "Listen on the the Yggdrasil network to provide an alternate reseed",
			},
			cli.StringFlag{
				Name:  "yggconfig",
				Value: "yggdrasil.conf",
				Usage: "Path to the Yggdrasil configuration file",
			},
		},
	}
}

func CreateEepServiceKey(c *cli.Context) (i2pkeys.I2PKeys, error) {
	sam, err := sam3.NewSAM(c.String("samaddr"))
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	defer sam.Close()
	k, err := sam.NewKeys()
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	return k, err
}

func LoadKeys(keysPath string, c *cli.Context) (i2pkeys.I2PKeys, error) {
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		keys, err := CreateEepServiceKey(c)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		file, err := os.Create(keysPath)
		defer file.Close()
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		err = i2pkeys.StoreKeysIncompat(keys, file)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		return keys, nil
	} else if err == nil {
		file, err := os.Open(keysPath)
		defer file.Close()
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		keys, err := i2pkeys.LoadKeysIncompat(file)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		return keys, nil
	} else {
		return i2pkeys.I2PKeys{}, err
	}
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

func reseedAction(c *cli.Context) {
	netdbDir := c.String("netdb")
	if netdbDir == "" {
		fmt.Println("--netdb is required")
		return
	}

	signerID := c.String("signer")
	if signerID == "" || signerID == "you@mail.i2p" {
		fmt.Println("--signer is required")
		return
	}
	if !strings.Contains(signerID, "@") {
		if !fileExists(signerID) {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return
		}
		bytes, err := ioutil.ReadFile(signerID)
		if err != nil {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return
		}
		signerID = string(bytes)
	}

	var tlsCert, tlsKey string
	tlsHost := c.String("tlsHost")
	onionTlsHost := ""
	var onionTlsCert, onionTlsKey string
	i2pTlsHost := ""
	var i2pTlsCert, i2pTlsKey string
	var i2pkey i2pkeys.I2PKeys

	if tlsHost != "" {
		onionTlsHost = tlsHost
		i2pTlsHost = tlsHost
		tlsKey = c.String("tlsKey")
		// if no key is specified, default to the host.pem in the current dir
		if tlsKey == "" {
			tlsKey = tlsHost + ".pem"
			onionTlsKey = tlsHost + ".pem"
			i2pTlsKey = tlsHost + ".pem"
		}

		tlsCert = c.String("tlsCert")
		// if no certificate is specified, default to the host.crt in the current dir
		if tlsCert == "" {
			tlsCert = tlsHost + ".crt"
			onionTlsCert = tlsHost + ".crt"
			i2pTlsCert = tlsHost + ".crt"
		}

		// prompt to create tls keys if they don't exist?
		auto := c.Bool("yes")
		ignore := c.Bool("ignore")
		if !ignore {
			// use ACME?
			acme := c.Bool("acme")
			if acme {
				acmeserver := c.String("acmeserver")
				err := checkUseAcmeCert(tlsHost, signerID, acmeserver, &tlsCert, &tlsKey, auto)
				if nil != err {
					log.Fatalln(err)
				}
			} else {
				err := checkOrNewTLSCert(tlsHost, &tlsCert, &tlsKey, auto)
				if nil != err {
					log.Fatalln(err)
				}
			}
		}

	}

	if c.Bool("i2p") {
		var err error
		i2pkey, err = LoadKeys("reseed.i2pkeys", c)
		if err != nil {
			log.Fatalln(err)
		}
		if i2pTlsHost == "" {
			i2pTlsHost = i2pkey.Addr().Base32()
		}
		if i2pTlsHost != "" {
			// if no key is specified, default to the host.pem in the current dir
			if i2pTlsKey == "" {
				i2pTlsKey = i2pTlsHost + ".pem"
			}

			// if no certificate is specified, default to the host.crt in the current dir
			if i2pTlsCert == "" {
				i2pTlsCert = i2pTlsHost + ".crt"
			}

			// prompt to create tls keys if they don't exist?
			auto := c.Bool("yes")
			ignore := c.Bool("trustProxy")
			if !ignore {
				err := checkOrNewTLSCert(i2pTlsHost, &i2pTlsCert, &i2pTlsKey, auto)
				if nil != err {
					log.Fatalln(err)
				}
			}
		}
	}

	if c.Bool("onion") {
		var ok []byte
		var err error
		if _, err = os.Stat(c.String("onionKey")); err == nil {
			ok, err = ioutil.ReadFile(c.String("onionKey"))
			if err != nil {
				log.Fatalln(err.Error())
			}
		} else {
			key, err := ed25519.GenerateKey(nil)
			if err != nil {
				log.Fatalln(err.Error())
			}
			ok = []byte(key.PrivateKey())
		}
		if onionTlsHost == "" {
			onionTlsHost = torutil.OnionServiceIDFromPrivateKey(ed25519.PrivateKey(ok)) + ".onion"
		}
		err = ioutil.WriteFile(c.String("onionKey"), ok, 0644)
		if err != nil {
			log.Fatalln(err.Error())
		}
		if onionTlsHost != "" {
			// if no key is specified, default to the host.pem in the current dir
			if onionTlsKey == "" {
				onionTlsKey = onionTlsHost + ".pem"
			}

			// if no certificate is specified, default to the host.crt in the current dir
			if onionTlsCert == "" {
				onionTlsCert = onionTlsHost + ".crt"
			}

			// prompt to create tls keys if they don't exist?
			auto := c.Bool("yes")
			ignore := c.Bool("trustProxy")
			if !ignore {
				err := checkOrNewTLSCert(onionTlsHost, &onionTlsCert, &onionTlsKey, auto)
				if nil != err {
					log.Fatalln(err)
				}
			}
		}
	}

	reloadIntvl, err := time.ParseDuration(c.String("interval"))
	if nil != err {
		fmt.Printf("'%s' is not a valid time interval.\n", reloadIntvl)
		return
	}

	signerKey := c.String("key")
	// if no key is specified, default to the signerID.pem in the current dir
	if signerKey == "" {
		signerKey = signerFile(signerID) + ".pem"
	}

	// load our signing privKey
	auto := c.Bool("yes")
	privKey, err := getOrNewSigningCert(&signerKey, signerID, auto)
	if nil != err {
		log.Fatalln(err)
	}

	// create a local file netdb provider
	netdb := reseed.NewLocalNetDb(netdbDir)

	// create a reseeder
	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerID = []byte(signerID)
	reseeder.NumRi = c.Int("numRi")
	reseeder.NumSu3 = c.Int("numSu3")
	reseeder.RebuildInterval = reloadIntvl
	reseeder.Start()

	// create a server

	if c.Bool("onion") {
		log.Printf("Onion server starting\n")
		if tlsHost != "" && tlsCert != "" && tlsKey != "" {
			go reseedOnion(c, onionTlsCert, onionTlsKey, reseeder)
		} else {
			reseedOnion(c, onionTlsCert, onionTlsKey, reseeder)
		}
	}
	if c.Bool("i2p") {
		log.Printf("I2P server starting\n")
		if tlsHost != "" && tlsCert != "" && tlsKey != "" {
			go reseedI2P(c, i2pTlsCert, i2pTlsKey, i2pkey, reseeder)
		} else {
			reseedI2P(c, i2pTlsCert, i2pTlsKey, i2pkey, reseeder)
		}
	}
	if c.Bool("p2p") {
		log.Printf("libP2P listener starting\n")
		if tlsHost != "" && tlsCert != "" && tlsKey != "" {
			go reseedP2P(c, reseeder)
		} else {
			reseedP2P(c, reseeder)
		}
	}
	if !c.Bool("trustProxy") {
		log.Printf("HTTPS server starting\n")
		reseedHTTPS(c, tlsCert, tlsKey, reseeder)
	} else {
		log.Printf("HTTP server starting on\n")
		reseedHTTP(c, reseeder)
	}
}

func reseedHTTPS(c *cli.Context, tlsCert, tlsKey string, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	log.Printf("HTTPS server started on %s\n", server.Addr)
	if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		log.Fatalln(err)
	}
}

func reseedHTTP(c *cli.Context, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	log.Printf("HTTP server started on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalln(err)
	}
}

func makeRandomHost(port int) (host.Host, error) {
	host, err := libp2p.New(context.Background(), libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port)))
	if err != nil {
		return nil, err
	}
	return host, nil
}

func reseedYggdrasil(c *cli.Context, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	if err := server.ListenAndServeYggdrasil(); err != nil {
		log.Fatalln(err)
	}
	log.Printf("Yggdrasil listener started on %s\n", server.YggdrasilAddr())
}

func reseedP2P(c *cli.Context, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		log.Fatalln(err.Error())
	}
	port += 2
	host, err := makeRandomHost(port)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("P2P listener started on %s\n", host.ID())
	if err := server.ListenAndServeLibP2P(host); err != nil {
		log.Fatalln(err)
	}
}

func reseedOnion(c *cli.Context, onionTlsCert, onionTlsKey string, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		log.Fatalln(err.Error())
	}
	port += 1
	if _, err := os.Stat(c.String("onionKey")); err == nil {
		ok, err := ioutil.ReadFile(c.String("onionKey"))
		if err != nil {
			log.Fatalln(err.Error())
		} else {
			if onionTlsCert != "" && onionTlsKey != "" {
				tlc := &tor.ListenConf{
					LocalPort:    port,
					Key:          ed25519.PrivateKey(ok),
					RemotePorts:  []int{443},
					Version3:     true,
					NonAnonymous: c.Bool("singleOnion"),
					DiscardKey:   false,
				}
				if err := server.ListenAndServeOnionTLS(nil, tlc, onionTlsCert, onionTlsKey); err != nil {
					log.Fatalln(err)
				}
			} else {
				tlc := &tor.ListenConf{
					LocalPort:    port,
					Key:          ed25519.PrivateKey(ok),
					RemotePorts:  []int{80},
					Version3:     true,
					NonAnonymous: c.Bool("singleOnion"),
					DiscardKey:   false,
				}
				if err := server.ListenAndServeOnion(nil, tlc); err != nil {
					log.Fatalln(err)
				}

			}
		}
	} else if os.IsNotExist(err) {
		tlc := &tor.ListenConf{
			LocalPort:    port,
			RemotePorts:  []int{80},
			Version3:     true,
			NonAnonymous: c.Bool("singleOnion"),
			DiscardKey:   false,
		}
		if err := server.ListenAndServeOnion(nil, tlc); err != nil {
			log.Fatalln(err)
		}
	}
	log.Printf("Onion server started on %s\n", server.Addr)
}

func reseedI2P(c *cli.Context, i2pTlsCert, i2pTlsKey string, i2pIdentKey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) {
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

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				log.Printf("TotalAllocs: %d Kb, Allocs: %d Kb, Mallocs: %d, NumGC: %d", mem.TotalAlloc/1024, mem.Alloc/1024, mem.Mallocs, mem.NumGC)
			}
		}()
	}
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		log.Fatalln(err.Error())
	}
	port += 1
	if i2pTlsCert != "" && i2pTlsKey != "" {
		if err := server.ListenAndServeI2PTLS(c.String("samaddr"), i2pIdentKey, i2pTlsCert, i2pTlsKey); err != nil {
			log.Fatalln(err)
		}
	} else {
		if err := server.ListenAndServeI2P(c.String("samaddr"), i2pIdentKey); err != nil {
			log.Fatalln(err)
		}

	}

	log.Printf("Onion server started on %s\n", server.Addr)
}
