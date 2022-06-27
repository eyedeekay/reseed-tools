package reseed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/eyedeekay/sam3"
	"github.com/eyedeekay/sam3/i2pkeys"
	"github.com/gorilla/handlers"
	"github.com/hjson/hjson-go"
	"github.com/justinas/alice"
	"github.com/libp2p/go-libp2p-core/host"
	gostream "github.com/libp2p/go-libp2p-gostream"
	p2phttp "github.com/libp2p/go-libp2p-http"

	"github.com/mitchellh/mapstructure"
	throttled "github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/defaults"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"golang.org/x/text/encoding/unicode"
)

const (
	i2pUserAgent = "Wget/1.11.4"
)

type Server struct {
	*http.Server
	I2P           *sam3.SAM
	I2PSession    *sam3.StreamSession
	I2PListener   *sam3.StreamListener
	I2PKeys       i2pkeys.I2PKeys
	Reseeder      *ReseederImpl
	Blacklist     *Blacklist
	OnionListener *tor.OnionService
	YggdrasilConf string
	yggdrasilNode *node
	acceptables   map[string]time.Time
}
type node struct {
	core      *core.Core
	config    *config.NodeConfig
	multicast *multicast.Multicast
	//tuntap    *tuntap.TunAdapter
	//admin     *admin.AdminSocket
}

func NewServer(prefix string, trustProxy bool) *Server {
	config := &tls.Config{
		//		MinVersion:               tls.VersionTLS10,
		//		PreferServerCipherSuites: true,
		//		CipherSuites: []uint16{
		//			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		//			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		//			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		//			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		//			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		//			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		//			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		//			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		//		},
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

	th := throttled.RateLimit(throttled.PerHour(4), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(200000))
	thw := throttled.RateLimit(throttled.PerHour(30), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(200000))

	middlewareChain := alice.New()
	if trustProxy {
		middlewareChain = middlewareChain.Append(proxiedMiddleware)
	}

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write(nil); nil != err {
			log.Println(err)
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware, thw.Throttle, server.browsingMiddleware).Then(errorHandler))
	mux.Handle(prefix+"/i2pseeds.su3", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware, verifyMiddleware, th.Throttle).Then(http.HandlerFunc(server.reseedHandler)))
	server.Handler = mux

	return &server
}

// See use of crypto/rand on:
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 52 possibilities
	letterIdxBits = 6                                                      // 6 bits to represent 64 possibilities / indexes
	letterIdxMask = 1<<letterIdxBits - 1                                   // All 1-bits, as many as letterIdxBits
)

func SecureRandomAlphaString() string {
	length := 16
	result := make([]byte, length)
	bufferSize := int(float64(length) * 1.3)
	for i, j, randomBytes := 0, 0, []byte{}; i < length; j++ {
		if j%bufferSize == 0 {
			randomBytes = SecureRandomBytes(bufferSize)
		}
		if idx := int(randomBytes[j%length] & letterIdxMask); idx < len(letterBytes) {
			result[i] = letterBytes[idx]
			i++
		}
	}
	return string(result)
}

// SecureRandomBytes returns the requested number of bytes using crypto/rand
func SecureRandomBytes(length int) []byte {
	var randomBytes = make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal("Unable to generate random bytes")
	}
	return randomBytes
}

//

func (srv *Server) Acceptable() string {
	if srv.acceptables == nil {
		srv.acceptables = make(map[string]time.Time)
	}
	if len(srv.acceptables) > 50 {
		for val := range srv.acceptables {
			srv.CheckAcceptable(val)
		}
		for val := range srv.acceptables {
			if len(srv.acceptables) < 50 {
				break
			}
			delete(srv.acceptables, val)
		}
	}
	acceptme := SecureRandomAlphaString()
	srv.acceptables[acceptme] = time.Now()
	return acceptme
}

func (srv *Server) CheckAcceptable(val string) bool {
	if srv.acceptables == nil {
		srv.acceptables = make(map[string]time.Time)
	}
	if timeout, ok := srv.acceptables[val]; ok {
		checktime := time.Now().Sub(timeout)
		if checktime > (4 * time.Minute) {
			delete(srv.acceptables, val)
			return false
		}
		delete(srv.acceptables, val)
		return true
	}
	return false
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return srv.Serve(newBlacklistListener(ln, srv.Blacklist))
}

func (srv *Server) YggdrasilConfigFile() (*config.NodeConfig, error) {
	var conf []byte
	var err error
	if srv.YggdrasilConf != "" {
		conf, err = ioutil.ReadFile(srv.YggdrasilConf)
	} else {
		conf, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		return nil, err
	}
	if bytes.Equal(conf[0:2], []byte{0xFF, 0xFE}) ||
		bytes.Equal(conf[0:2], []byte{0xFE, 0xFF}) {
		utf := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
		decoder := utf.NewDecoder()
		conf, err = decoder.Bytes(conf)
		if err != nil {
			return nil, err
		}
	}
	cfg := defaults.GenerateConfig()
	var dat map[string]interface{}
	if err := hjson.Unmarshal(conf, &dat); err != nil {
		return nil, err
	}
	// Sanitise the config
	confJson, err := json.Marshal(dat)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(confJson, &cfg); err != nil {
		return nil, err
	}
	// Overlay our newly mapped configuration onto the autoconf node config that
	// we generated above.
	if err = mapstructure.Decode(dat, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (srv *Server) ListenAndServeYggdrasil() error {
	cfg, err := srv.YggdrasilConfigFile()
	if err != nil {
		return err
	}
	srv.yggdrasilNode.core = &core.Core{}
	if err = srv.yggdrasilNode.core.Start(cfg, nil); err != nil {
		return err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var interf net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if addrs, err := iface.MulticastAddrs(); addrs == nil || err != nil {
			continue
		}
		interf = iface
	}
	addrs, err := interf.MulticastAddrs()
	if err != nil {
		return err
	}
	addr := addrs[0].(*net.IPAddr)
	srv.yggdrasilNode.multicast = &multicast.Multicast{}
	srv.yggdrasilNode.multicast.Init(srv.yggdrasilNode.core, srv.yggdrasilNode.config, nil, nil)
	// get a random port above say, 40000
	port := 40000 + int(mrand.Int31n(10000))
	url, err := url.Parse("tcp://" + addr.IP.String() + fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	ln, err := srv.yggdrasilNode.core.Listen(url, "")
	if err != nil {
		return err
	}
	return srv.Serve(newBlacklistListener(ln.Listener, srv.Blacklist))
}

func (srv *Server) YggdrasilAddr() string {
	return srv.yggdrasilNode.core.Address().String()
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}

	if srv.TLSConfig.NextProtos == nil {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	var err error
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(newBlacklistListener(ln, srv.Blacklist), srv.TLSConfig)
	return srv.Serve(tlsListener)
}

func (srv *Server) ListenAndServeOnionTLS(startConf *tor.StartConf, listenConf *tor.ListenConf, certFile, keyFile string) error {
	log.Println("Starting and registering OnionV3 HTTPS service, please wait a couple of minutes...")
	tor, err := tor.Start(nil, startConf)
	if err != nil {
		return err
	}
	defer tor.Close()

	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	srv.OnionListener, err = tor.Listen(listenCtx, listenConf)
	if err != nil {
		return err
	}
	srv.Addr = srv.OnionListener.ID
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{
			ServerName: srv.OnionListener.ID,
		}
	}

	if srv.TLSConfig.NextProtos == nil {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	//	var err error
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	log.Printf("Onionv3 server started on https://%v.onion\n", srv.OnionListener.ID)

	//	tlsListener := tls.NewListener(newBlacklistListener(srv.OnionListener, srv.Blacklist), srv.TLSConfig)
	tlsListener := tls.NewListener(srv.OnionListener, srv.TLSConfig)

	return srv.Serve(tlsListener)
}

func (srv *Server) ListenAndServeOnion(startConf *tor.StartConf, listenConf *tor.ListenConf) error {
	log.Println("Starting and registering OnionV3 service, please wait a couple of minutes...")
	tor, err := tor.Start(nil, startConf)
	if err != nil {
		return err
	}
	defer tor.Close()

	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()
	srv.OnionListener, err = tor.Listen(listenCtx, listenConf)
	if err != nil {
		return err
	}

	log.Printf("Onionv3 server started on http://%v.onion\n", srv.OnionListener.ID)
	return srv.Serve(srv.OnionListener)
}

func (srv *Server) ListenAndServeI2PTLS(samaddr string, I2PKeys i2pkeys.I2PKeys, certFile, keyFile string) error {
	log.Println("Starting and registering I2P HTTPS service, please wait a couple of minutes...")
	var err error
	srv.I2P, err = sam3.NewSAM(samaddr)
	if err != nil {
		return err
	}
	srv.I2PSession, err = srv.I2P.NewStreamSession("", I2PKeys, []string{})
	if err != nil {
		return err
	}
	srv.I2PListener, err = srv.I2PSession.Listen()
	if err != nil {
		return err
	}
	srv.Addr = srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32()
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{
			ServerName: srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32(),
		}
	}

	if srv.TLSConfig.NextProtos == nil {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	//	var err error
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	log.Printf("I2P server started on https://%v\n", srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32())

	//	tlsListener := tls.NewListener(newBlacklistListener(srv.OnionListener, srv.Blacklist), srv.TLSConfig)
	tlsListener := tls.NewListener(srv.I2PListener, srv.TLSConfig)

	return srv.Serve(tlsListener)
}

func (srv *Server) ListenAndServeI2P(samaddr string, I2PKeys i2pkeys.I2PKeys) error {
	log.Println("Starting and registering I2P service, please wait a couple of minutes...")
	var err error
	srv.I2P, err = sam3.NewSAM(samaddr)
	if err != nil {
		return err
	}
	srv.I2PSession, err = srv.I2P.NewStreamSession("", I2PKeys, []string{})
	if err != nil {
		return err
	}
	srv.I2PListener, err = srv.I2PSession.Listen()
	if err != nil {
		return err
	}
	log.Printf("I2P server started on http://%v.b32.i2p\n", srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32())
	return srv.Serve(srv.I2PListener)
}

// ListenAndServeLibP2P is used to serve the reseed server over libp2p http connections
func (srv *Server) ListenAndServeLibP2P(hst host.Host) error {
	listener, err := gostream.Listen(hst, p2phttp.DefaultP2PProtocol)
	if err != nil {
		return err
	}
	return srv.Serve(listener)
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
		}
		if i2pUserAgent != r.UserAgent() {
			srv.HandleARealBrowser(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func verifyMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if i2pUserAgent != r.UserAgent() {
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
