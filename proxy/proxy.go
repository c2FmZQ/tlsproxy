// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package proxy implements a simple lightweight TLS termination proxy that uses
// Let's Encrypt to provide TLS encryption for any number of TCP and HTTP
// servers and server names concurrently on the same port.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/autocertcache"
	"github.com/c2FmZQ/storage/crypto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	yaml "gopkg.in/yaml.v3"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	startTimeKey     = "s"
	handshakeDoneKey = "h"
	dialDoneKey      = "d"
	serverNameKey    = "sn"
	protoKey         = "p"
	subjectKey       = "sub"
	internalConnKey  = "ic"
	reportEndKey     = "re"
	backendKey       = "be"
)

var (
	errAccessDenied = errors.New("access denied")
)

// Proxy receives TLS connections and forwards them to the configured
// backends.
type Proxy struct {
	certManager interface {
		HTTPHandler(fallback http.Handler) http.Handler
		TLSConfig() *tls.Config
	}
	cfg      *Config
	ctx      context.Context
	cancel   func()
	listener net.Listener

	mu            sync.Mutex
	connClosed    *sync.Cond
	defServerName string
	backends      map[string]*Backend
	connections   map[connKey]*netw.Conn

	metrics map[string]*backendMetrics
	events  map[string]int64
}

type connKey struct {
	dst net.Addr
	src net.Addr
}

type backendMetrics struct {
	numConnections   int64
	numBytesSent     int64
	numBytesReceived int64
}

// New returns a new initialized Proxy.
func New(cfg *Config, passphrase []byte) (*Proxy, error) {
	opts := []crypto.Option{
		crypto.WithAlgo(crypto.PickFastest),
		crypto.WithLogger(logger{}),
	}
	mkFile := filepath.Join(cfg.CacheDir, "masterkey")
	mk, err := crypto.ReadMasterKey(passphrase, mkFile, opts...)
	if errors.Is(err, os.ErrNotExist) {
		if mk, err = crypto.CreateMasterKey(opts...); err != nil {
			return nil, errors.New("failed to create master key")
		}
		err = mk.Save(passphrase, mkFile)
	}
	if err != nil {
		return nil, fmt.Errorf("masterkey: %w", err)
	}
	p := &Proxy{
		certManager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocertcache.New("autocert", storage.New(cfg.CacheDir, mk)),
			Email:  cfg.Email,
		},
		connections: make(map[connKey]*netw.Conn),
	}
	p.Reconfigure(cfg)
	return p, nil
}

// NewTestProxy returns a test Proxy that uses an internal certificate manager
// instead of letsencrypt.
func NewTestProxy(cfg *Config) (*Proxy, error) {
	cm, err := certmanager.New("root-ca.example.com", func(fmt string, args ...interface{}) {
		log.Printf("DBG CertManager: "+fmt, args...)
	})
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		certManager: cm,
		connections: make(map[connKey]*netw.Conn),
	}
	p.Reconfigure(cfg)
	return p, nil
}

// Reconfigure updates the proxy's configuration. Some parameters cannot be
// changed after Start has been called, e.g. HTTPAddr, TLSAddr, CacheDir.
func (p *Proxy) Reconfigure(cfg *Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, _ := yaml.Marshal(p.cfg)
	b, _ := yaml.Marshal(cfg)
	if bytes.Equal(a, b) {
		return nil
	}
	if err := cfg.Check(); err != nil {
		return err
	}
	if p.cfg != nil {
		log.Print("INF Configuration changed")
	}

	p.defServerName = cfg.DefaultServerName
	backends := make(map[string]*Backend, len(cfg.Backends))
	for _, be := range cfg.Backends {
		for _, sn := range be.ServerNames {
			backends[sn] = be
		}
		tc := p.baseTLSConfig()
		if be.ClientAuth {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
			if be.ClientCAs != "" {
				c, err := loadCerts(be.ClientCAs)
				if err != nil {
					return err
				}
				tc.ClientCAs = c
			}
			tc.VerifyConnection = func(cs tls.ConnectionState) error {
				be, err := p.backend(cs.ServerName)
				if err != nil {
					return err
				}
				if !be.ClientAuth {
					return nil
				}
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no certificate")
				}
				subject := cs.PeerCertificates[0].Subject.String()
				if err := be.authorize(subject); err != nil {
					p.recordEvent(fmt.Sprintf("deny [%s] to %s", subject, cs.ServerName))
					return fmt.Errorf("%w [%s]", err, subject)
				}
				if subject != "" {
					p.recordEvent(fmt.Sprintf("allow [%s] to %s", subject, cs.ServerName))
				}
				return nil
			}
		}
		if be.ALPNProtos != nil {
			tc.NextProtos = *be.ALPNProtos
		}
		be.tlsConfig = tc
		if be.ForwardRootCAs != "" {
			c, err := loadCerts(be.ForwardRootCAs)
			if err != nil {
				return err
			}
			be.forwardRootCAs = c
		}
		switch be.Mode {
		case ModeConsole:
			mux := http.NewServeMux()
			mux.HandleFunc("/", p.metricsHandler)
			mux.HandleFunc("/favicon.ico", p.faviconHandler)
			mux.HandleFunc("/config", p.configHandler)
			addPProfHandlers(mux)

			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(
				http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					logRequest(req)
					mux.ServeHTTP(w, req)
				}),
				be.httpConnChan,
			)

		case ModeHTTP, ModeHTTPS:
			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.reverseProxy(), be.httpConnChan)
		}
	}
	if p.cfg != nil {
		for _, be := range p.cfg.Backends {
			be.close(p.ctx)
		}
	}
	p.backends = backends
	p.cfg = cfg
	return nil
}

// Start starts a TLS proxy with the given configuration. The proxy runs
// in background until the context is canceled.
func (p *Proxy) Start(ctx context.Context) error {
	p.connClosed = sync.NewCond(&p.mu)
	var httpServer *http.Server
	if p.cfg.HTTPAddr != "" {
		httpServer = &http.Server{
			Handler: p.certManager.HTTPHandler(nil),
		}
		httpListener, err := net.Listen("tcp", p.cfg.HTTPAddr)
		if err != nil {
			return err
		}
		httpServer.SetKeepAlivesEnabled(false)
		go serveHTTP(httpServer, httpListener)
	}

	listener, err := netw.Listen("tcp", p.cfg.TLSAddr)
	if err != nil {
		return err
	}
	p.listener = listener
	p.ctx, p.cancel = context.WithCancel(ctx)

	go p.ctxWait(httpServer)
	go p.acceptLoop()
	return nil
}

func (p *Proxy) ctxWait(s *http.Server) {
	<-p.ctx.Done()
	if s != nil {
		s.Close()
	}
	p.Stop()
}

func (p *Proxy) acceptLoop() {
	log.Printf("INF Accepting TLS connections on %s", p.listener.Addr())
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Print("INF Accept loop terminated")
				break
			}
			log.Printf("ERR Accept: %v", err)
			continue
		}
		go p.handleConnection(conn.(*netw.Conn))
	}
}

// Stop closes all connections and stops all goroutines.
func (p *Proxy) Stop() {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.listener.Close()
	backends := p.cfg.Backends
	p.cfg.Backends = nil
	conns := make([]net.Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, be := range backends {
		be.close(nil)
	}
	for _, conn := range conns {
		conn.Close()
	}
}

// Shutdown gracefully shuts down the proxy, waiting for all existing
// connections to close or ctx to be canceled.
func (p *Proxy) Shutdown(ctx context.Context) {
	p.mu.Lock()
	p.listener.Close()
	for _, be := range p.cfg.Backends {
		be.close(ctx)
	}
	p.mu.Unlock()

	done := make(chan struct{})
	go func() {
		connLeft := func() bool {
			for _, c := range p.connections {
				if mode := connMode(c); mode != ModeTCP && mode != ModeTLS && mode != ModeTLSPassthrough {
					return true
				}
			}
			return false
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		for connLeft() {
			p.connClosed.Wait()
		}
		close(done)
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
	p.Stop()
}

func (p *Proxy) baseTLSConfig() *tls.Config {
	tc := p.certManager.TLSConfig()
	getCert := tc.GetCertificate
	tc.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			hello.ServerName = p.defaultServerName()
		}
		return getCert(hello)
	}
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	tc.NextProtos = []string{
		"h2", "http/1.1",
	}
	tc.MinVersion = tls.VersionTLS12
	return tc
}

func (p *Proxy) handleConnection(conn *netw.Conn) {
	defer func() {
		if r := recover(); r != nil {
			p.recordEvent("panic")
			log.Printf("ERR [%s] %s: PANIC: %v", connSubject(conn), conn.RemoteAddr(), r)
			conn.Close()
		}
	}()
	closeConnNeeded := true
	defer func() {
		if closeConnNeeded {
			conn.Close()
		}
	}()
	conn.SetAnnotation(startTimeKey, time.Now())
	numOpen := p.addConn(conn)
	conn.OnClose(func() {
		p.removeConn(conn)
		if conn.Annotation(reportEndKey, false).(bool) {
			startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
			log.Printf("END %s; Dur:%s Recv:%d Sent:%d",
				formatConnDesc(conn), time.Since(startTime).Truncate(time.Millisecond),
				conn.BytesReceived(), conn.BytesSent())
		}
		if be := connBackend(conn); be != nil {
			be.incInFlight(-1)
		}
		p.connClosed.Broadcast()
	})
	if numOpen >= p.cfg.MaxOpen {
		p.recordEvent("too many open connections")
		log.Printf("ERR [-] %s: too many open connections: %d >= %d", conn.RemoteAddr(), numOpen, p.cfg.MaxOpen)
		sendCloseNotify(conn)
		return
	}
	setKeepAlive(conn)

	hello, err := peekClientHello(conn)
	if err != nil {
		p.recordEvent("invalid ClientHello")
		log.Printf("BAD [-] %s ➔  %q: invalid ClientHello: %v", conn.RemoteAddr(), hello.ServerName, err)
		return
	}
	serverName := hello.ServerName
	if serverName == "" {
		p.recordEvent("no SNI")
		serverName = p.defaultServerName()
	}
	conn.SetAnnotation(serverNameKey, serverName)

	be, err := p.backend(serverName)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("BAD [-] %s ➔  %q: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return
	}
	conn.SetAnnotation(backendKey, be)
	be.incInFlight(1)
	switch {
	case be.Mode == ModeTLSPassthrough:
		if err := p.checkIP(conn); err != nil {
			return
		}
		p.handleTLSPassthroughConnection(conn)

	case len(hello.ALPNProtos) == 1 && hello.ALPNProtos[0] == acme.ALPNProto && hello.ServerName != "":
		tc := p.baseTLSConfig()
		tc.NextProtos = []string{acme.ALPNProto}
		p.handleACMEConnection(tls.Server(conn, tc))

	case be.Mode == ModeConsole || be.Mode == ModeHTTP || be.Mode == ModeHTTPS:
		if err := p.checkIP(conn); err != nil {
			return
		}
		p.handleHTTPConnection(tls.Server(conn, be.tlsConfig))
		closeConnNeeded = false

	case be.Mode == ModeTCP || be.Mode == ModeTLS:
		if err := p.checkIP(conn); err != nil {
			return
		}
		p.handleTLSConnection(tls.Server(conn, be.tlsConfig))

	default:
		log.Printf("ERR [-] %s: unhandled connection %q", conn.RemoteAddr(), be.Mode)
	}
}

// checkIP is just a wrapper around be.checkIP. It must be called before the TLS
// handshake completes.
func (p *Proxy) checkIP(conn *netw.Conn) error {
	be := connBackend(conn)
	if err := be.checkIP(conn.RemoteAddr()); err != nil {
		serverName := connServerName(conn)
		p.recordEvent(serverName + " CheckIP " + err.Error())
		log.Printf("BAD [-] %s ➔  %q CheckIP: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return err
	}
	return nil
}

func (p *Proxy) handleACMEConnection(conn *tls.Conn) {
	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Minute)
	defer cancel()
	serverName := connServerName(conn)
	log.Printf("INF ACME %s ➔  %s", conn.RemoteAddr(), serverName)
	if err := conn.HandshakeContext(ctx); err != nil {
		p.recordEvent("tls handshake failed")
		log.Printf("BAD [-] %s ➔  %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
	}
}

func (p *Proxy) authorizeTLSConnection(conn *tls.Conn) bool {
	serverName := connServerName(conn)
	be := connBackend(conn)

	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Minute)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		switch {
		case err.Error() == "tls: client didn't provide a certificate":
			p.recordEvent(fmt.Sprintf("deny no cert to %s", serverName))
		case errors.Is(err, errAccessDenied):
			p.recordEvent("access denied")
		default:
			p.recordEvent("tls handshake failed")
		}
		log.Printf("BAD [-] %s ➔  %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
		return false
	}
	netwConn(conn).SetAnnotation(handshakeDoneKey, time.Now())
	cs := conn.ConnectionState()
	if (cs.ServerName == "" && serverName != p.defaultServerName()) || (cs.ServerName != "" && cs.ServerName != serverName) {
		p.recordEvent("mismatched server name")
		log.Printf("BAD [-] %s ➔  %q Mismatched server name", conn.RemoteAddr(), serverName)
		return false
	}
	proto := cs.NegotiatedProtocol
	var subject string
	if len(cs.PeerCertificates) > 0 {
		subject = cs.PeerCertificates[0].Subject.String()
	}
	netwConn(conn).SetAnnotation(protoKey, proto)
	netwConn(conn).SetAnnotation(subjectKey, subject)

	// The check below is also done in VerifyConnection.
	if be.ClientACL != nil {
		if err := be.authorize(subject); err != nil {
			p.recordEvent(err.Error())
			log.Printf("BAD [-] %s ➔  %q Authorize(%q): %v", conn.RemoteAddr(), serverName, subject, err)
			return false
		}
	}
	return true
}

func (p *Proxy) handleHTTPConnection(conn *tls.Conn) {
	if !p.authorizeTLSConnection(conn) {
		conn.Close()
		return
	}
	serverName := connServerName(conn)
	be := connBackend(conn)
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", conn.RemoteAddr(), serverName, err)
		conn.Close()
		return
	}
	if be.Mode != ModeConsole && be.Mode != ModeHTTP && be.Mode != ModeHTTPS {
		p.recordEvent("wrong mode")
		log.Printf("ERR [-] %s ➔  %q Mode is not [CONSOLE, HTTP, HTTPS]", conn.RemoteAddr(), serverName)
		conn.Close()
		return
	}
	if be.httpConnChan == nil {
		p.recordEvent("conn chan nil")
		log.Printf("ERR [-] %s ➔  %q conn channel is nil", conn.RemoteAddr(), serverName)
		conn.Close()
		return
	}
	netwConn(conn).SetAnnotation(reportEndKey, true)
	log.Printf("CON %s", formatConnDesc(conn.NetConn().(*netw.Conn)))
	be.httpConnChan <- conn
}

func (p *Proxy) handleTLSConnection(extConn *tls.Conn) {
	if !p.authorizeTLSConnection(extConn) {
		return
	}
	serverName := connServerName(extConn)
	be := connBackend(extConn)
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		return
	}

	proto := connProto(extConn)

	intConn, err := be.dial(proto)
	if err != nil {
		p.recordEvent("dial error")
		log.Printf("ERR [-] %s ➔  %q Dial: %v", extConn.RemoteAddr(), serverName, err)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)

	netwConn(extConn).SetAnnotation(dialDoneKey, time.Now())
	netwConn(extConn).SetAnnotation(internalConnKey, intConn)

	desc := formatConnDesc(netwConn(extConn))
	log.Printf("CON %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		log.Printf("DBG %s %v", desc, err)
	}

	startTime := netwConn(extConn).Annotation(startTimeKey, time.Time{}).(time.Time)
	hsTime := netwConn(extConn).Annotation(handshakeDoneKey, time.Time{}).(time.Time)
	dialTime := netwConn(extConn).Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	log.Printf("END %s; HS:%s Dial:%s Dur:%s Recv:%d Sent:%d", desc,
		hsTime.Sub(startTime).Truncate(time.Millisecond),
		dialTime.Sub(hsTime).Truncate(time.Millisecond), totalTime,
		netwConn(extConn).BytesReceived(), netwConn(extConn).BytesSent())
}

func (p *Proxy) handleTLSPassthroughConnection(extConn net.Conn) {
	serverName := connServerName(extConn)
	be := connBackend(extConn)
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		sendInternalError(extConn)
		return
	}

	intConn, err := be.dial("")
	if err != nil {
		p.recordEvent("dial error")
		log.Printf("ERR [-] %s ➔  %q Dial: %v", extConn.RemoteAddr(), serverName, err)
		sendInternalError(extConn)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)

	netwConn(extConn).SetAnnotation(dialDoneKey, time.Now())
	netwConn(extConn).SetAnnotation(internalConnKey, intConn)

	desc := formatConnDesc(netwConn(extConn))
	log.Printf("CON %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		log.Printf("DBG  %s %v", desc, err)
	}

	startTime := netwConn(extConn).Annotation(startTimeKey, time.Time{}).(time.Time)
	dialTime := netwConn(extConn).Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	log.Printf("END %s; Dial:%s Dur:%s Recv:%d Sent:%d", desc,
		dialTime.Sub(startTime).Truncate(time.Millisecond), totalTime,
		netwConn(extConn).BytesReceived(), netwConn(extConn).BytesSent())
}

func (p *Proxy) defaultServerName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.defServerName
}

func (p *Proxy) backend(serverName string) (*Backend, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	be, ok := p.backends[serverName]
	if !ok {
		return nil, errors.New("unexpected SNI")
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if be.shutdown {
		return nil, errors.New("backend shutdown")
	}
	return be, nil
}

func formatConnDesc(c *netw.Conn) string {
	serverName := connServerName(c)
	mode := connMode(c)
	proto := connProto(c)
	subject := connSubject(c)
	intConn := connIntConn(c)

	var buf bytes.Buffer
	if subject == "" {
		buf.WriteString("[-] ")
	} else {
		buf.WriteString("[" + subject + "] ")
	}
	buf.WriteString(c.RemoteAddr().String())
	if serverName != "" {
		buf.WriteString(" ➔ ")
		buf.WriteString(serverName)
		buf.WriteString("|" + mode)
		if proto != "" {
			buf.WriteString(":" + proto)
		}
		if intConn != nil {
			buf.WriteString("|" + intConn.LocalAddr().String())
			buf.WriteString(" ➔ ")
			buf.WriteString(intConn.RemoteAddr().String())
		}
	}
	return buf.String()
}

func setKeepAlive(conn net.Conn) {
	switch c := conn.(type) {
	case *tls.Conn:
		setKeepAlive(c.NetConn())
	case *net.TCPConn:
		c.SetKeepAlivePeriod(30 * time.Second)
		c.SetKeepAlive(true)
	case *netw.Conn:
		setKeepAlive(c.Conn)
	default:
		log.Fatalf("setKeepAlive called with unexpected type: %T", conn)
	}
}

func loadCerts(s string) (*x509.CertPool, error) {
	var b []byte
	if len(s) > 0 && s[0] == '/' {
		var err error
		if b, err = os.ReadFile(s); err != nil {
			return nil, err
		}
	} else {
		b = []byte(s)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid certs")
	}
	return pool, nil
}

func unwrapErr(err error) error {
	if e, ok := err.(*net.OpError); ok {
		return unwrapErr(e.Err)
	}
	return err
}

type logger struct{}

func (logger) Debug(args ...any) {}

func (logger) Debugf(f string, args ...any) {}

func (logger) Info(args ...any) {
	log.Print(append([]any{"INF "}, args)...)
}

func (logger) Infof(f string, args ...any) {
	log.Printf("INF "+f, args...)
}

func (logger) Error(args ...any) {
	log.Print(append([]any{"ERR "}, args)...)
}

func (logger) Errorf(f string, args ...any) {
	log.Printf("ERR "+f, args...)
}

func (logger) Fatal(args ...any) {
	log.Fatal(append([]any{"FATAL "}, args)...)
}

func (logger) Fatalf(f string, args ...any) {
	log.Fatalf("FATAL "+f, args...)
}
