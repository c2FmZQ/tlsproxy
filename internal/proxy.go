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

package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/exp/slices"
	yaml "gopkg.in/yaml.v3"

	"github.com/c2FmZQ/tlsproxy/internal/certmanager"
	"github.com/c2FmZQ/tlsproxy/internal/netw"
)

const (
	startTimeKey     = "s"
	handshakeDoneKey = "h"
	dialDoneKey      = "d"
	serverNameKey    = "sn"
	modeKey          = "m"
	protoKey         = "p"
	subjectKey       = "sub"
	internalConnKey  = "ic"
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
	defServerName string
	backends      map[string]*Backend
	connections   map[connKey]*netw.Conn

	consoleChan   chan net.Conn
	consoleServer *http.Server

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
func New(cfg *Config) (*Proxy, error) {
	p := &Proxy{
		certManager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(cfg.CacheDir),
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
		log.Printf("DBUG CertManager: "+fmt, args...)
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
		log.Print("INFO Configuration changed")
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
	}
	p.backends = backends
	p.cfg = cfg
	p.startConsoleIfNeeded()
	return nil
}

// Start starts a TLS proxy with the given configuration. The proxy runs
// in background until the context is canceled.
func (p *Proxy) Start(ctx context.Context) error {
	var httpServer *http.Server
	if p.cfg.HTTPAddr != "" {
		httpServer = &http.Server{
			Handler: p.certManager.HTTPHandler(nil),
		}
		httpListener, err := net.Listen("tcp", p.cfg.HTTPAddr)
		if err != nil {
			return err
		}
		go func() {
			httpServer.SetKeepAlivesEnabled(false)
			if err := httpServer.Serve(httpListener); err != http.ErrServerClosed {
				log.Fatalf("http: %v", err)
			}
		}()
	}

	listener, err := netw.Listen("tcp", p.cfg.TLSAddr)
	if err != nil {
		return err
	}
	p.listener = listener
	p.ctx, p.cancel = context.WithCancel(ctx)

	go func() {
		<-p.ctx.Done()
		p.cancel()
		if httpServer != nil {
			httpServer.Close()
		}
		if p.consoleServer != nil {
			p.consoleServer.Close()
		}
		p.listener.Close()
	}()

	p.startConsoleIfNeeded()

	go func() {
		log.Printf("INFO Accepting TLS connections on %s", p.listener.Addr())
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Print("INFO Accept loop terminated")
					break
				}
				log.Printf("ERR Accept: %v", err)
				continue
			}
			go p.handleConnection(conn.(*netw.Conn))
		}
	}()
	return nil
}

// Stop signals the background goroutines to exit.
func (p *Proxy) Stop() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
}

func (p *Proxy) startConsoleIfNeeded() {
	if p.ctx == nil || p.consoleChan != nil {
		return
	}
	var needed bool
	for _, be := range p.backends {
		if be.Mode == ModeConsole {
			needed = true
			break
		}
	}

	if !needed {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.metricsHandler)
	addPProfHandlers(mux)

	p.consoleChan = make(chan net.Conn)
	p.consoleServer = startInternalHTTPServer(p.ctx, mux, p.consoleChan)
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

func (p *Proxy) recordEvent(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.events == nil {
		p.events = make(map[string]int64)
	}
	p.events[msg]++
}

func (p *Proxy) addConn(c *netw.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections[connKey{c.LocalAddr(), c.RemoteAddr()}] = c
	return len(p.connections)
}

func (p *Proxy) removeConn(c *netw.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.connections, connKey{c.LocalAddr(), c.RemoteAddr()})

	if sn := c.Annotation(serverNameKey, "").(string); sn != "" && p.backends[sn] != nil {
		if p.metrics == nil {
			p.metrics = make(map[string]*backendMetrics)
		}
		m := p.metrics[sn]
		if m == nil {
			m = &backendMetrics{}
			p.metrics[sn] = m
		}
		m.numConnections++
		m.numBytesSent += c.BytesSent()
		m.numBytesReceived += c.BytesReceived()
	}

	return len(p.connections)
}

func (p *Proxy) metricsHandler(w http.ResponseWriter, req *http.Request) {
	peer := "-"
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		peer = req.TLS.PeerCertificates[0].Subject.String()
	}
	host := strings.Split(req.Host, ":")[0]
	log.Printf("INFO  [%s] %s ➔  %s (Console) ➔  %s %s", peer, req.RemoteAddr, host, req.Method, req.RequestURI)
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	req.ParseForm()
	if v := req.Form.Get("refresh"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			w.Header().Set("refresh", strconv.Itoa(i))
		}
	}

	var buf bytes.Buffer
	defer buf.WriteTo(w)

	p.mu.Lock()
	defer p.mu.Unlock()

	totals := make(map[string]*backendMetrics)
	for k, v := range p.metrics {
		m := *v
		totals[k] = &m
	}
	for _, c := range p.connections {
		sn := c.Annotation(serverNameKey, "").(string)
		if sn == "" || p.backends[sn] == nil {
			continue
		}
		m := totals[sn]
		if m == nil {
			m = &backendMetrics{}
			totals[sn] = m
		}
		m.numConnections++
		m.numBytesSent += c.BytesSent()
		m.numBytesReceived += c.BytesReceived()
	}

	var serverNames []string
	var maxLen int
	for k := range totals {
		if n := len(k); n > maxLen {
			maxLen = n
		}
		serverNames = append(serverNames, k)
	}
	sort.Strings(serverNames)
	fmt.Fprintln(&buf, "Backend metrics:")
	fmt.Fprintln(&buf)
	fmt.Fprintf(&buf, "  %*s %12s %12s %12s\n", -maxLen, "Server", "Count", "Sent", "Recv")
	for _, s := range serverNames {
		fmt.Fprintf(&buf, "  %*s %12d %12d %12d\n", -maxLen, s, totals[s].numConnections, totals[s].numBytesSent, totals[s].numBytesReceived)
	}

	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Event counts:")
	fmt.Fprintln(&buf)
	events := make([]string, 0, len(p.events))
	max := 0
	for k := range p.events {
		if len(k) > max {
			max = len(k)
		}
		events = append(events, k)
	}
	sort.Strings(events)
	for _, e := range events {
		fmt.Fprintf(&buf, "  %*s %6d\n", -(max + 1), e+":", p.events[e])
	}

	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Current connections:")
	fmt.Fprintln(&buf)
	keys := make([]connKey, 0, len(p.connections))
	for k := range p.connections {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		sa := p.connections[keys[i]].Annotation(serverNameKey, "").(string)
		sb := p.connections[keys[j]].Annotation(serverNameKey, "").(string)
		if sa == sb {
			a := keys[i].src.String() + " " + keys[i].dst.String()
			b := keys[j].src.String() + " " + keys[j].dst.String()
			return a < b
		}
		return sa < sb
	})
	for _, k := range keys {
		c := p.connections[k]
		desc := formatConnDesc(c)

		startTime := c.Annotation(startTimeKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime)

		fmt.Fprintf(&buf, "  %s; Start:%s (%s) Recv:%d Sent:%d\n", desc,
			startTime.Format(time.DateTime), totalTime, c.BytesReceived(), c.BytesSent())
	}
}

func (p *Proxy) handleConnection(conn *netw.Conn) {
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
		if mode := conn.Annotation(modeKey, "").(string); mode == ModeConsole {
			startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
			log.Printf("END   %s; Total:%s Recv:%d Sent:%d",
				formatConnDesc(conn), time.Since(startTime),
				conn.BytesReceived(), conn.BytesSent())
		}
	})
	if numOpen >= p.cfg.MaxOpen {
		p.recordEvent("too many open connections")
		log.Printf("ERR   %s: too many open connections: %d >= %d", conn.RemoteAddr(), numOpen, p.cfg.MaxOpen)
		sendCloseNotify(conn)
		return
	}
	setKeepAlive(conn)

	hello, err := peekClientHello(conn)
	if err != nil {
		p.recordEvent("invalid ClientHello")
		log.Printf("ERR   %s ➔  %q: invalid ClientHello: %v", conn.RemoteAddr(), hello.ServerName, err)
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
		log.Printf("ERR   %s ➔  %q: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return
	}
	conn.SetAnnotation(modeKey, be.Mode)
	switch {
	case be.Mode == ModeTLSPassthrough:
		if err := p.checkIP(be, conn, serverName); err != nil {
			return
		}
		p.handleTLSPassthroughConnection(conn, serverName)

	case slices.Contains(hello.ALPNProtos, acme.ALPNProto):
		tc := p.baseTLSConfig()
		tc.NextProtos = []string{acme.ALPNProto}
		p.handleACMEConnection(tls.Server(conn, tc), serverName)

	case be.Mode == ModeConsole:
		if err := p.checkIP(be, conn, serverName); err != nil {
			return
		}
		p.handleConsoleConnection(tls.Server(conn, be.tlsConfig), serverName)
		closeConnNeeded = false

	default:
		if err := p.checkIP(be, conn, serverName); err != nil {
			return
		}
		p.handleTLSConnection(tls.Server(conn, be.tlsConfig), serverName)
	}
}

// checkIP is just a wrapper around be.checkIP. It must be called before the TLS
// handshake completes.
func (p *Proxy) checkIP(be *Backend, conn net.Conn, serverName string) error {
	if err := be.checkIP(conn.RemoteAddr()); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q CheckIP: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return err
	}
	return nil
}

func (p *Proxy) handleACMEConnection(conn *tls.Conn, serverName string) {
	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Minute)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		p.recordEvent("tls handshake failed")
		log.Printf("ERR   %s ➔  %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
	}
	log.Printf("INFO ACME %s ➔ %s", conn.RemoteAddr(), serverName)
}

func (p *Proxy) authorizeTLSConnection(conn *tls.Conn, serverName string) bool {
	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Minute)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		switch {
		case err.Error() == "tls: client didn't provide a certificate":
			p.recordEvent("no client certificate")
		case errors.Is(err, errAccessDenied):
			p.recordEvent("access denied")
		default:
			p.recordEvent("tls handshake failed")
		}
		log.Printf("ERR   %s ➔  %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
		return false
	}
	netwConn := conn.NetConn().(*netw.Conn)
	netwConn.SetAnnotation(handshakeDoneKey, time.Now())
	cs := conn.ConnectionState()
	if (cs.ServerName == "" && serverName != p.defaultServerName()) || (cs.ServerName != "" && cs.ServerName != serverName) {
		p.recordEvent("mismatched server name")
		log.Printf("ERR   %s ➔  %q Mismatched server name", conn.RemoteAddr(), serverName)
		return false
	}
	proto := cs.NegotiatedProtocol
	var subject string
	if len(cs.PeerCertificates) > 0 {
		subject = cs.PeerCertificates[0].Subject.String()
	}
	netwConn.SetAnnotation(protoKey, proto)
	netwConn.SetAnnotation(subjectKey, subject)

	// The checks below should already have been done in VerifyConnection.
	be, err := p.backend(serverName)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q: %v", conn.RemoteAddr(), serverName, err)
		return false
	}
	if be.ClientACL != nil {
		if err := be.authorize(subject); err != nil {
			p.recordEvent(err.Error())
			log.Printf("ERR   %s ➔  %q Authorize(%q): %v", conn.RemoteAddr(), serverName, subject, err)
			return false
		}
	}
	return true
}

func (p *Proxy) handleConsoleConnection(conn *tls.Conn, serverName string) {
	if !p.authorizeTLSConnection(conn, serverName) {
		conn.Close()
		return
	}
	be, err := p.backend(serverName)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q: %v", conn.RemoteAddr(), serverName, err)
		conn.Close()
		return
	}
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q Wait: %v", conn.RemoteAddr(), serverName, err)
		conn.Close()
		return
	}
	if be.Mode != ModeConsole {
		p.recordEvent("wrong mode")
		log.Printf("ERR   %s ➔  %q Mode is not %s", conn.RemoteAddr(), serverName, ModeConsole)
		conn.Close()
		return
	}
	log.Printf("BEGIN %s", formatConnDesc(conn.NetConn().(*netw.Conn)))
	p.consoleChan <- conn
}

func (p *Proxy) handleTLSConnection(extConn *tls.Conn, serverName string) {
	if !p.authorizeTLSConnection(extConn, serverName) {
		return
	}
	be, err := p.backend(serverName)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q: %v", extConn.RemoteAddr(), serverName, err)
		return
	}
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		return
	}

	extNetwConn := extConn.NetConn().(*netw.Conn)
	proto := extNetwConn.Annotation(protoKey, "").(string)

	intConn, err := be.dial(proto)
	if err != nil {
		p.recordEvent("dial error")
		log.Printf("ERR   %s ➔  %q Dial: %v", extConn.RemoteAddr(), serverName, err)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)

	extNetwConn.SetAnnotation(dialDoneKey, time.Now())
	extNetwConn.SetAnnotation(internalConnKey, intConn)

	desc := formatConnDesc(extNetwConn)
	log.Printf("BEGIN %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		log.Printf("ERR   %s %v", desc, err)
	}

	startTime := extNetwConn.Annotation(startTimeKey, time.Time{}).(time.Time)
	hsTime := extNetwConn.Annotation(handshakeDoneKey, time.Time{}).(time.Time)
	dialTime := extNetwConn.Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime)

	log.Printf("END   %s; HS:%s Dial:%s Total:%s Recv:%d Sent:%d", desc,
		hsTime.Sub(startTime), dialTime.Sub(hsTime), totalTime,
		extNetwConn.BytesReceived(), extNetwConn.BytesSent())
}

func (p *Proxy) handleTLSPassthroughConnection(extConn net.Conn, serverName string) {
	be, err := p.backend(serverName)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q: %v", extConn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(extConn)
		return
	}
	if err := be.limiter.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR   %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		sendInternalError(extConn)
		return
	}

	extNetwConn := extConn.(*netw.Conn)

	intConn, err := be.dial("")
	if err != nil {
		p.recordEvent("dial error")
		log.Printf("ERR   %s ➔  %q Dial: %v", extConn.RemoteAddr(), serverName, err)
		sendInternalError(extConn)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)

	extNetwConn.SetAnnotation(dialDoneKey, time.Now())
	extNetwConn.SetAnnotation(internalConnKey, intConn)

	desc := formatConnDesc(extNetwConn)
	log.Printf("BEGIN %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		log.Printf("ERR   %s %v", desc, err)
	}

	startTime := extNetwConn.Annotation(startTimeKey, time.Time{}).(time.Time)
	dialTime := extNetwConn.Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime)

	log.Printf("END   %s; PT Dial:%s Total:%s Recv:%d Sent:%d", desc,
		dialTime.Sub(startTime), totalTime, extNetwConn.BytesReceived(), extNetwConn.BytesSent())
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
	return be, nil
}

func formatConnDesc(c *netw.Conn) string {
	serverName := c.Annotation(serverNameKey, "").(string)
	mode := c.Annotation(modeKey, "").(string)
	proto := c.Annotation(protoKey, "").(string)
	subject := c.Annotation(subjectKey, "").(string)
	var intConn net.Conn
	if ic, ok := c.Annotation(internalConnKey, intConn).(net.Conn); ok {
		intConn = ic
	}

	var buf bytes.Buffer
	if subject == "" {
		buf.WriteString("[-] ")
	} else {
		buf.WriteString("[" + subject + "] ")
	}
	buf.WriteString(c.RemoteAddr().String())
	if serverName != "" {
		buf.WriteString(" ➔  ")
		buf.WriteString(serverName)
		buf.WriteString("|" + mode)
		if proto != "" {
			buf.WriteString("/" + proto)
		}
		if intConn != nil {
			buf.WriteString(" ➔  ")
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

func (be *Backend) dial(proto string) (net.Conn, error) {
	var max int
	for {
		be.mu.Lock()
		sz := len(be.Addresses)
		if max == 0 {
			max = sz
		}
		addr := be.Addresses[be.next]
		be.next = (be.next + 1) % sz
		be.mu.Unlock()

		dialer := &net.Dialer{
			Timeout:   be.ForwardTimeout,
			KeepAlive: 30 * time.Second,
		}
		var c net.Conn
		var err error
		if be.Mode == ModeTLS {
			var protos []string
			if proto != "" {
				protos = append(protos, proto)
			}
			tc := &tls.Config{
				InsecureSkipVerify: be.InsecureSkipVerify,
				ServerName:         be.ForwardServerName,
				NextProtos:         protos,
			}
			if be.forwardRootCAs != nil {
				tc.RootCAs = be.forwardRootCAs
			}
			c, err = tls.DialWithDialer(dialer, "tcp", addr, tc)
		} else {
			c, err = dialer.Dial("tcp", addr)
		}
		if err != nil {
			max--
			if max > 0 {
				log.Printf("ERR dial %q: %v", addr, err)
				continue
			}
			return nil, err
		}
		return c, nil
	}
}

func (be *Backend) authorize(subject string) error {
	if be.ClientACL == nil {
		return nil
	}
	if subject == "" || !slices.Contains(*be.ClientACL, subject) {
		return errAccessDenied
	}
	return nil
}

func (be *Backend) checkIP(addr net.Addr) error {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	default:
		return fmt.Errorf("can't get IP address from %T", addr)
	}
	if be.denyIPs != nil {
		for _, n := range *be.denyIPs {
			if n.Contains(ip) {
				return errAccessDenied
			}
		}
	}
	if be.allowIPs != nil {
		for _, n := range *be.allowIPs {
			if n.Contains(ip) {
				return nil
			}
		}
		return errAccessDenied
	}
	return nil
}

func (be *Backend) bridgeConns(client, server net.Conn) error {
	serverClose := true
	if be.ServerCloseEndsConnection != nil {
		serverClose = *be.ServerCloseEndsConnection
	}
	clientClose := false
	if be.ClientCloseEndsConnection != nil {
		clientClose = *be.ClientCloseEndsConnection
	}
	timeout := time.Minute
	if be.HalfCloseTimeout != nil {
		timeout = *be.HalfCloseTimeout
	}
	ch := make(chan error)
	go func() {
		ch <- forward(client, server, serverClose, timeout)
	}()
	var retErr error
	if err := forward(server, client, clientClose, timeout); err != nil && !errors.Is(err, net.ErrClosed) {
		retErr = fmt.Errorf("[ext➔ int]: %w", unwrapErr(err))
	}
	if err := <-ch; err != nil && !errors.Is(err, net.ErrClosed) {
		retErr = fmt.Errorf("[int➔ ext]: %w", unwrapErr(err))
	}
	return retErr
}

func forward(out net.Conn, in net.Conn, closeWhenDone bool, halfClosedTimeout time.Duration) error {
	if _, err := io.Copy(out, in); err != nil || closeWhenDone {
		out.Close()
		in.Close()
		return err
	}
	if err := closeWrite(out); err != nil {
		out.Close()
		in.Close()
		return nil
	}
	if err := closeRead(in); err != nil {
		out.Close()
		in.Close()
		return nil
	}
	// At this point, the connection is either half closed, or fully closed.
	// If it is half closed, the remote end will get an EOF on the next
	// read. It can still send data back in the other direction. There are
	// some broken clients or network devices that never close their end of
	// the connection. So, we need to set a deadline to avoid keeping
	// connections open forever.
	out.SetReadDeadline(time.Now().Add(halfClosedTimeout))
	return nil
}

func closeWrite(c net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cc, ok := c.(closeWriter); ok {
		return cc.CloseWrite()
	}
	if cc, ok := c.(*netw.Conn); ok {
		return closeWrite(cc.Conn)
	}
	return fmt.Errorf("unexpected type: %T", c)
}

func closeRead(c net.Conn) error {
	type closeReader interface {
		CloseRead() error
	}
	if cc, ok := c.(closeReader); ok {
		return cc.CloseRead()
	}
	if cc, ok := c.(*netw.Conn); ok {
		return closeRead(cc.Conn)
	}
	return nil
}

func unwrapErr(err error) error {
	if e, ok := err.(*net.OpError); ok {
		return unwrapErr(e.Err)
	}
	return err
}
