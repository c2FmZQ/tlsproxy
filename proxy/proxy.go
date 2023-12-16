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
//
// It can also act as a reverse HTTP proxy with optional user authentication
// with SAML, OpenID Connect, and/or passkeys.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/autocertcache"
	"github.com/c2FmZQ/storage/crypto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
	yaml "gopkg.in/yaml.v3"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/ocspcache"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/oidc"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/passkeys"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/saml"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const (
	startTimeKey     = "s"
	handshakeDoneKey = "h"
	dialDoneKey      = "d"
	serverNameKey    = "sn"
	protoKey         = "p"
	clientCertKey    = "c"
	internalConnKey  = "ic"
	reportEndKey     = "re"
	backendKey       = "be"
)

var (
	errAccessDenied = errors.New("access denied")
	errRevoked      = errors.New("revoked")
)

// Proxy receives TLS connections and forwards them to the configured
// backends.
type Proxy struct {
	certManager interface {
		HTTPHandler(fallback http.Handler) http.Handler
		TLSConfig() *tls.Config
		GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	}
	cfg           *Config
	ctx           context.Context
	cancel        func()
	listener      net.Listener
	quicTransport io.Closer
	store         *storage.Storage
	tokenManager  *tokenmanager.TokenManager

	mu            sync.Mutex
	connClosed    *sync.Cond
	defServerName string
	backends      map[beKey]*Backend
	connections   map[connKey]*netw.Conn
	pkis          map[string]*pki.PKIManager
	ocspCache     *ocspcache.OCSPCache
	bwLimits      map[string]*bwLimit

	metrics   map[string]*backendMetrics
	startTime time.Time

	eventsmu sync.Mutex
	events   map[string]int64
}

type beKey struct {
	serverName string
	proto      string
}

type connKey struct {
	dst net.Addr
	src net.Addr
	id  int64
}

type bwLimit struct {
	ingress *rate.Limiter
	egress  *rate.Limiter
}

type backendMetrics struct {
	numConnections   int64
	numBytesSent     int64
	numBytesReceived int64
}

type eventRecorder struct {
	record func(string)
}

func (er eventRecorder) Record(s string) {
	er.record(s)
}

type identityProvider interface {
	RequestLogin(w http.ResponseWriter, req *http.Request, origURL string)
	HandleCallback(w http.ResponseWriter, req *http.Request)
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
	store := storage.New(cfg.CacheDir, mk)
	if !cfg.AcceptTOS {
		return nil, errors.New("AcceptTOS must be set to true")
	}
	tm, err := tokenmanager.New(store)
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		certManager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocertcache.New("autocert", store),
			Email:  cfg.Email,
		},
		store:        store,
		tokenManager: tm,
		connections:  make(map[connKey]*netw.Conn),
		pkis:         make(map[string]*pki.PKIManager),
		ocspCache:    ocspcache.New(store),
		bwLimits:     make(map[string]*bwLimit),
	}
	if err := p.Reconfigure(cfg); err != nil {
		return nil, err
	}
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
	passphrase := []byte("test")
	opts := []crypto.Option{
		crypto.WithAlgo(crypto.PickFastest),
		crypto.WithLogger(logger{}),
	}
	mkFile := filepath.Join(cfg.CacheDir, "test", "masterkey")
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
	store := storage.New(filepath.Join(cfg.CacheDir, "test"), mk)
	tm, err := tokenmanager.New(store)
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		certManager:  cm,
		connections:  make(map[connKey]*netw.Conn),
		store:        store,
		tokenManager: tm,
		pkis:         make(map[string]*pki.PKIManager),
		ocspCache:    ocspcache.New(store),
		bwLimits:     make(map[string]*bwLimit),
	}
	if err := p.Reconfigure(cfg); err != nil {
		return nil, err
	}
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
	cfg = cfg.clone()
	if err := cfg.Check(); err != nil {
		return err
	}
	if p.cfg != nil {
		log.Print("INF Configuration changed")
		p.recordEvent("config change")
	}

	type idp struct {
		name             string
		identityProvider identityProvider
		callback         string
		domain           string
		cm               *cookiemanager.CookieManager
	}
	er := eventRecorder{record: p.recordEvent}
	identityProviders := make(map[string]idp)
	for _, pp := range cfg.OIDCProviders {
		host, _, _ := hostAndPath(pp.RedirectURL)
		issuer := "https://" + host + "/"
		cm := cookiemanager.New(p.tokenManager, pp.Name, pp.Domain, issuer)
		oidcCfg := oidc.Config{
			DiscoveryURL:     pp.DiscoveryURL,
			AuthEndpoint:     pp.AuthEndpoint,
			Scopes:           pp.Scopes,
			TokenEndpoint:    pp.TokenEndpoint,
			UserinfoEndpoint: pp.UserinfoEndpoint,
			RedirectURL:      pp.RedirectURL,
			ClientID:         pp.ClientID,
			ClientSecret:     pp.ClientSecret,
		}
		provider, err := oidc.New(oidcCfg, er, cm)
		if err != nil {
			return err
		}
		identityProviders[pp.Name] = idp{
			name:             pp.Name,
			identityProvider: provider,
			callback:         pp.RedirectURL,
			domain:           pp.Domain,
			cm:               cm,
		}
	}
	for _, pp := range cfg.SAMLProviders {
		host, _, _ := hostAndPath(pp.ACSURL)
		issuer := "https://" + host + "/"
		cm := cookiemanager.New(p.tokenManager, pp.Name, pp.Domain, issuer)
		samlCfg := saml.Config{
			SSOURL:   pp.SSOURL,
			EntityID: pp.EntityID,
			Certs:    pp.Certs,
			ACSURL:   pp.ACSURL,
		}
		provider, err := saml.New(samlCfg, er, cm)
		if err != nil {
			return err
		}
		identityProviders[pp.Name] = idp{
			name:             pp.Name,
			identityProvider: provider,
			callback:         pp.ACSURL,
			domain:           pp.Domain,
			cm:               cm,
		}
	}
	for _, pp := range cfg.PasskeyProviders {
		other, ok := identityProviders[pp.IdentityProvider]
		if !ok {
			return fmt.Errorf("invalid identityProvider %q", pp.IdentityProvider)
		}
		host, _, _ := hostAndPath(pp.Endpoint)
		issuer := "https://" + host + "/"
		cm := cookiemanager.New(p.tokenManager, pp.Name, pp.Domain, issuer)
		cfg := passkeys.Config{
			Store:              p.store,
			Other:              other.identityProvider,
			Endpoint:           pp.Endpoint,
			EventRecorder:      er,
			CookieManager:      cm,
			OtherCookieManager: other.cm,
			ClaimsFromCtx:      claimsFromCtx,
		}
		provider, err := passkeys.NewManager(cfg)
		if err != nil {
			return err
		}
		identityProviders[pp.Name] = idp{
			name:             pp.Name,
			identityProvider: provider,
			callback:         pp.Endpoint,
			domain:           pp.Domain,
			cm:               cm,
		}
	}

	pkis := make(map[string]*pki.PKIManager)
	for _, pp := range cfg.PKI {
		opts := pki.Options{
			Name:                  pp.Name,
			KeyType:               pp.KeyType,
			Endpoint:              pp.Endpoint,
			IssuingCertificateURL: pp.IssuingCertificateURLs,
			CRLDistributionPoints: pp.CRLDistributionPoints,
			OCSPServer:            pp.OCSPServer,
			Admins:                pp.Admins,
			Store:                 p.store,
			EventRecorder:         er,
			ClaimsFromCtx:         claimsFromCtx,
		}
		m, err := pki.New(opts)
		if err != nil {
			return err
		}
		pkis[pp.Name] = m
	}

	for _, bwl := range cfg.BWLimits {
		const minBurst = 1 << 17 // 128 KB
		name := strings.ToLower(bwl.Name)
		if l, ok := p.bwLimits[name]; ok {
			l.ingress.SetLimit(rate.Limit(bwl.Ingress))
			l.ingress.SetBurst(int(max(bwl.Ingress, minBurst)))
			l.egress.SetLimit(rate.Limit(bwl.Egress))
			l.egress.SetBurst(int(max(bwl.Egress, minBurst)))
			continue
		}
		p.bwLimits[name] = &bwLimit{
			ingress: rate.NewLimiter(rate.Limit(bwl.Ingress), int(max(bwl.Ingress, minBurst))),
			egress:  rate.NewLimiter(rate.Limit(bwl.Egress), int(max(bwl.Egress, minBurst))),
		}
	}

	backends := make(map[beKey]*Backend, len(cfg.Backends))
	for _, be := range cfg.Backends {
		be.recordEvent = p.recordEvent
		be.tm = p.tokenManager
		be.quicTransport = p.quicTransport
		be.ocspCache = p.ocspCache

		for _, sn := range be.ServerNames {
			key := beKey{serverName: sn}
			if backends[key] == nil {
				backends[key] = be
			}
			if be.ALPNProtos == nil {
				continue
			}
			for _, proto := range *be.ALPNProtos {
				backends[beKey{serverName: sn, proto: proto}] = be
			}
		}
		if l, ok := p.bwLimits[be.BWLimit]; ok {
			be.bwLimit = l
		}
		if be.SSO != nil {
			idp, ok := identityProviders[be.SSO.Provider]
			if !ok {
				return fmt.Errorf("unknown identity provider: %q", be.SSO.Provider)
			}
			be.SSO.p = idp.identityProvider
			be.SSO.cm = idp.cm
			be.localHandlers = append(be.localHandlers,
				localHandler{
					desc:      "SSO identity",
					path:      "/.sso/",
					handler:   logHandler(http.HandlerFunc(be.serveSSOStatus)),
					ssoBypass: true,
				},
				localHandler{
					desc:      "Style Sheet",
					path:      "/.sso/style.css",
					handler:   logHandler(http.HandlerFunc(be.serveSSOStyle)),
					ssoBypass: true,
				},
				localHandler{
					desc:      "SSO Logout",
					path:      "/.sso/logout",
					handler:   logHandler(http.HandlerFunc(be.serveLogout)),
					ssoBypass: true,
				},
				localHandler{
					desc:      "Icon",
					path:      "/.sso/favicon.ico",
					handler:   logHandler(http.HandlerFunc(p.faviconHandler)),
					ssoBypass: true,
				})
			if m, ok := be.SSO.p.(*passkeys.Manager); ok {
				be.localHandlers = append(be.localHandlers,
					localHandler{
						desc:    "Manage Passkeys",
						path:    "/.sso/passkeys",
						handler: logHandler(http.HandlerFunc(m.ManageKeys)),
					},
					localHandler{
						desc:      "List of Passkey Endpoints",
						path:      "/.well-known/passkey-endpoints",
						handler:   logHandler(http.HandlerFunc(m.ServeWellKnown)),
						ssoBypass: true,
					},
				)
			}

			if ls := be.SSO.LocalOIDCServer; ls != nil && len(be.ServerNames) > 0 {
				opts := oidc.ServerOptions{
					TokenManager:  p.tokenManager,
					Issuer:        "https://" + be.ServerNames[0] + ls.PathPrefix,
					PathPrefix:    ls.PathPrefix,
					ClaimsFromCtx: claimsFromCtx,
					Clients:       make([]oidc.Client, 0, len(ls.Clients)),
					EventRecorder: er,
				}
				for _, client := range ls.Clients {
					opts.Clients = append(opts.Clients, oidc.Client{
						ID:          client.ID,
						Secret:      client.Secret,
						RedirectURI: client.RedirectURI,
					})
				}
				for _, rr := range ls.RewriteRules {
					opts.RewriteRules = append(opts.RewriteRules, oidc.RewriteRule{
						InputClaim:  rr.InputClaim,
						OutputClaim: rr.OutputClaim,
						Regex:       rr.Regex,
						Value:       rr.Value,
					})
				}
				oidcServer := oidc.NewServer(opts)
				be.localHandlers = append(be.localHandlers, localHandler{
					desc:      "OIDC Server Configuration",
					path:      ls.PathPrefix + "/.well-known/openid-configuration",
					handler:   logHandler(http.HandlerFunc(oidcServer.ServeConfig)),
					ssoBypass: true,
				},
					localHandler{
						desc:    "OIDC Server Authorization Endpoint",
						path:    ls.PathPrefix + "/authorization",
						handler: logHandler(http.HandlerFunc(oidcServer.ServeAuthorization)),
					},
					localHandler{
						desc:      "OIDC Server Token Endpoint",
						path:      ls.PathPrefix + "/token",
						handler:   logHandler(http.HandlerFunc(oidcServer.ServeToken)),
						ssoBypass: true,
					},
					localHandler{
						desc:      "OIDC Server Userinfo Endpoint",
						path:      ls.PathPrefix + "/userinfo",
						handler:   logHandler(http.HandlerFunc(oidcServer.ServeUserInfo)),
						ssoBypass: true,
					},
					localHandler{
						desc:      "OIDC Server JWKS Endpoint",
						path:      ls.PathPrefix + "/jwks",
						handler:   logHandler(http.HandlerFunc(p.tokenManager.ServeJWKS)),
						ssoBypass: true,
					},
				)
			}
		}
		be.pkiMap = make(map[string]*pki.PKIManager)
		tc := p.baseTLSConfig()
		if be.ClientAuth != nil {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
			for _, n := range be.ClientAuth.RootCAs {
				if tc.ClientCAs == nil {
					tc.ClientCAs = x509.NewCertPool()
				}
				if m, ok := pkis[n]; ok {
					ca, err := m.CACert()
					if err != nil {
						return err
					}
					be.pkiMap[hex.EncodeToString(ca.SubjectKeyId)] = m
					tc.ClientCAs.AddCert(ca)
					continue
				}
				if err := loadCerts(tc.ClientCAs, n); err != nil {
					return err
				}
			}
			tc.VerifyConnection = func(cs tls.ConnectionState) error {
				be, err := p.backend(cs.ServerName, cs.NegotiatedProtocol)
				if err != nil {
					return err
				}
				if be.ClientAuth == nil {
					return nil
				}
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no certificate")
				}
				cert := cs.PeerCertificates[0]
				sum := certSummary(cert)
				if m, ok := be.pkiMap[hex.EncodeToString(cert.AuthorityKeyId)]; ok {
					if m.IsRevoked(cert.SerialNumber) {
						p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s (revoked)", sum, cs.ServerName))
						return fmt.Errorf("%w [%s]", errRevoked, sum)
					}
				} else if len(cert.OCSPServer) > 0 {
					if err := p.ocspCache.VerifyChains(cs.VerifiedChains); err != nil {
						p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s (OCSP:%v)", sum, cs.ServerName, err))
						return fmt.Errorf("%w [%s]", errRevoked, sum)
					}
				}
				if err := be.authorize(cert); err != nil {
					p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s", sum, cs.ServerName))
					return fmt.Errorf("%w [%s]", err, sum)
				}
				if sum != "" {
					p.recordEvent(fmt.Sprintf("allow X509 [%s] to %s", sum, cs.ServerName))
				}
				return nil
			}
		}
		if be.ALPNProtos != nil {
			tc.NextProtos = slices.Clone(*be.ALPNProtos)
			tc.NextProtos = slices.DeleteFunc(tc.NextProtos, func(p string) bool {
				return quicOnlyProtocols[p] && (be.Mode == ModeTLS || be.Mode == ModeTCP)
			})
		}
		be.tlsConfigQUIC = tc.Clone()
		be.tlsConfigQUIC.MinVersion = tls.VersionTLS13
		// http/3 requires QUIC. Offering it on a TCP connection could
		// lead to confusion.
		tc.NextProtos = slices.Clone(tc.NextProtos)
		tc.NextProtos = slices.DeleteFunc(tc.NextProtos, func(p string) bool {
			return quicOnlyProtocols[p]
		})
		be.tlsConfig = tc

		be.getClientCert = func(ctx context.Context) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			serverName := connServerName(ctx.Value(connCtxKey).(net.Conn))
			return func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				// autocert wants a ClientHelloInfo. Create one with reasonable values.
				hello := &tls.ClientHelloInfo{
					ServerName:       serverName,
					SignatureSchemes: cri.SignatureSchemes,
					SupportedCurves: []tls.CurveID{
						tls.CurveP256,
					},
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					},
				}
				return p.certManager.GetCertificate(hello)
			}
		}

		for _, n := range be.ForwardRootCAs {
			if be.forwardRootCAs == nil {
				be.forwardRootCAs = x509.NewCertPool()
			}
			if m, ok := pkis[n]; ok {
				ca, err := m.CACert()
				if err != nil {
					return err
				}
				be.pkiMap[hex.EncodeToString(ca.SubjectKeyId)] = m
				be.forwardRootCAs.AddCert(ca)
				continue
			}
			if err := loadCerts(be.forwardRootCAs, n); err != nil {
				return err
			}
		}
		for _, po := range be.PathOverrides {
			for _, n := range po.ForwardRootCAs {
				if po.forwardRootCAs == nil {
					po.forwardRootCAs = x509.NewCertPool()
				}
				if m, ok := pkis[n]; ok {
					ca, err := m.CACert()
					if err != nil {
						return err
					}
					be.pkiMap[hex.EncodeToString(ca.SubjectKeyId)] = m
					po.forwardRootCAs.AddCert(ca)
					continue
				}
				if err := loadCerts(po.forwardRootCAs, n); err != nil {
					return err
				}
			}
		}
		if be.ExportJWKS != "" {
			be.localHandlers = append(be.localHandlers, localHandler{
				desc:      "JWKS Endpoint",
				path:      be.ExportJWKS,
				handler:   logHandler(http.HandlerFunc(p.tokenManager.ServeJWKS)),
				ssoBypass: true,
			})
		}
		switch be.Mode {
		case ModeConsole:
			be := be
			be.localHandlers = append(be.localHandlers,
				localHandler{desc: "Metrics", path: "/", handler: logHandler(http.HandlerFunc(p.metricsHandler))},
				localHandler{desc: "Icon", path: "/favicon.ico", handler: logHandler(http.HandlerFunc(p.faviconHandler))},
				localHandler{desc: "Proxy Config", path: "/config", handler: logHandler(http.HandlerFunc(p.configHandler))},
			)
			addPProfHandlers(&be.localHandlers)

			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.localHandler(), be.httpConnChan)
			if cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Handler = be.localHandler()
			}

		case ModeLocal:
			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.localHandler(), be.httpConnChan)
			if cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Handler = be.localHandler()
			}

		case ModeHTTPS, ModeHTTP:
			if cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Handler = be.reverseProxy()
			}
			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.reverseProxy(), be.httpConnChan)
		}
	}

	addLocalHandler := func(h localHandler, urls ...string) {
		for _, v := range urls {
			host, path, err := hostAndPath(v)
			if err != nil {
				log.Printf("ERR %s: %v", v, err)
				continue
			}
			be, exists := backends[beKey{serverName: host}]
			if !exists {
				log.Printf("ERR Backend for %s not found", v)
				continue
			}
			h.host = host
			h.path = path
			be.localHandlers = append(be.localHandlers, h)

			if h.isCallback && be.SSO != nil {
				if m, ok := be.SSO.p.(*passkeys.Manager); ok {
					m.SetACL(be.SSO.ACL)
				}
			}
		}
	}
	for _, p := range identityProviders {
		p := p
		addLocalHandler(localHandler{
			desc: fmt.Sprintf("OIDC Client Redirect Endpoint (%s)", p.name),
			handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				log.Printf("REQ %s ➔ %s %s (SSO callback) (%q)", formatReqDesc(req), req.Method, req.URL.Path, userAgent(req))
				p.identityProvider.HandleCallback(w, req)
			}),
			ssoBypass:  true,
			isCallback: true,
		}, p.callback)
	}
	for _, pp := range cfg.PKI {
		addLocalHandler(localHandler{
			desc:      fmt.Sprintf("PKI CA Cert (%s)", pp.Name),
			handler:   logHandler(http.HandlerFunc(pkis[pp.Name].ServeCACert)),
			ssoBypass: true,
		}, pp.IssuingCertificateURLs...)
		addLocalHandler(localHandler{
			desc:      fmt.Sprintf("PKI CRL (%s)", pp.Name),
			handler:   logHandler(http.HandlerFunc(pkis[pp.Name].ServeCRL)),
			ssoBypass: true,
		}, pp.CRLDistributionPoints...)
		addLocalHandler(localHandler{
			desc:        fmt.Sprintf("PKI OCSP (%s)", pp.Name),
			handler:     logHandler(http.HandlerFunc(pkis[pp.Name].ServeOCSP)),
			ssoBypass:   true,
			matchPrefix: true,
		}, pp.OCSPServer...)
		if pp.Endpoint != "" {
			addLocalHandler(localHandler{
				desc:    fmt.Sprintf("PKI Cert Management (%s)", pp.Name),
				handler: logHandler(http.HandlerFunc(pkis[pp.Name].ServeCertificateManagement)),
			}, pp.Endpoint)
		}
	}
	for _, be := range backends {
		sort.Slice(be.localHandlers, func(i, j int) bool {
			a := be.localHandlers[i].host
			b := be.localHandlers[j].host
			if a == b {

				return len(be.localHandlers[i].path) > len(be.localHandlers[j].path)
			}
			if la, lb := len(a), len(b); la != lb {
				return la > lb
			}
			return a < b

		})
	}
	if p.cfg != nil {
		for _, be := range p.cfg.Backends {
			be.close(p.ctx)
		}
	}
	p.defServerName = cfg.DefaultServerName
	p.backends = backends
	p.pkis = pkis
	p.cfg = cfg
	go p.reAuthorize()
	return nil
}

func (p *Proxy) reAuthorize() {
	p.mu.Lock()
	conns := make([]*netw.Conn, 0, len(p.connections))
	for _, c := range p.connections {
		conns = append(conns, c)
	}
	p.mu.Unlock()

	for _, conn := range conns {
		serverName := connServerName(conn)
		proto := connProto(conn)
		be, err := p.backend(serverName, proto)
		if err != nil {
			p.recordEvent(err.Error())
			log.Printf("BAD [-] ReAuth %s ➔ %q: %v", conn.RemoteAddr(), serverName, err)
			conn.Close()
			continue
		}
		if oldBE := connBackend(conn); be.Mode != oldBE.Mode {
			log.Printf("INF [-] ReAuth %s ➔  %q backend mode changed %s->%s", conn.RemoteAddr(), serverName, oldBE.Mode, be.Mode)
			conn.Close()
			continue
		}
		if err := be.checkIP(conn.RemoteAddr()); err != nil {
			p.recordEvent(serverName + " CheckIP " + err.Error())
			log.Printf("BAD [-] ReAuth %s ➔ %q CheckIP: %v", conn.RemoteAddr(), serverName, err)
			conn.Close()
			continue
		}
		if be.ClientAuth == nil {
			continue
		}
		clientCert := connClientCert(conn)
		if err := be.authorize(clientCert); err != nil {
			p.recordEvent(err.Error())
			log.Printf("BAD [-] ReAuth %s ➔ %q Authorize(%q): %v", conn.RemoteAddr(), serverName, certSummary(clientCert), err)
			conn.Close()
			continue
		}
	}
}

// Start starts a TLS proxy with the given configuration. The proxy runs
// in background until the context is canceled.
func (p *Proxy) Start(ctx context.Context) error {
	p.startTime = time.Now()
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
	if p.cfg.EnableQUIC {
		if err := p.startQUIC(ctx); err != nil {
			return err
		}
	}

	listener, err := netw.Listen("tcp", p.cfg.TLSAddr)
	if err != nil {
		return err
	}
	p.listener = listener
	p.ctx, p.cancel = context.WithCancel(ctx)

	go p.ctxWait(httpServer)
	go p.tokenManager.KeyRotationLoop(p.ctx)
	go p.ocspCache.FlushLoop(p.ctx)
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
	log.Printf("INF Accepting TLS connections on %s %s", p.listener.Addr().Network(), p.listener.Addr())
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Print("INF TLS Accept loop terminated")
				break
			}
			log.Printf("ERR TLS Accept: %v", err)
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
	if p.quicTransport != nil {
		p.quicTransport.Close()
	}
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
	if p.quicTransport != nil {
		p.quicTransport.Close()
	}
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
	tc.NextProtos = *defaultALPNProtos
	tc.MinVersion = tls.VersionTLS12
	return tc
}

func (p *Proxy) handleConnection(conn *netw.Conn) {
	p.recordEvent("tcp connection")
	defer func() {
		if r := recover(); r != nil {
			p.recordEvent("panic")
			log.Printf("ERR [%s] %s: PANIC: %v", certSummary(connClientCert(conn)), conn.RemoteAddr(), r)
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
		log.Printf("BAD [-] %s ➔ %q: invalid ClientHello: %v", conn.RemoteAddr(), hello.ServerName, err)
		return
	}
	serverName := hello.ServerName
	if serverName == "" {
		p.recordEvent("no SNI")
		serverName = p.defaultServerName()
	}
	conn.SetAnnotation(serverNameKey, serverName)

	be, err := p.backend(serverName, hello.ALPNProtos...)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("BAD [-] %s ➔ %q: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return
	}
	conn.SetAnnotation(backendKey, be)
	be.incInFlight(1)
	if l := be.bwLimit; l != nil {
		conn.SetLimiters(l.ingress, l.egress)
	}
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

	case be.Mode == ModeConsole || be.Mode == ModeLocal || be.Mode == ModeHTTP || be.Mode == ModeHTTPS:
		if err := p.checkIP(conn); err != nil {
			return
		}
		p.handleHTTPConnection(tls.Server(conn, be.tlsConfig))
		closeConnNeeded = false

	case be.Mode == ModeTCP || be.Mode == ModeTLS || be.Mode == ModeQUIC:
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
		log.Printf("BAD [-] %s ➔ %q CheckIP: %v", conn.RemoteAddr(), serverName, err)
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
		log.Printf("BAD [-] %s ➔ %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
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
		case errors.Is(err, errRevoked):
			p.recordEvent("cert is revoked")
		default:
			p.recordEvent("tls handshake failed")
		}
		log.Printf("BAD [-] %s ➔ %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
		return false
	}
	netwConn(conn).SetAnnotation(handshakeDoneKey, time.Now())
	cs := conn.ConnectionState()
	if (cs.ServerName == "" && serverName != p.defaultServerName()) || (cs.ServerName != "" && cs.ServerName != serverName) {
		p.recordEvent("mismatched server name")
		log.Printf("BAD [-] %s ➔ %q Mismatched server name", conn.RemoteAddr(), serverName)
		return false
	}
	proto := cs.NegotiatedProtocol
	var clientCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		clientCert = cs.PeerCertificates[0]
	}
	netwConn(conn).SetAnnotation(protoKey, proto)
	netwConn(conn).SetAnnotation(clientCertKey, clientCert)

	// The check below is also done in VerifyConnection.
	if be.ClientAuth != nil && be.ClientAuth.ACL != nil {
		if err := be.authorize(clientCert); err != nil {
			p.recordEvent(err.Error())
			log.Printf("BAD [-] %s ➔ %q Authorize(%q): %v", conn.RemoteAddr(), serverName, certSummary(clientCert), err)
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
	if err := be.connLimit.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", conn.RemoteAddr(), serverName, err)
		conn.Close()
		return
	}
	if be.Mode != ModeConsole && be.Mode != ModeLocal && be.Mode != ModeHTTP && be.Mode != ModeHTTPS {
		p.recordEvent("wrong mode")
		log.Printf("ERR [-] %s ➔  %q Mode is not [CONSOLE, LOCAL, HTTP, HTTPS]", conn.RemoteAddr(), serverName)
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
	if err := be.connLimit.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		return
	}

	var protos []string
	if proto := connProto(extConn); proto != "" {
		protos = []string{proto}
	}

	intConn, err := be.dial(context.WithValue(p.ctx, connCtxKey, extConn), protos...)
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
	if err := be.connLimit.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		log.Printf("ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), serverName, err)
		sendInternalError(extConn)
		return
	}

	intConn, err := be.dial(context.WithValue(p.ctx, connCtxKey, extConn))
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

func (p *Proxy) backend(serverName string, protos ...string) (*Backend, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var be *Backend
	var ok bool
	for _, proto := range protos {
		if be, ok = p.backends[beKey{serverName: serverName, proto: proto}]; ok {
			break
		}
	}
	if !ok {
		be, ok = p.backends[beKey{serverName: serverName}]
	}
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

func formatReqDesc(req *http.Request) string {
	var ids []string
	if claims := claimsFromCtx(req.Context()); claims != nil {
		email, _ := claims["email"].(string)
		ids = append(ids, email)
	}
	conn, ok := req.Context().Value(connCtxKey).(net.Conn)
	if !ok {
		log.Printf("ERR Request without connCtxKey: %v", req.Context())
		return ""
	}
	return formatConnDesc(conn, ids...)
}

func formatConnDesc(c net.Conn, ids ...string) string {
	serverName := connServerName(c)
	mode := connMode(c)
	proto := connProto(c)
	clientCert := connClientCert(c)
	intConn := connIntConn(c)

	var identities []string
	if sum := certSummary(clientCert); sum != "" {
		identities = append(identities, sum)
	}
	identities = append(identities, ids...)

	var buf bytes.Buffer
	if len(identities) == 0 {
		buf.WriteString("[-] ")
	} else {
		buf.WriteString("[" + strings.Join(identities, "|") + "] ")
	}
	buf.WriteString(c.RemoteAddr().Network() + ":" + c.RemoteAddr().String())
	if serverName != "" {
		buf.WriteString(" ➔ ")
		buf.WriteString(serverName)
		buf.WriteString("|" + mode)
		if proto != "" {
			buf.WriteString(":" + proto)
		}
		if intConn != nil {
			buf.WriteString("|" + intConn.LocalAddr().Network() + ":" + intConn.LocalAddr().String())
			buf.WriteString(" ➔ ")
			buf.WriteString(intConn.RemoteAddr().Network() + ":" + intConn.RemoteAddr().String())
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
	}
}

func loadCerts(p *x509.CertPool, s string) error {
	var b []byte
	if len(s) > 0 && s[0] == '/' {
		var err error
		if b, err = os.ReadFile(s); err != nil {
			return err
		}
	} else {
		b = []byte(s)
	}
	if !p.AppendCertsFromPEM(b) {
		return errors.New("invalid certs")
	}
	return nil
}

func hostFromReq(req *http.Request) string {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

func hostAndPath(urlString string) (string, string, error) {
	url, err := url.Parse(urlString)
	if err != nil {
		return "", "", err
	}
	host := url.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host), url.Path, nil
}

func certSummary(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	var parts []string
	if sub := c.Subject.String(); sub != "" {
		parts = append(parts, "SUBJECT:"+sub)
	}
	for _, v := range c.DNSNames {
		parts = append(parts, "DNS:"+v)
	}
	for _, v := range c.EmailAddresses {
		parts = append(parts, "EMAIL:"+v)
	}
	for _, v := range c.URIs {
		parts = append(parts, "URI:"+v.String())
	}
	return strings.Join(parts, ";")
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
