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
	"github.com/c2FmZQ/tpm"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/time/rate"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/counter"
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
	modeKey          = "m"
	requestFlagKey   = "rf"
	proxyProtoKey    = "pp"
	httpUpgradeKey   = "hu"

	tlsBadCertificate      = tls.AlertError(0x2a)
	tlsCertificateRevoked  = tls.AlertError(0x2c)
	tlsAccessDenied        = tls.AlertError(0x31)
	tlsUnrecognizedName    = tls.AlertError(0x70)
	tlsCertificateRequired = tls.AlertError(0x74)
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
		GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	}
	cfg           *Config
	ctx           context.Context
	cancel        func()
	listener      net.Listener
	quicTransport io.Closer
	tpm           *tpm.TPM
	mk            crypto.MasterKey
	store         *storage.Storage
	tokenManager  *tokenmanager.TokenManager

	mu            sync.RWMutex
	connClosed    *sync.Cond
	defServerName string
	backends      map[beKey]*Backend
	pkis          map[string]*pki.PKIManager
	ocspCache     *ocspcache.OCSPCache
	bwLimits      map[string]*bwLimit
	inConns       *connTracker
	outConns      *connTracker

	metrics   map[string]*backendMetrics
	startTime time.Time

	eventsmu sync.Mutex
	events   map[string]int64
}

type beKey struct {
	serverName string
	proto      string
}

type bwLimit struct {
	ingress *rate.Limiter
	egress  *rate.Limiter
}

type backendMetrics struct {
	numConnections   *counter.Counter
	numBytesSent     *counter.Counter
	numBytesReceived *counter.Counter
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
	p := &Proxy{}
	opts := []crypto.Option{
		crypto.WithLogger(logger{p.logErrorF}),
	}
	var pTPM *tpm.TPM
	if cfg.HWBacked {
		t, err := tpm.New(tpm.WithObjectAuth(passphrase))
		if err != nil {
			return nil, err
		}
		opts = append(opts, crypto.WithTPM(t))
		pTPM = t
	} else {
		opts = append(opts, crypto.WithAlgo(crypto.PickFastest))
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
		return nil, fmt.Errorf("%s: %w", mkFile, err)
	}
	store := storage.New(cfg.CacheDir, mk)
	if !cfg.AcceptTOS {
		return nil, errors.New("AcceptTOS must be set to true")
	}
	tm, err := tokenmanager.New(store, pTPM)
	if err != nil {
		return nil, err
	}

	p.certManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocertcache.New("autocert", store),
		Email:  cfg.Email,
	}
	p.tpm = pTPM
	p.mk = mk
	p.store = store
	p.tokenManager = tm
	p.pkis = make(map[string]*pki.PKIManager)
	p.ocspCache = ocspcache.New(store)
	p.bwLimits = make(map[string]*bwLimit)
	p.inConns = newConnTracker()
	p.outConns = newConnTracker()

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
	tm, err := tokenmanager.New(store, nil)
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		certManager:  cm,
		mk:           mk,
		store:        store,
		tokenManager: tm,
		pkis:         make(map[string]*pki.PKIManager),
		ocspCache:    ocspcache.New(store),
		bwLimits:     make(map[string]*bwLimit),
		inConns:      newConnTracker(),
		outConns:     newConnTracker(),
	}
	if err := p.Reconfigure(cfg); err != nil {
		return nil, err
	}
	return p, nil
}

// Reconfigure updates the proxy's configuration. Some parameters cannot be
// changed after Start has been called, e.g. HTTPAddr, TLSAddr, CacheDir.
func (p *Proxy) Reconfigure(cfg *Config) error {
	p.mu.RLock()
	curCfg := p.cfg
	p.mu.RUnlock()
	if cfg.equal(curCfg) {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
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
		actualIDP        string
	}
	er := eventRecorder{record: p.recordEvent}
	identityProviders := make(map[string]idp)
	for _, pp := range cfg.OIDCProviders {
		_, host, _, _ := hostAndPath(pp.RedirectURL)
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
			HostedDomain:     pp.HostedDomain,
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
			actualIDP:        guessIDP(pp.AuthEndpoint),
		}
	}
	for _, pp := range cfg.SAMLProviders {
		_, host, _, _ := hostAndPath(pp.ACSURL)
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
			actualIDP:        guessIDP(pp.SSOURL),
		}
	}
	for _, pp := range cfg.PasskeyProviders {
		other, ok := identityProviders[pp.IdentityProvider]
		if !ok {
			return fmt.Errorf("invalid identityProvider %q", pp.IdentityProvider)
		}
		_, host, _, _ := hostAndPath(pp.Endpoint)
		issuer := "https://" + host + "/"
		cm := cookiemanager.New(p.tokenManager, pp.Name, pp.Domain, issuer)
		cfg := passkeys.Config{
			Store:              p.store,
			Other:              other.identityProvider,
			RefreshInterval:    pp.RefreshInterval,
			Endpoint:           pp.Endpoint,
			EventRecorder:      er,
			CookieManager:      cm,
			OtherCookieManager: other.cm,
			TokenManager:       p.tokenManager,
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
			TPM:                   p.tpm,
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
		be.defaultLogFilter = cfg.LogFilter

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
			be.SSO.actualIDP = idp.actualIDP
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
					desc:      "SSO Login",
					path:      "/.sso/login",
					handler:   logHandler(http.HandlerFunc(be.serveLogin)),
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
					return tlsUnrecognizedName
				}
				if be.ClientAuth == nil {
					return nil
				}
				if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
					p.recordEvent(fmt.Sprintf("deny no cert to %s", idnaToUnicode(cs.ServerName)))
					if cs.Version == tls.VersionTLS12 {
						return tlsBadCertificate
					}
					return tlsCertificateRequired
				}
				cert := cs.PeerCertificates[0]
				sum := certSummary(cert)
				if m, ok := be.pkiMap[hex.EncodeToString(cert.AuthorityKeyId)]; ok {
					if m.IsRevoked(cert.SerialNumber) {
						p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s (revoked)", sum, idnaToUnicode(cs.ServerName)))
						return tlsCertificateRevoked
					}
				} else if len(cert.OCSPServer) > 0 {
					if err := p.ocspCache.VerifyChains(cs.VerifiedChains, cs.OCSPResponse); err != nil {
						p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s (OCSP:%v)", sum, idnaToUnicode(cs.ServerName), err))
						return tlsCertificateRevoked
					}
				}
				if err := be.authorize(cert); err != nil {
					p.recordEvent(fmt.Sprintf("deny X509 [%s] to %s", sum, idnaToUnicode(cs.ServerName)))
					return tlsAccessDenied
				}
				if sum != "" {
					p.recordEvent(fmt.Sprintf("allow X509 [%s] to %s", sum, idnaToUnicode(cs.ServerName)))
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
			serverName := connServerName(ctx.Value(connCtxKey).(anyConn))
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
			)
			addPProfHandlers(&be.localHandlers)

			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.localHandler(), be.httpConnChan)
			if *cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Server = http3Server(be.localHandler())
			}

		case ModeLocal:
			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.localHandler(), be.httpConnChan)
			if *cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Server = http3Server(be.localHandler())
			}

		case ModeHTTPS, ModeHTTP:
			be.httpConnChan = make(chan net.Conn)
			be.httpServer = startInternalHTTPServer(be.reverseProxy(), be.httpConnChan)
			if *cfg.EnableQUIC && be.ALPNProtos != nil && slices.Contains(*be.ALPNProtos, "h3") {
				be.http3Server = http3Server(be.reverseProxy())
			}
		}
	}

	addLocalHandler := func(h localHandler, urls ...string) {
		for _, v := range urls {
			host, _, path, err := hostAndPath(v)
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
				if be := connBackend(req.Context().Value(connCtxKey).(anyConn)); be != nil {
					be.logF(logRequest, "REQ %s ➔ %s %s (SSO callback) (%q)", formatReqDesc(req), req.Method, req.URL.Path, userAgent(req))
				}
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
		be.outConns = p.outConns
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
	for _, conn := range p.inConns.slice() {
		if !connServerNameIsSet(conn) {
			continue
		}
		serverName := connServerName(conn)
		proto := connProto(conn)
		be, err := p.backend(serverName, proto)
		if err != nil {
			p.recordEvent(err.Error())
			be.logF(logConnection, "BAD [-] ReAuth %s ➔ %q: %v", conn.RemoteAddr(), serverName, err)
			conn.Close()
			continue
		}
		if oldBE := connBackend(conn); be.Mode != oldBE.Mode {
			be.logF(logConnection, "INF [-] ReAuth %s ➔  %q backend mode changed %s->%s", conn.RemoteAddr(), idnaToUnicode(serverName), oldBE.Mode, be.Mode)
			conn.Close()
			continue
		}
		if err := be.checkIP(conn.RemoteAddr()); err != nil {
			p.recordEvent(serverName + " CheckIP " + err.Error())
			be.logF(logConnection, "BAD [-] ReAuth %s ➔ %q CheckIP: %v", conn.RemoteAddr(), idnaToUnicode(serverName), err)
			conn.Close()
			continue
		}
		if be.ClientAuth == nil {
			continue
		}
		clientCert := connClientCert(conn)
		if err := be.authorize(clientCert); err != nil {
			p.recordEvent(err.Error())
			be.logF(logConnection, "BAD [-] ReAuth %s ➔ %q Authorize(%q): %v", conn.RemoteAddr(), idnaToUnicode(serverName), certSummary(clientCert), err)
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
	if *p.cfg.EnableQUIC {
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

	go p.revokeUnusedCertificates(p.ctx)
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
	if p.mk != nil {
		p.mk.Wipe()
		p.mk = nil
	}
	backends := p.cfg.Backends
	p.cfg.Backends = nil
	conns := p.inConns.slice()
	p.mu.Unlock()

	for _, be := range backends {
		be.close(nil)
	}
	for _, conn := range conns {
		conn.Close()
	}
	if p.tpm != nil {
		p.tpm.Close()
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
			for _, c := range p.inConns.slice() {
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
		cert, err := getCert(hello)
		if err != nil {
			return nil, err
		}
		if len(cert.Certificate) < 2 {
			return cert, nil
		}
		if cert.Leaf == nil {
			c, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, err
			}
			cert.Leaf = c
		}
		issuer, err := x509.ParseCertificate(cert.Certificate[1])
		if err != nil {
			return nil, err
		}
		if ocspResp, err := p.ocspCache.Response(cert.Leaf, issuer, time.Hour); err == nil && ocspResp.Status == ocsp.Good {
			cert.OCSPStaple = ocspResp.Raw
		} else {
			p.recordEvent("ocsp staple error for " + idnaToUnicode(hello.ServerName))
		}
		return cert, nil
	}
	tc.NextProtos = *defaultALPNProtos
	tc.MinVersion = tls.VersionTLS12
	return tc
}

func (p *Proxy) acceptProxyHeader(addr net.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, n := range p.cfg.acceptProxyHeaderFrom {
		if n.Contains(tcpAddr.IP) {
			return true
		}
	}
	return false
}

func (p *Proxy) logConnF(format string, args ...any) {
	if p.cfg == nil || p.cfg.LogFilter.Connections == nil || !*p.cfg.LogFilter.Connections {
		return
	}
	log.Printf(format, args...)
}

func (p *Proxy) logErrorF(format string, args ...any) {
	if p.cfg == nil || p.cfg.LogFilter.Errors == nil || !*p.cfg.LogFilter.Errors {
		return
	}
	log.Printf(format, args...)
}

func (p *Proxy) handleConnection(conn *netw.Conn) {
	p.recordEvent("tcp connection")
	defer func() {
		if r := recover(); r != nil {
			p.recordEvent("panic")
			p.logErrorF("ERR [%s] %s: PANIC: %v", certSummary(connClientCert(conn)), conn.RemoteAddr(), r)
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
	if p.acceptProxyHeader(conn.RemoteAddr()) {
		cc := proxyproto.NewConn(conn.Conn)
		conn.Conn = cc
	}
	numOpen := p.inConns.add(conn)
	conn.OnClose(func() {
		p.inConns.remove(conn)
		if be := connBackend(conn); be != nil {
			be.incInFlight(-1)
			if conn.Annotation(reportEndKey, false).(bool) {
				startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
				be.logF(logConnection, "END %s; Dur:%s Recv:%d Sent:%d",
					formatConnDesc(conn), time.Since(startTime).Truncate(time.Millisecond),
					conn.BytesReceived(), conn.BytesSent())
			}
		}
		p.connClosed.Broadcast()
	})
	if numOpen >= p.cfg.MaxOpen {
		p.recordEvent("too many open connections")
		p.logErrorF("ERR [-] %s: too many open connections: %d >= %d", conn.RemoteAddr(), numOpen, p.cfg.MaxOpen)
		sendCloseNotify(conn)
		return
	}
	setKeepAlive(conn)

	hello, err := peekClientHello(conn)
	if err != nil {
		p.recordEvent("invalid ClientHello")
		p.logErrorF("BAD [-] %s ➔ %q: invalid ClientHello: %v", conn.RemoteAddr(), hello.ServerName, err)
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
		p.logErrorF("BAD [-] %s ➔ %q: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return
	}
	conn.SetAnnotation(backendKey, be)
	be.incInFlight(1)
	p.setCounters(conn, serverName)
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
		be.logF(logError, "ERR [-] %s: unhandled connection %q", conn.RemoteAddr(), be.Mode)
	}
}

// checkIP is just a wrapper around be.checkIP. It must be called before the TLS
// handshake completes.
func (p *Proxy) checkIP(conn *netw.Conn) error {
	be := connBackend(conn)
	if err := be.checkIP(conn.RemoteAddr()); err != nil {
		serverName := idnaToUnicode(connServerName(conn))
		p.recordEvent(serverName + " CheckIP " + err.Error())
		be.logF(logConnection, "BAD [-] %s ➔ %q CheckIP: %v", conn.RemoteAddr(), serverName, err)
		sendUnrecognizedName(conn)
		return err
	}
	return nil
}

func (p *Proxy) handleACMEConnection(conn *tls.Conn) {
	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Minute)
	defer cancel()
	serverName := idnaToUnicode(connServerName(conn))
	p.logConnF("INF ACME %s ➔  %s", conn.RemoteAddr(), serverName)
	if err := conn.HandshakeContext(ctx); err != nil {
		p.recordEvent("tls handshake failed")
		p.logErrorF("BAD [-] %s ➔ %q Handshake: %v", conn.RemoteAddr(), serverName, unwrapErr(err))
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
			p.recordEvent(fmt.Sprintf("deny no cert to %s", idnaToUnicode(serverName)))
		case errors.Is(err, tlsAccessDenied):
			p.recordEvent("access denied")
		case errors.Is(err, tlsCertificateRevoked):
			p.recordEvent("cert is revoked")
		default:
			p.recordEvent("tls handshake failed")
		}
		be.logF(logError, "BAD [-] %s ➔ %q Handshake: %v", conn.RemoteAddr(), idnaToUnicode(serverName), unwrapErr(err))
		return false
	}
	annotatedConn(conn).SetAnnotation(handshakeDoneKey, time.Now())
	cs := conn.ConnectionState()
	if (cs.ServerName == "" && serverName != p.defaultServerName()) || (cs.ServerName != "" && cs.ServerName != serverName) {
		p.recordEvent("mismatched server name")
		be.logF(logError, "BAD [-] %s ➔ %q Mismatched server name", conn.RemoteAddr(), serverName)
		return false
	}
	proto := cs.NegotiatedProtocol
	var clientCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		clientCert = cs.PeerCertificates[0]
	}
	annotatedConn(conn).SetAnnotation(protoKey, proto)
	annotatedConn(conn).SetAnnotation(clientCertKey, clientCert)

	// The check below is also done in VerifyConnection.
	if be.ClientAuth != nil && be.ClientAuth.ACL != nil {
		if err := be.authorize(clientCert); err != nil {
			p.recordEvent(err.Error())
			be.logF(logError, "BAD [-] %s ➔ %q Authorize(%q): %v", conn.RemoteAddr(), idnaToUnicode(serverName), certSummary(clientCert), err)
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
		be.logF(logError, "ERR [-] %s ➔  %q Wait: %v", conn.RemoteAddr(), idnaToUnicode(serverName), err)
		conn.Close()
		return
	}
	if be.Mode != ModeConsole && be.Mode != ModeLocal && be.Mode != ModeHTTP && be.Mode != ModeHTTPS {
		p.recordEvent("wrong mode")
		be.logF(logError, "ERR [-] %s ➔  %q Mode is not [CONSOLE, LOCAL, HTTP, HTTPS]", conn.RemoteAddr(), idnaToUnicode(serverName))
		conn.Close()
		return
	}
	if be.httpConnChan == nil {
		p.recordEvent("conn chan nil")
		be.logF(logError, "ERR [-] %s ➔  %q conn channel is nil", conn.RemoteAddr(), idnaToUnicode(serverName))
		conn.Close()
		return
	}
	annotatedConn(conn).SetAnnotation(reportEndKey, true)
	be.logF(logConnection, "CON %s", formatConnDesc(conn.NetConn().(*netw.Conn)))
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
		be.logF(logError, "ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), idnaToUnicode(serverName), err)
		return
	}

	var protos []string
	if proto := connProto(extConn); proto != "" {
		protos = []string{proto}
	}

	intConn, err := be.dial(context.WithValue(p.ctx, connCtxKey, extConn), protos...)
	if err != nil {
		p.recordEvent("dial error")
		be.logF(logError, "ERR [-] %s ➔  %q Dial: %v", extConn.RemoteAddr(), idnaToUnicode(serverName), err)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)
	annotatedConn(extConn).SetAnnotation(dialDoneKey, time.Now())

	desc := formatConnDesc(annotatedConn(extConn))
	be.logF(logConnection, "CON %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		be.logF(logError, "DBG %s %v", desc, err)
	}

	startTime := annotatedConn(extConn).Annotation(startTimeKey, time.Time{}).(time.Time)
	hsTime := annotatedConn(extConn).Annotation(handshakeDoneKey, time.Time{}).(time.Time)
	dialTime := annotatedConn(extConn).Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	be.logF(logConnection, "END %s; HS:%s Dial:%s Dur:%s Recv:%d Sent:%d", desc,
		hsTime.Sub(startTime).Truncate(time.Millisecond),
		dialTime.Sub(hsTime).Truncate(time.Millisecond), totalTime,
		annotatedConn(extConn).BytesReceived(), annotatedConn(extConn).BytesSent())
}

func (p *Proxy) handleTLSPassthroughConnection(extConn net.Conn) {
	serverName := connServerName(extConn)
	be := connBackend(extConn)
	if err := be.connLimit.Wait(p.ctx); err != nil {
		p.recordEvent(err.Error())
		be.logF(logError, "ERR [-] %s ➔  %q Wait: %v", extConn.RemoteAddr(), idnaToUnicode(serverName), err)
		sendInternalError(extConn)
		return
	}

	intConn, err := be.dial(context.WithValue(p.ctx, connCtxKey, extConn))
	if err != nil {
		p.recordEvent("dial error")
		be.logF(logError, "ERR [-] %s ➔  %q Dial: %v", extConn.RemoteAddr(), idnaToUnicode(serverName), err)
		sendInternalError(extConn)
		return
	}
	defer intConn.Close()
	setKeepAlive(intConn)

	annotatedConn(extConn).SetAnnotation(dialDoneKey, time.Now())

	desc := formatConnDesc(annotatedConn(extConn))
	be.logF(logConnection, "CON %s", desc)

	if err := be.bridgeConns(extConn, intConn); err != nil {
		be.logF(logError, "DBG  %s %v", desc, err)
	}

	startTime := annotatedConn(extConn).Annotation(startTimeKey, time.Time{}).(time.Time)
	dialTime := annotatedConn(extConn).Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	be.logF(logConnection, "END %s; Dial:%s Dur:%s Recv:%d Sent:%d", desc,
		dialTime.Sub(startTime).Truncate(time.Millisecond), totalTime,
		annotatedConn(extConn).BytesReceived(), annotatedConn(extConn).BytesSent())
}

func (p *Proxy) defaultServerName() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.defServerName
}

func (p *Proxy) backend(serverName string, protos ...string) (*Backend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
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
	be.state.mu.Lock()
	defer be.state.mu.Unlock()
	if be.state.shutdown {
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
	conn, ok := req.Context().Value(connCtxKey).(anyConn)
	if !ok {
		log.Printf("ERR Request without connCtxKey: %v", req.Context())
		return ""
	}
	return formatConnDesc(conn, ids...)
}

func formatConnDesc(c anyConn, ids ...string) string {
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
	if isProxyProtoConn(c) {
		buf.WriteString(" ➔ ")
		buf.WriteString(c.LocalAddr().Network() + ":" + c.LocalAddr().String())
	}
	if serverName != "" {
		buf.WriteString(" ➔ ")
		buf.WriteString(idnaToUnicode(serverName))
		buf.WriteString("|" + mode)
		if proto != "" {
			buf.WriteString(":" + proto)
		}
		if httpUpgrade := connHTTPUpgrade(c); httpUpgrade != "" {
			buf.WriteString("+" + httpUpgrade)
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
	return host
}

// hostAndPath returns asciiHost, unicodeHost, port, err
func hostAndPath(urlString string) (string, string, string, error) {
	url, err := url.Parse(urlString)
	if err != nil {
		return "", "", "", err
	}
	host := url.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ascHost := idnaToASCII(host)
	uniHost := idnaToUnicode(ascHost)

	return ascHost, uniHost, url.Path, nil
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

func guessIDP(url string) string {
	if strings.HasPrefix(url, "https://accounts.google.com/") {
		return "google"
	}
	if strings.HasPrefix(url, "https://facebook.com/") {
		return "facebook"
	}
	if strings.HasPrefix(url, "https://github.com/") {
		return "github"
	}
	return ""
}

func unwrapErr(err error) error {
	if e, ok := err.(*net.OpError); ok {
		return unwrapErr(e.Err)
	}
	return err
}

type logger struct {
	f func(string, ...any)
}

func (logger) Debug(args ...any) {}

func (logger) Debugf(f string, args ...any) {}

func (l logger) Info(args ...any) {
	if l.f != nil {
		l.f("%s", append([]any{"INF "}, args...))
		return
	}
	log.Print(append([]any{"INF "}, args...)...)
}

func (l logger) Infof(f string, args ...any) {
	if l.f != nil {
		l.f("INF "+f, args...)
		return
	}
	log.Printf("INF "+f, args...)
}

func (l logger) Error(args ...any) {
	if l.f != nil {
		l.f("%s", append([]any{"ERR "}, args...))
		return
	}
	log.Print(append([]any{"ERR "}, args...)...)
}

func (l logger) Errorf(f string, args ...any) {
	if l.f != nil {
		l.f("ERR "+f, args...)
		return
	}
	log.Printf("ERR "+f, args...)
}

func (l logger) Fatal(args ...any) {
	if l.f != nil {
		l.f("%s", append([]any{"FATAL "}, args...))
		return
	}
	log.Fatal(append([]any{"FATAL "}, args...)...)
}

func (l logger) Fatalf(f string, args ...any) {
	if l.f != nil {
		l.f("FATAL "+f, args...)
		return
	}
	log.Fatalf("FATAL "+f, args...)
}
