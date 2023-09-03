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

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
	yaml "gopkg.in/yaml.v3"
)

const (
	ModePlaintext      = "PLAINTEXT"
	ModeTCP            = "TCP"
	ModeTLS            = "TLS"
	ModeTLSPassthrough = "TLSPASSTHROUGH"
	ModeHTTP           = "HTTP"
	ModeHTTPS          = "HTTPS"
	ModeConsole        = "CONSOLE"
)

var (
	validModes = []string{
		ModeTCP,
		ModeTLS,
		ModeTLSPassthrough,
		ModeHTTP,
		ModeHTTPS,
		ModeConsole,
	}
)

// Config is the TLS proxy configuration.
type Config struct {
	// Definitions is a section where yaml anchors can be defined. It is
	// otherwise ignored by the proxy.
	Definitions any `yaml:"definitions,omitempty"`

	// HTTPAddr must be reachable from the internet via port 80 for the
	// letsencrypt ACME http-01 challenge to work. If the httpAddr is empty,
	// the proxy will only use tls-alpn-01 and tlsAddr must be reachable on
	// port 443.
	// See https://letsencrypt.org/docs/challenge-types/
	HTTPAddr string `yaml:"httpAddr,omitempty"`
	// TLSAddr is the address where the proxy will receive TLS connections
	// and forward them to the backends.
	TLSAddr string `yaml:"tlsAddr"`
	// CacheDir is the directory where the proxy stores TLS certificates.
	CacheDir string `yaml:"cacheDir,omitempty"`
	// DefaultServerName is the server name to use when the TLS client
	// doesn't use the Server Name Indication (SNI) extension.
	DefaultServerName string `yaml:"defaultServerName,omitempty"`
	// Backends is the list of service backends.
	Backends []*Backend `yaml:"backends"`
	// OIDCProviders is the list of OIDC providers.
	OIDCProviders []*ConfigOIDC `yaml:"oidc,omitempty"`
	// SAMLProviders is the list of SAML providers.
	SAMLProviders []*ConfigSAML `yaml:"saml,omitempty"`
	// Email is optionally included in the requests to letsencrypt.
	Email string `yaml:"email,omitempty"`
	// MaxOpen is the maximum number of open incoming connections.
	MaxOpen int `yaml:"maxOpen,omitempty"`
	// AcceptTOS indicates acceptance of the Let's Encrypt Terms of Service.
	AcceptTOS bool `yaml:"acceptTOS"`
}

// Backend encapsulates the data of one backend.
type Backend struct {
	// ServerNames is the list of all the server names for this service,
	// e.g. example.com, www.example.com.
	ServerNames []string `yaml:"serverNames"`
	// ClientAuth specifies that the TLS client's identity must be verified.
	ClientAuth *ClientAuth `yaml:"clientAuth,omitempty"`
	// AllowIPs specifies a list of IP network addresses to allow, in CIDR
	// format, e.g. 192.168.0.0/24.
	//
	// The rules are applied in this order:
	// * If DenyIPs is specified, the remote addr must not match any of the
	//   IP addresses in the list.
	// * If AllowIPs is specified, the remote addr must match at least one
	//   of the IP addresses on the list.
	//
	// If an IP address is blocked, the client receives a TLS "unrecognized
	// name" alert, as if it connected to an unknown server name.
	AllowIPs *[]string `yaml:"allowIPs,omitempty"`
	// DenyIPs specifies a list of IP network addresses to deny, in CIDR
	// format, e.g. 192.168.0.0/24. See AllowIPs.
	DenyIPs *[]string `yaml:"denyIPs,omitempty"`
	// SSO indicates that the backend requires user authentication, and
	// specifies which identity provider to use and who's allowed to
	// connect.
	SSO *BackendSSO `yaml:"sso,omitempty"`
	// ExportJWKS is the path where to export the proxy's JSON Web Key Set.
	// This should only be set when SSO is enabled and JSON Web Tokens are
	// generated for the users to authenticate with the backends.
	ExportJWKS string `yaml:"exportJwks,omitempty"`
	// ALPNProtos specifies the list of ALPN procotols supported by this
	// backend. The ACME acme-tls/1 protocol doesn't need to be specified.
	// The default values are: h2, http/1.1
	// Set the value to an empty slice to disable ALPN.
	// The negotiated protocol is forwarded to the backends that use TLS.
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	ALPNProtos *[]string `yaml:"alpnProtos,omitempty"`
	// Mode controls how the proxy communicates with the backend.
	// - PLAINTEXT: Use a plaintext, non-encrypted, TCP connection. This is
	//     the default mode.
	//        CLIENT --TLS--> PROXY ----> BACKEND SERVER
	// - TLS: Open a new TLS connection. Set ForwardServerName, ForwardRootCAs,
	//     and/or InsecureSkipVerify to verify the identity of the server.
	//        CLIENT --TLS--> PROXY --TLS--> BACKEND SERVER
	// - TLSPASSTHROUGH: Forward the whole TLS connection to the backend.
	//     In this mode, the proxy terminates the TCP connection, but not
	//     the TLS connection. The proxy uses the information from the TLS
	//     ClientHello message to route the TLS data to the right backend.
	//     It cannot see the plaintext data, and it cannot enforce client
	//     authentication & authorization.
	//                +-TCP-PROXY-TCP-+
	//        CLIENT -+------TLS------+-> BACKEND SERVER
	// - HTTP: Parses the incoming connection as HTTPS and forwards the
	//     requests to the backends as HTTP requests. Only HTTP/1 is
	//     supported.
	//        CLIENT --HTTPS--> PROXY --HTTP--> BACKEND SERVER
	// - HTTPS: Parses the incoming connection as HTTPS and forwards the
	//     requests to the backends as HTTPS requests. Only HTTP/1 is
	//     supported.
	//        CLIENT --HTTPS--> PROXY --HTTPS--> BACKEND SERVER
	// - CONSOLE: Indicates that this backend is handled by the proxy itself
	//     to report its status and metrics. It is strongly recommended
	//     to use it with ClientAuth and ACL. Otherwise, information from
	//     the proxy's configuration can be leaked to anyone who knows the
	//     backend's server name.
	//        CLIENT --TLS--> PROXY CONSOLE
	Mode string `yaml:"mode"`
	// AddClientCertHeader indicates that the HTTP Client-Cert header should
	// be added to the request when Mode is HTTP or HTTPS.
	AddClientCertHeader bool `yaml:"addClientCertHeader,omitempty"`
	// Addresses is a list of server addresses where requests are forwarded.
	// When more than one address are specified, requests are distributed
	// using a simple round robin.
	Addresses []string `yaml:"addresses,omitempty"`
	// InsecureSkipVerify disabled the verification of the backend server's
	// TLS certificate. See https://pkg.go.dev/crypto/tls#Config
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty"`
	// ForwardRateLimit specifies how fast requests can be forwarded to the
	// backend servers. The default value is 5 requests per second.
	ForwardRateLimit int `yaml:"forwardRateLimit"`
	// ForwardServerName is the ServerName to send in the TLS handshake with
	// the backend server. It is also used to verify the server's identify.
	// This is particularly useful when the addresses use IP addresses
	// instead of hostnames.
	ForwardServerName string `yaml:"forwardServerName,omitempty"`
	// ForwardRootCAs is either a file name or a set of PEM-encoded CA
	// certificates that are used to authenticate backend servers.
	ForwardRootCAs string `yaml:"forwardRootCAs,omitempty"`
	// ForwardTimeout is the connection timeout to backend servers. If
	// Addresses contains multiple addresses, this timeout indicates how
	// long to wait before trying the next address in the list. The default
	// value is 30 seconds.
	ForwardTimeout time.Duration `yaml:"forwardTimeout"`

	// TCP connections consist of two streams of data:
	//
	//    CLIENT --> SERVER
	//    CLIENT <-- SERVER
	//
	// The CLIENT and the SERVER can send data to each other at the same.
	// When one stream is closed, the other one can remain open and continue
	// to transmit data indefinitely. The TCP connection is closed when both
	// streams are closed. (Either end can close the whole connection at any
	// time too)
	//
	// This is a normal feature of TCP connections, but very few
	// applications / protocols use half-close connections.
	//
	// There are some broken clients and network devices doing Network
	// Address Translation (NAT) that never close their end of the
	// connection. This can result in TCP connections staying open doing
	// nothing, but still using resources for a very long time.
	//
	// The parameters below can be used to control the behavior of the proxy
	// when connections are half-closed. The default values should be
	// appropriate for well-behaved servers and occasionally broken clients.

	// ServerCloseEndsConnection indicates that the proxy will close the
	// whole TCP connection when the server closes its end of it. The
	// default value is true.
	ServerCloseEndsConnection *bool `yaml:"serverCloseEndsConnection,omitempty"`
	// ClientCloseEndsConnection indicates that the proxy will close the
	// whole TCP connection when the client closes its end of it. The
	// default value is false.
	ClientCloseEndsConnection *bool `yaml:"clientCloseEndsConnection,omitempty"`
	// HalfCloseTimeout is the amount of time to keep the TCP connection
	// open when one stream is closed. The default value is 1 minute.
	HalfCloseTimeout *time.Duration `yaml:"halfCloseTimeout,omitempty"`

	recordEvent func(string)

	tlsConfig      *tls.Config
	forwardRootCAs *x509.CertPool
	limiter        *rate.Limiter

	allowIPs *[]*net.IPNet
	denyIPs  *[]*net.IPNet

	httpServer    *http.Server
	httpConnChan  chan net.Conn
	localHandlers map[string]localHandler

	mu       sync.Mutex
	next     int
	inFlight int
	shutdown bool
}

type localHandler struct {
	handler   http.HandlerFunc
	ssoBypass bool
}

// ClientAuth specifies how to authenticate and authorize the TLS client's
// identity.
type ClientAuth struct {
	// ACL optionally specifies which client identities are allowed to use
	// this service. A nil value disabled the authorization check and allows
	// any valid client certificate. Otherwise, the value is a slice of
	// Subject strings from the client X509 certificate.
	ACL *[]string `yaml:"acl,omitempty"`
	// RootCAs is either a file name or a set of PEM-encoded CA
	// certificates that are used to authenticate clients.
	RootCAs string `yaml:"rootCAs,omitempty"`
}

// ConfigOIDC contains the parameters of an OIDC provider.
type ConfigOIDC struct {
	// Name is the name of the provider. It is used internally only.
	Name string `yaml:"name"`
	// DiscoveryURL is the discovery URL of the OIDC provider. If set, it
	// is used to discover the values of AuthEndpoint and TokenEndpoint.
	DiscoveryURL string `yaml:"discoveryUrl,omitempty"`
	// AuthEndpoint is the authorization endpoint. It must be set only if
	// DiscoveryURL is not set.
	AuthEndpoint string `yaml:"authorizationEndpoint,omitempty"`
	// TokenEndpoint is the token endpoint. It must be set only if
	// DiscoveryURL is not set.
	TokenEndpoint string `yaml:"tokenEndpoint,omitempty"`
	// RedirectURL is the OAUTH2 redirect URL. It must be managed by the
	// proxy.
	RedirectURL string `yaml:"redirectUrl"`
	// ClientID is the Client ID.
	ClientID string `yaml:"clientId"`
	// ClientSecret is the Client Secret.
	ClientSecret string `yaml:"clientSecret"`
	// Domain, if set, determine the domain where the user identities will
	// be valid.
	Domain string `yaml:"domain,omitempty"`
}

// ConfigSAML contains the parameters of a SAML identity provider.
type ConfigSAML struct {
	Name     string `yaml:"name"`
	SSOURL   string `yaml:"ssoUrl"`
	EntityID string `yaml:"entityId"`
	Certs    string `yaml:"certs"`
	ACSURL   string `yaml:"acsUrl"`
	// Domain, if set, determine the domain where the user identities will
	// be valid.
	Domain string `yaml:"domain,omitempty"`
}

// BackendSSO specifies the identity parameters to use for a backend.
type BackendSSO struct {
	// Provider is the the name of an identity provider defined in
	// Config.OIDCProviders.
	Provider string `yaml:"provider"`
	// ACL restricts which user identity can access this backend. It is a
	// list of email addresses and/or domains, e.g. "bob@example.com", or
	// "@example.com"
	// If ACL is nil, all identities are allowed. If ACL is an empty list,
	// nobody is allowed.
	ACL *[]string `yaml:"acl,omitempty"`
	// Paths lists the path prefixes for which this policy will be enforced.
	// If Paths is empty, the policy applies to all paths.
	Paths []string `yaml:"paths,omitempty"`

	p identityProvider
}

func (cfg *Config) clone() *Config {
	b, _ := yaml.Marshal(cfg)
	var out Config
	yaml.Unmarshal(b, &out)
	return &out
}

// Check checks that the Config is valid, sets some default values, and
// initializes internal data structures.
func (cfg *Config) Check() error {
	cfg.Definitions = nil
	if cfg.CacheDir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return errors.New("CacheDir must be set in config")
		}
		cfg.CacheDir = filepath.Join(d, "tlsproxy", "letsencrypt")
	}
	if cfg.TLSAddr == "" {
		cfg.TLSAddr = ":10443"
	}
	if cfg.MaxOpen == 0 {
		n, err := openFileLimit()
		if err != nil {
			return errors.New("MaxOpen: value must be set")
		}
		cfg.MaxOpen = n/2 - 100
	}

	identityProviders := make(map[string]bool)
	for i, oi := range cfg.OIDCProviders {
		if identityProviders[oi.Name] {
			return fmt.Errorf("oidc[%d].Name: duplicate provider name %q", i, oi.Name)
		}
		identityProviders[oi.Name] = true

		if (oi.AuthEndpoint == "" || oi.TokenEndpoint == "") && oi.DiscoveryURL == "" {
			return fmt.Errorf("oidc[%d] AuthEndpoint and TokenEndpoint must be set unless DiscoveryURL is set", i)
		}
		if oi.DiscoveryURL != "" {
			if _, err := url.Parse(oi.DiscoveryURL); err != nil {
				return fmt.Errorf("oidc[%d].DiscoveryURL: %v", i, err)
			}
		}
		if oi.AuthEndpoint != "" {
			if _, err := url.Parse(oi.AuthEndpoint); err != nil {
				return fmt.Errorf("oidc[%d].AuthEndpoint: %v", i, err)
			}
		}
		if oi.TokenEndpoint != "" {
			if _, err := url.Parse(oi.TokenEndpoint); err != nil {
				return fmt.Errorf("oidc[%d].TokenEndpoint: %v", i, err)
			}
		}
		if oi.RedirectURL == "" {
			return fmt.Errorf("oidc[%d].RedirectURL must be set", i)
		}
		if _, err := url.Parse(oi.RedirectURL); err != nil {
			return fmt.Errorf("oidc[%d].RedirectURL: %v", i, err)
		}
		if oi.ClientID == "" {
			return fmt.Errorf("oidc[%d].ClientID must be set", i)
		}
		if oi.ClientSecret == "" {
			return fmt.Errorf("oidc[%d].ClientSecret must be set", i)
		}
		if oi.Domain != "" {
			u, _ := url.Parse(oi.RedirectURL)
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !strings.HasSuffix(host, oi.Domain) {
				return fmt.Errorf("oidc[%d].Domain %q must be part of RedirectURL", i, oi.Domain)
			}
		}
	}
	for i, s := range cfg.SAMLProviders {
		if identityProviders[s.Name] {
			return fmt.Errorf("saml[%d].Name: duplicate provider name %q", i, s.Name)
		}
		identityProviders[s.Name] = true
		if s.SSOURL == "" {
			return fmt.Errorf("saml[%d].SSOURL must be set", i)
		}
		if s.EntityID == "" {
			return fmt.Errorf("saml[%d].EntityID must be set", i)
		}
		if s.Certs == "" {
			return fmt.Errorf("saml[%d].Certs must be set", i)
		}
		if s.ACSURL == "" {
			return fmt.Errorf("saml[%d].ACSURL must be set", i)
		}
		if s.Domain != "" {
			u, _ := url.Parse(s.ACSURL)
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !strings.HasSuffix(host, s.Domain) {
				return fmt.Errorf("saml[%d].Domain %q must be part of ACSURL", i, s.Domain)
			}
		}
	}

	serverNames := make(map[string]bool)
	for i, be := range cfg.Backends {
		be.Mode = strings.ToUpper(be.Mode)
		if be.Mode == "" || be.Mode == ModePlaintext {
			be.Mode = ModeTCP
		}
		if !slices.Contains(validModes, be.Mode) {
			return fmt.Errorf("backend[%d].Mode: value %q must be one of %v", i, be.Mode, validModes)
		}
		if be.Mode == ModeTLSPassthrough && be.ClientAuth != nil {
			return fmt.Errorf("backend[%d].ClientAuth: client auth is not compatible with TLS Passthrough", i)
		}
		if be.Mode == ModeHTTP || be.Mode == ModeHTTPS {
			be.ALPNProtos = &[]string{"http/1.1", "http/1.0"}
		}
		if len(be.ServerNames) == 0 {
			return fmt.Errorf("backend[%d].ServerNames: backend must have at least one server name", i)
		}
		if len(be.Addresses) == 0 && be.Mode != ModeConsole && be.Mode != ModeHTTP && be.Mode != ModeHTTPS {
			return fmt.Errorf("backend[%d].Addresses: backend must have at least one address", i)
		}
		if len(be.Addresses) > 0 && be.Mode == ModeConsole {
			return fmt.Errorf("backend[%d].Addresses: Addresses should be empty when Mode is CONSOLE", i)
		}
		for j, sn := range be.ServerNames {
			sn = strings.ToLower(sn)
			be.ServerNames[j] = sn
			if serverNames[sn] {
				return fmt.Errorf("backend[%d].ServerNames: duplicate server name %q", i, sn)
			}
			serverNames[sn] = true
		}
		if be.ClientAuth != nil && be.ClientAuth.RootCAs != "" {
			_, err := loadCerts(be.ClientAuth.RootCAs)
			if err != nil {
				return fmt.Errorf("backend[%d].ClientCAs: %w", i, err)
			}
		}
		if be.SSO != nil {
			if !identityProviders[be.SSO.Provider] {
				return fmt.Errorf("backend[%d].SSO.Provider: unknown provider %q", i, be.SSO.Provider)
			}
		}
		if be.ForwardRootCAs != "" {
			_, err := loadCerts(be.ForwardRootCAs)
			if err != nil {
				return fmt.Errorf("backend[%d].ForwardRootCAs: %w", i, err)
			}
		}
		if be.ForwardTimeout == 0 {
			be.ForwardTimeout = 30 * time.Second
		}
		if be.AllowIPs != nil {
			ips := make([]*net.IPNet, 0, len(*be.AllowIPs))
			for j, c := range *be.AllowIPs {
				_, n, err := net.ParseCIDR(c)
				if err != nil {
					return fmt.Errorf("backend[%d].AllowIPs[%d]: %w", i, j, err)
				}
				ips = append(ips, n)
			}
			be.allowIPs = &ips
		}
		if be.DenyIPs != nil {
			ips := make([]*net.IPNet, 0, len(*be.DenyIPs))
			for j, c := range *be.DenyIPs {
				_, n, err := net.ParseCIDR(c)
				if err != nil {
					return fmt.Errorf("backend[%d].DenyIPs[%d]: %w", i, j, err)
				}
				ips = append(ips, n)
			}
			be.denyIPs = &ips
		}
		be.ForwardServerName = strings.ToLower(be.ForwardServerName)
		if be.ForwardRateLimit == 0 {
			be.ForwardRateLimit = 5
		}
		be.limiter = rate.NewLimiter(rate.Limit(be.ForwardRateLimit), be.ForwardRateLimit)
	}
	return os.MkdirAll(cfg.CacheDir, 0o700)
}

// ReadConfig reads and validates a YAML config file.
func ReadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
