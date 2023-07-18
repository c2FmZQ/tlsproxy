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
	ModeTLS            = "TLS"
	ModeTLSPassthrough = "TLSPASSTHROUGH"
	ModeConsole        = "CONSOLE"
)

var (
	validModes = []string{
		ModePlaintext,
		ModeTLS,
		ModeTLSPassthrough,
		ModeConsole,
	}
)

// Config is the TLS proxy configuration.
type Config struct {
	// HTTPAddr must be reachable from the internet via port 80 for the
	// letsencrypt ACME http-01 challenge to work. If the httpAddr is empty,
	// the proxy will only use tls-alpn-01 and tlsAddr must be reachable on
	// port 443.
	// See https://letsencrypt.org/docs/challenge-types/
	HTTPAddr string `yaml:"httpAddr"`
	// TLSAddr is the address where the proxy will receive TLS connections
	// and forward them to the backends.
	TLSAddr string `yaml:"tlsAddr"`
	// CacheDir is the directory where the proxy stores TLS certificates.
	CacheDir string `yaml:"cacheDir"`
	// DefaultServerName is the server name to use when the TLS client
	// doesn't use the Server Name Indication (SNI) extension.
	DefaultServerName string `yaml:"defaultServerName"`
	// Backends is the list of service backends.
	Backends []*Backend `yaml:"backends"`
	// Email is optionally included in the requests to letsencrypt.
	Email string `yaml:"email"`
	// MaxOpen is the maximum number of open incoming connections.
	MaxOpen int `yaml:"maxOpen"`
}

// Backend encapsulates the data of one backend.
type Backend struct {
	// ServerNames is the list of all the server names for this service,
	// e.g. example.com, www.example.com.
	ServerNames []string `yaml:"serverNames"`
	// ClientAuth indicates whether TLS client authentication is required
	// for this service.
	ClientAuth bool `yaml:"clientAuth"`
	// ClientACL optionally specifies which client identities are allowed
	// to use this service. A nil value disabled the authorization check and
	// allows any valid client certificate. Otherwise, the value is a slice
	// of Subject strings from the client X509 certificate.
	ClientACL *[]string `yaml:"clientACL"`
	// ClientCAs is either a file name or a set of PEM-encoded CA
	// certificates that are used to authenticate clients.
	ClientCAs string `yaml:"clientCAs"`
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
	// - CONSOLE: Indicates that this backend is handled by the proxy itself
	//     to report its status and metrics. It is strongly recommended
	//     to use it with ClientAuth and ClientACL. Otherwise, information
	//     from the proxy's configuration can be leaked to anyone who knows
	//     the backend's server name.
	//        CLIENT --TLS--> PROXY CONSOLE
	Mode string `yaml:"mode"`
	// Addresses is a list of server addresses where requests are forwarded.
	// When more than one address are specified, requests are distributed
	// using a simple round robin.
	Addresses []string `yaml:"addresses"`
	// InsecureSkipVerify disabled the verification of the backend server's
	// TLS certificate. See https://pkg.go.dev/crypto/tls#Config
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// ForwardRateLimit specifies how fast requests can be forwarded to the
	// backend servers. The default value is 5 requests per second.
	ForwardRateLimit int `yaml:"forwardRateLimit"`
	// ForwardServerName is the ServerName to send in the TLS handshake with
	// the backend server. It is also used to verify the server's identify.
	// This is particularly useful when the addresses use IP addresses
	// instead of hostnames.
	ForwardServerName string `yaml:"forwardServerName"`
	// ForwardRootCAs is either a file name or a set of PEM-encoded CA
	// certificates that are used to authenticate backend servers.
	ForwardRootCAs string `yaml:"forwardRootCAs"`
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

	tlsConfig      *tls.Config
	forwardRootCAs *x509.CertPool
	limiter        *rate.Limiter

	allowIPs *[]*net.IPNet
	denyIPs  *[]*net.IPNet

	mu   sync.Mutex
	next int
}

// Check checks that the Config is valid, sets some default values, and
// initializes internal data structures.
func (cfg *Config) Check() error {
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

	serverNames := make(map[string]bool)
	for i, be := range cfg.Backends {
		be.Mode = strings.ToUpper(be.Mode)
		if be.Mode == "" {
			be.Mode = ModePlaintext
		}
		if !slices.Contains(validModes, be.Mode) {
			return fmt.Errorf("backend[%d].Mode: value %q must be one of %v", i, be.Mode, validModes)
		}
		if be.Mode == ModeTLSPassthrough && be.ClientAuth {
			return fmt.Errorf("backend[%d].ClientAuth: client auth is not compatible with TLS Passthrough", i)
		}
		if len(be.ServerNames) == 0 {
			return fmt.Errorf("backend[%d].ServerNames: backend must have at least one server name", i)
		}
		if len(be.Addresses) == 0 && be.Mode != ModeConsole {
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
		if be.ClientAuth && be.ClientCAs != "" {
			_, err := loadCerts(be.ClientCAs)
			if err != nil {
				return fmt.Errorf("backend[%d].ClientCAs: %w", i, err)
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
