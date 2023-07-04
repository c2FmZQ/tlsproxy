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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	yaml "gopkg.in/yaml.v3"
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
	// ALPNProtos specifies the list of ALPN procotols supported by this
	// backend. The ACME acme-tls/1 protocol doesn't need to be specified.
	// The default values are: h2, http/1.1
	// Set the value to an empty slice to disable ALPN.
	// The negotiated protocol is forwarded to the backends that use TLS.
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	ALPNProtos *[]string `yaml:"alpnProtos,omitempty"`
	// Addresses is a list of server addresses where requests are forwarded.
	// When more than one address are specified, requests are distributed
	// using a simple round robin.
	Addresses []string `yaml:"addresses"`
	// UseTLS indicates whether TLS should be used to establish the
	// connections to the backend addresses.
	UseTLS bool `yaml:"useTLS"`
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

	tlsConfig      *tls.Config
	forwardRootCAs *x509.CertPool
	limiter        *rate.Limiter

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
		if len(be.ServerNames) == 0 {
			return fmt.Errorf("backend[%d].ServerNames: backend must have at least one server name", i)
		}
		if len(be.Addresses) == 0 {
			return fmt.Errorf("backend[%d].Addresses: backend must have at least one address", i)
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
