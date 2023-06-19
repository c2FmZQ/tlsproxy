// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
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

	"golang.org/x/sys/unix"
	yaml "gopkg.in/yaml.v3"
)

// Config is the TLS proxy configuration.
type Config struct {
	HTTPAddr string     `yaml:"httpAddr"`
	TLSAddr  string     `yaml:"tlsAddr"`
	CacheDir string     `yaml:"cacheDir"`
	Backends []*Backend `yaml:"backends"`
	Email    string     `yaml:"email"`
	MaxOpen  int        `yaml:"maxOpen"`
}

// Backend encapsulates the data of one backend.
type Backend struct {
	ServerNames []string `yaml:"serverNames"`
	ClientAuth  bool     `yaml:"clientAuth"`
	ClientCAs   string   `yaml:"clientCAs"`

	Addresses          []string      `yaml:"addresses"`
	UseTLS             bool          `yaml:"useTLS"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	ForwardServerName  string        `yaml:"forwardServerName"`
	ForwardRootCAs     string        `yaml:"forwardRootCAs"`
	ForwardTimeout     time.Duration `yaml:"forwardTimeout"`

	tlsConfig      *tls.Config
	forwardRootCAs *x509.CertPool

	mu   sync.Mutex
	next int
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
	if cfg.CacheDir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return nil, errors.New("CacheDir must be set in config")
		}
		cfg.CacheDir = filepath.Join(d, "tlsproxy", "letsencrypt")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":10080"
	}
	if cfg.TLSAddr == "" {
		cfg.TLSAddr = ":10443"
	}
	if cfg.MaxOpen == 0 {
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
			return nil, err
		}
		rl.Cur = rl.Max
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
			return nil, err
		}
		cfg.MaxOpen = int(rl.Cur/2 - 100)
	}

	serverNames := make(map[string]bool)
	for i, be := range cfg.Backends {
		if len(be.ServerNames) == 0 {
			return nil, fmt.Errorf("backend[%d].ServerNames: backend must have at least one server name", i)
		}
		if len(be.Addresses) == 0 {
			return nil, fmt.Errorf("backend[%d].Addresses: backend must have at least one address", i)
		}
		for j, sn := range be.ServerNames {
			sn = strings.ToLower(sn)
			be.ServerNames[j] = sn
			if serverNames[sn] {
				return nil, fmt.Errorf("backend[%d].ServerNames: duplicate server name %q", i, sn)
			}
			serverNames[sn] = true
		}
		if be.ClientAuth && be.ClientCAs != "" {
			_, err := loadCerts(be.ClientCAs)
			if err != nil {
				return nil, fmt.Errorf("backend[%d].ClientCAs: %w", i, err)
			}
		}
		if be.ForwardRootCAs != "" {
			_, err := loadCerts(be.ForwardRootCAs)
			if err != nil {
				return nil, fmt.Errorf("backend[%d].ForwardRootCAs: %w", i, err)
			}
		}
		if be.ForwardTimeout == 0 {
			be.ForwardTimeout = 5 * time.Second
		}
		be.ForwardServerName = strings.ToLower(be.ForwardServerName)
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, err
	}
	return &cfg, nil
}
